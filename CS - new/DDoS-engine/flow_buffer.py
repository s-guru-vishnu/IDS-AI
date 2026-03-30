"""
flow_buffer.py — Flow-Based Buffer Processing Engine
=====================================================
Groups packets into flows using 5-tuple key (src_ip, dst_ip, src_port,
dst_port, protocol), maintains rolling windows per flow, and triggers
analysis when conditions are met.

Design:
  - Sliding window per flow (configurable 1-5 seconds)
  - Auto-eviction of stale flows
  - Lightweight memory: only stores aggregated stats, not raw packets
  - Trigger conditions: flow end, threshold, suspicious pattern

Thread-safe for concurrent access from packet capture threads.
"""

import time
import math
import threading
import logging
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

logger = logging.getLogger("ids.flow_buffer")


# ─────────────────────────────────────────────
# Flow Key (5-tuple)
# ─────────────────────────────────────────────

def make_flow_key(src_ip: str, dst_ip: str, src_port: int = 0,
                  dst_port: int = 0, protocol: str = "TCP") -> str:
    """Create a canonical 5-tuple flow key (bidirectional)."""
    # Normalize direction: lower IP:port is always first
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a > b:
        a, b = b, a
    return f"{a[0]}:{a[1]}-{b[0]}:{b[1]}/{protocol}"


# ─────────────────────────────────────────────
# Buffer Stats (output for each flow)
# ─────────────────────────────────────────────

@dataclass
class BufferStats:
    """Aggregated statistics from a flow buffer window."""
    packet_count: int = 0
    total_bytes: int = 0
    duration_sec: float = 0.0
    packet_rate: float = 0.0       # packets per second
    byte_rate: float = 0.0         # bytes per second
    entropy: float = 0.0           # packet size entropy
    avg_iat: float = 0.0           # average inter-arrival time
    std_iat: float = 0.0           # std dev of inter-arrival time
    burst_count: int = 0           # number of burst events
    syn_ratio: float = 0.0        # SYN flag ratio
    ack_ratio: float = 0.0        # ACK flag ratio
    fin_ratio: float = 0.0        # FIN flag ratio
    rst_ratio: float = 0.0        # RST flag ratio
    unique_sizes: int = 0          # unique packet sizes (entropy proxy)

    def to_dict(self) -> dict:
        return {
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "duration_sec": round(self.duration_sec, 4),
            "packet_rate": round(self.packet_rate, 2),
            "byte_rate": round(self.byte_rate, 2),
            "entropy": round(self.entropy, 4),
            "avg_iat": round(self.avg_iat, 6),
            "std_iat": round(self.std_iat, 6),
            "burst_count": self.burst_count,
            "syn_ratio": round(self.syn_ratio, 4),
            "ack_ratio": round(self.ack_ratio, 4),
            "fin_ratio": round(self.fin_ratio, 4),
            "rst_ratio": round(self.rst_ratio, 4),
        }


# ─────────────────────────────────────────────
# Flow Record (internal state per flow)
# ─────────────────────────────────────────────

class FlowRecord:
    """
    Maintains rolling statistics for a single flow.

    Memory-efficient: stores only aggregate stats, not raw packets.
    Uses Welford's online algorithm for running variance on IAT.
    """
    __slots__ = (
        'flow_key', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
        'first_seen', 'last_seen', 'packet_count', 'total_bytes',
        '_timestamps', '_sizes', '_flags',
        '_iat_mean', '_iat_m2', '_iat_count',
        '_burst_count', '_last_burst_time',
        '_syn_count', '_ack_count', '_fin_count', '_rst_count',
        '_size_set', 'trust_score', 'trigger_reason',
    )

    # Burst threshold: if IAT < this, it's a burst
    _BURST_IAT_THRESHOLD = 0.001  # 1ms

    def __init__(self, flow_key: str, src_ip: str, dst_ip: str,
                 src_port: int = 0, dst_port: int = 0, protocol: str = "TCP"):
        self.flow_key = flow_key
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        self.first_seen = 0.0
        self.last_seen = 0.0
        self.packet_count = 0
        self.total_bytes = 0

        # Rolling window of recent timestamps (limited to last N)
        self._timestamps: List[float] = []
        self._sizes: List[int] = []
        self._flags: List[str] = []

        # Welford's online variance for IAT
        self._iat_mean = 0.0
        self._iat_m2 = 0.0
        self._iat_count = 0

        # Burst detection
        self._burst_count = 0
        self._last_burst_time = 0.0

        # Flag counters
        self._syn_count = 0
        self._ack_count = 0
        self._fin_count = 0
        self._rst_count = 0

        # Unique packet sizes (for entropy)
        self._size_set: set = set()

        # Per-flow trust score (for fast-path optimization)
        self.trust_score = 0.5  # neutral start
        self.trigger_reason = ""

    def ingest_packet(self, timestamp: float, size: int, flags: str = "",
                      window_sec: float = 5.0):
        """
        Ingest a single packet into this flow's buffer.

        Memory-efficient: only keeps last `window_sec` of timestamps.
        """
        now = timestamp

        if self.first_seen == 0.0:
            self.first_seen = now
        self.last_seen = now
        self.packet_count += 1
        self.total_bytes += size

        # Track size for entropy
        self._size_set.add(size)

        # IAT computation (Welford's online)
        if self._timestamps:
            iat = now - self._timestamps[-1]
            if iat >= 0:
                self._iat_count += 1
                delta = iat - self._iat_mean
                self._iat_mean += delta / self._iat_count
                delta2 = iat - self._iat_mean
                self._iat_m2 += delta * delta2

                # Burst detection
                if iat < self._BURST_IAT_THRESHOLD:
                    if now - self._last_burst_time > 0.1:
                        self._burst_count += 1
                        self._last_burst_time = now

        # Store timestamp and size (sliding window)
        self._timestamps.append(now)
        self._sizes.append(size)

        # Flag tracking
        if flags:
            flags_upper = str(flags).upper()
            if 'S' in flags_upper and 'A' not in flags_upper:
                self._syn_count += 1
            if 'A' in flags_upper:
                self._ack_count += 1
            if 'F' in flags_upper:
                self._fin_count += 1
            if 'R' in flags_upper:
                self._rst_count += 1

        # Evict stale data from sliding window
        cutoff = now - window_sec
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.pop(0)
            self._sizes.pop(0)

    def get_stats(self) -> BufferStats:
        """Compute buffer stats from current flow state."""
        stats = BufferStats()
        stats.packet_count = self.packet_count
        stats.total_bytes = self.total_bytes

        duration = self.last_seen - self.first_seen if self.first_seen > 0 else 0.0
        stats.duration_sec = duration

        if duration > 0:
            stats.packet_rate = self.packet_count / duration
            stats.byte_rate = self.total_bytes / duration
        elif self.packet_count > 0:
            stats.packet_rate = float(self.packet_count)
            stats.byte_rate = float(self.total_bytes)

        # IAT stats
        stats.avg_iat = self._iat_mean
        if self._iat_count > 1:
            variance = self._iat_m2 / (self._iat_count - 1)
            stats.std_iat = math.sqrt(max(0, variance))

        # Burst count
        stats.burst_count = self._burst_count

        # Flag ratios
        n = max(self.packet_count, 1)
        stats.syn_ratio = self._syn_count / n
        stats.ack_ratio = self._ack_count / n
        stats.fin_ratio = self._fin_count / n
        stats.rst_ratio = self._rst_count / n

        # Entropy (Shannon entropy of packet sizes in window)
        stats.unique_sizes = len(self._size_set)
        if self._sizes:
            stats.entropy = self._compute_entropy(self._sizes)

        return stats

    @staticmethod
    def _compute_entropy(sizes: List[int]) -> float:
        """Shannon entropy of packet size distribution."""
        if not sizes:
            return 0.0
        n = len(sizes)
        if n <= 1:
            return 0.0
        counts: Dict[int, int] = {}
        for s in sizes:
            counts[s] = counts.get(s, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / n
            if p > 0:
                entropy -= p * math.log2(p)
        # Normalize to 0-1 range
        max_entropy = math.log2(min(n, len(counts)))
        if max_entropy > 0:
            return entropy / max_entropy
        return 0.0

    def should_trigger_analysis(self, pps_threshold: float = 80.0,
                                 syn_threshold: float = 0.15,
                                 min_packets: int = 5) -> Tuple[bool, str]:
        """
        Check if this flow should trigger immediate analysis.

        Returns (should_trigger, reason).
        """
        if self.packet_count < min_packets:
            return False, ""

        n = max(self.packet_count, 1)
        syn_ratio = self._syn_count / n

        # High packet rate
        duration = self.last_seen - self.first_seen
        if duration > 0:
            pps = self.packet_count / duration
            if pps > pps_threshold:
                self.trigger_reason = f"high_pps:{pps:.1f}"
                return True, self.trigger_reason

        # SYN flood pattern
        if syn_ratio > syn_threshold and self.packet_count > 10:
            self.trigger_reason = f"syn_flood:{syn_ratio:.2f}"
            return True, self.trigger_reason

        # Burst pattern (multiple bursts in short time)
        if self._burst_count >= 3:
            self.trigger_reason = f"burst_pattern:{self._burst_count}"
            return True, self.trigger_reason

        # FIN/RST without established connection
        rst_ratio = self._rst_count / n
        if rst_ratio > 0.5 and self.packet_count > 5:
            self.trigger_reason = f"rst_flood:{rst_ratio:.2f}"
            return True, self.trigger_reason

        return False, ""

    def is_stale(self, now: float, max_idle_sec: float = 30.0) -> bool:
        """Check if this flow has been idle too long."""
        return (now - self.last_seen) > max_idle_sec if self.last_seen > 0 else False

    def has_ended(self) -> bool:
        """Check if flow has ended (FIN or RST seen)."""
        return self._fin_count > 0 or self._rst_count > 0


# ─────────────────────────────────────────────
# Flow Buffer Manager
# ─────────────────────────────────────────────

class FlowBufferManager:
    """
    Manages all active flow buffers.

    Thread-safe: designed for concurrent packet ingestion from
    the main sniff callback thread.

    Features:
      - 5-tuple flow identification
      - Sliding window per flow
      - Auto-eviction of stale flows
      - Trigger-based analysis (threshold, suspicious pattern, flow end)
      - Per-flow trust scoring
      - Memory-bounded (max_flows limit)
    """

    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        self._lock = threading.Lock()

        # Configuration
        self._window_sec = cfg.get("window_sec", 5.0)
        self._max_flows = cfg.get("max_flows", 10000)
        self._max_idle_sec = cfg.get("max_idle_sec", 30.0)
        self._pps_threshold = cfg.get("pps_threshold", 80.0)
        self._syn_threshold = cfg.get("syn_threshold", 0.15)
        self._min_trigger_packets = cfg.get("min_trigger_packets", 5)

        # Active flows
        self._flows: Dict[str, FlowRecord] = {}

        # Per-IP trust scores (learned over time)
        self._ip_trust: Dict[str, float] = {}
        self._ip_trust_decay = cfg.get("trust_decay", 0.01)

        # Stats
        self._total_packets = 0
        self._total_flows_created = 0
        self._total_flows_evicted = 0
        self._total_triggers = 0

        logger.info(
            "FlowBufferManager initialized | window=%.1fs | max_flows=%d | "
            "pps_trigger=%.0f | syn_trigger=%.2f",
            self._window_sec, self._max_flows,
            self._pps_threshold, self._syn_threshold,
        )

    def ingest_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int = 0,
        dst_port: int = 0,
        protocol: str = "TCP",
        size: int = 0,
        flags: str = "",
        timestamp: float = 0.0,
    ) -> Tuple[str, Optional[FlowRecord]]:
        """
        Ingest a single packet into the appropriate flow buffer.

        Returns:
            (flow_key, triggered_flow_or_None)

            If a FlowRecord is returned, it means this flow triggered
            immediate analysis (suspicious pattern detected).
        """
        if timestamp <= 0:
            timestamp = time.time()

        flow_key = make_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)

        with self._lock:
            self._total_packets += 1

            # Get or create flow
            flow = self._flows.get(flow_key)
            if flow is None:
                # Memory bound check
                if len(self._flows) >= self._max_flows:
                    self._evict_oldest_flow()

                flow = FlowRecord(
                    flow_key=flow_key,
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol=protocol,
                )
                # Apply learned trust
                flow.trust_score = self._ip_trust.get(src_ip, 0.5)
                self._flows[flow_key] = flow
                self._total_flows_created += 1

            # Ingest packet
            flow.ingest_packet(timestamp, size, flags, self._window_sec)

            # Check trigger conditions
            should_trigger, reason = flow.should_trigger_analysis(
                pps_threshold=self._pps_threshold,
                syn_threshold=self._syn_threshold,
                min_packets=self._min_trigger_packets,
            )

            if should_trigger:
                self._total_triggers += 1
                return flow_key, flow

        return flow_key, None

    def get_flow(self, flow_key: str) -> Optional[FlowRecord]:
        """Get a specific flow record."""
        with self._lock:
            return self._flows.get(flow_key)

    def get_all_flows(self) -> Dict[str, FlowRecord]:
        """Get a snapshot of all active flows."""
        with self._lock:
            return dict(self._flows)

    def get_flows_for_batch(self, min_packets: int = 1) -> List[FlowRecord]:
        """
        Get all flows with enough packets for batch analysis.
        Used by the 10-second batch processor.
        """
        with self._lock:
            return [
                flow for flow in self._flows.values()
                if flow.packet_count >= min_packets
            ]

    def get_flow_stats(self, flow_key: str) -> Optional[BufferStats]:
        """Get buffer stats for a specific flow."""
        with self._lock:
            flow = self._flows.get(flow_key)
            if flow:
                return flow.get_stats()
        return None

    def update_trust(self, src_ip: str, delta: float):
        """
        Update trust score for an IP.
        Positive delta = more trusted, negative = less trusted.
        """
        with self._lock:
            current = self._ip_trust.get(src_ip, 0.5)
            self._ip_trust[src_ip] = max(0.0, min(1.0, current + delta))

    def is_trusted(self, src_ip: str, threshold: float = 0.8) -> bool:
        """Check if an IP is trusted (for fast-path optimization)."""
        return self._ip_trust.get(src_ip, 0.5) >= threshold

    def cleanup(self, now: float = 0.0):
        """Remove stale flows."""
        if now <= 0:
            now = time.time()
        with self._lock:
            stale_keys = [
                key for key, flow in self._flows.items()
                if flow.is_stale(now, self._max_idle_sec)
            ]
            for key in stale_keys:
                del self._flows[key]
                self._total_flows_evicted += 1

            # Trim trust scores if too many
            if len(self._ip_trust) > 20000:
                # Keep top half by trust value
                sorted_ips = sorted(
                    self._ip_trust.items(),
                    key=lambda x: x[1], reverse=True
                )
                self._ip_trust = dict(sorted_ips[:10000])

    def get_stats(self) -> dict:
        """Return buffer manager statistics."""
        with self._lock:
            return {
                "active_flows": len(self._flows),
                "total_packets_ingested": self._total_packets,
                "total_flows_created": self._total_flows_created,
                "total_flows_evicted": self._total_flows_evicted,
                "total_triggers": self._total_triggers,
                "tracked_ip_trusts": len(self._ip_trust),
                "window_sec": self._window_sec,
                "max_flows": self._max_flows,
            }

    def _evict_oldest_flow(self):
        """Evict the oldest idle flow to make room."""
        if not self._flows:
            return
        oldest_key = min(
            self._flows.keys(),
            key=lambda k: self._flows[k].last_seen,
        )
        del self._flows[oldest_key]
        self._total_flows_evicted += 1
