"""
correlation_engine.py — Multi-Flow Correlation Engine (Stage 6)
================================================================
Detects distributed, multi-stage, and time-based attack patterns
by correlating signals across multiple flows and time windows.

Key capabilities:
  - Cross-flow correlation (multiple IPs → same target)
  - Attack chain detection (scan → exploit → exfiltrate)
  - Time-based pattern analysis (pulse, jitter, slow-ramp)
  - Distributed micro-traffic aggregation
  - Multi-vector fusion (DDoS + MITM simultaneously)
"""

import time
import uuid
import logging
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set

logger = logging.getLogger("ids.correlation")


# ─────────────────────────────────────────────
# Attack Chain Definitions
# ─────────────────────────────────────────────

# Known multi-stage attack progressions
ATTACK_CHAINS = {
    "recon_to_exploit": {
        "stages": ["Scan", "DDoS", "WAF_Injection"],
        "description": "Reconnaissance → Volumetric Cover → Application Exploit",
        "severity_boost": 0.3,
    },
    "distraction_exfil": {
        "stages": ["DDoS", "MITM"],
        "description": "DDoS distraction → MITM data interception",
        "severity_boost": 0.4,
    },
    "credential_harvest": {
        "stages": ["Scan", "MITM", "Slowloris"],
        "description": "Port scan → MITM interception → Service disruption",
        "severity_boost": 0.35,
    },
    "stealth_escalation": {
        "stages": ["Anomaly", "Scan", "DoS"],
        "description": "Anomalous probing → Port scanning → Full DoS",
        "severity_boost": 0.25,
    },
}


# ─────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────

@dataclass
class FlowEvent:
    """A single flow event for correlation."""
    src_ip: str
    dst_ip: str
    attack_type: str
    risk_score: float
    pps: float
    timestamp: float
    syn_ratio: float = 0.0
    mitm_risk: float = 0.0
    correlation_id: str = ""


@dataclass
class CorrelationSignal:
    """Output signal from the correlation engine."""
    signal_type: str             # "distributed_attack" | "attack_chain" | "pulse_pattern" | etc.
    severity: float              # 0.0–1.0
    involved_ips: List[str] = field(default_factory=list)
    target_ip: str = ""
    description: str = ""
    correlation_id: str = ""
    chain_stage: int = 0         # For attack chains: which stage is current
    total_stages: int = 0


@dataclass
class TargetProfile:
    """Aggregated profile of attack activity targeting a single destination."""
    target_ip: str
    source_ips: Set[str] = field(default_factory=set)
    attack_types: Set[str] = field(default_factory=set)
    total_pps: float = 0.0
    max_risk: float = 0.0
    event_count: int = 0
    first_event: float = 0.0
    last_event: float = 0.0
    
    @property
    def duration_sec(self) -> float:
        if self.first_event == 0:
            return 0
        return self.last_event - self.first_event


# ─────────────────────────────────────────────
# Correlation Engine
# ─────────────────────────────────────────────

class CorrelationEngine:
    """
    Multi-flow correlation engine.

    Maintains sliding windows of flow events and detects:
      1. Distributed attacks (many IPs → one target)
      2. Attack chains (scan → flood → exploit)
      3. Pulse patterns (on-off-on attack waves)
      4. Slow-ramp attacks (gradually increasing intensity)
      5. Multi-vector attacks (DDoS + MITM combined)
      6. Micro-traffic aggregation (many tiny flows = one big attack)

    Thread-safe for concurrent pipeline access.
    """

    def __init__(self, config: Optional[dict] = None):
        self._lock = threading.Lock()
        cfg = config or {}

        # Configuration
        self._window_sec = cfg.get("multi_flow_window_sec", 30)
        self._chain_timeout_sec = cfg.get("chain_timeout_sec", 300)
        self._distributed_min_ips = cfg.get("distributed_min_ips", 3)
        self._distributed_min_pps = cfg.get("distributed_min_aggregate_pps", 50)
        self._pulse_min_cycles = cfg.get("pulse_min_cycles", 3)
        self._micro_traffic_threshold = cfg.get("micro_traffic_aggregate_pps", 30)

        # Sliding event windows
        self._event_window: deque = deque(maxlen=5000)

        # Per-target aggregation
        self._target_profiles: Dict[str, TargetProfile] = {}

        # Attack chain tracking: src_ip → [(attack_type, timestamp)]
        self._attack_chains: Dict[str, List[Tuple[str, float]]] = defaultdict(list)

        # Pulse detection: target_ip → [(pps, timestamp)]
        self._pulse_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # Rate tracking per source for slow-ramp detection
        self._rate_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))

        # Generated correlation IDs for linking events
        self._active_correlations: Dict[str, CorrelationSignal] = {}

        logger.info("CorrelationEngine initialized | window=%ds | chain_timeout=%ds",
                     self._window_sec, self._chain_timeout_sec)

    # ─────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────

    def ingest(self, event: FlowEvent) -> List[CorrelationSignal]:
        """
        Ingest a flow event and return any correlation signals detected.

        Called by the security pipeline for every processed flow.
        Returns a list of 0+ CorrelationSignals.
        """
        signals: List[CorrelationSignal] = []
        now = event.timestamp or time.time()

        with self._lock:
            # Store event
            self._event_window.append(event)

            # Update target profile
            self._update_target_profile(event, now)

            # Update attack chain tracking
            self._update_chain(event, now)

            # Update rate history
            self._rate_history[event.src_ip].append((event.pps, now))

            # Update pulse history
            self._pulse_history[event.dst_ip].append((event.pps, now))

            # ── Detection Passes ──

            # 1. Distributed attack detection
            dist_signal = self._detect_distributed(event.dst_ip, now)
            if dist_signal:
                signals.append(dist_signal)

            # 2. Attack chain detection
            chain_signal = self._detect_chain(event.src_ip, now)
            if chain_signal:
                signals.append(chain_signal)

            # 3. Multi-vector detection
            mv_signal = self._detect_multi_vector(event.dst_ip, now)
            if mv_signal:
                signals.append(mv_signal)

            # 4. Pulse pattern detection
            pulse_signal = self._detect_pulse(event.dst_ip, now)
            if pulse_signal:
                signals.append(pulse_signal)

            # 5. Slow-ramp detection
            ramp_signal = self._detect_slow_ramp(event.src_ip, now)
            if ramp_signal:
                signals.append(ramp_signal)

            # 6. Micro-traffic aggregation
            micro_signal = self._detect_micro_traffic(event.dst_ip, now)
            if micro_signal:
                signals.append(micro_signal)

        # Assign correlation IDs
        for sig in signals:
            if not sig.correlation_id:
                sig.correlation_id = str(uuid.uuid4())[:8]

        return signals

    def get_active_correlations(self) -> List[dict]:
        """Return all active correlation events for the API."""
        with self._lock:
            return [
                {
                    "correlation_id": sig.correlation_id,
                    "signal_type": sig.signal_type,
                    "severity": round(sig.severity, 3),
                    "target_ip": sig.target_ip,
                    "involved_ips": sig.involved_ips,
                    "description": sig.description,
                }
                for sig in self._active_correlations.values()
            ]

    def get_stats(self) -> dict:
        """Return correlation engine statistics."""
        with self._lock:
            return {
                "events_in_window": len(self._event_window),
                "tracked_targets": len(self._target_profiles),
                "active_chains": len(self._attack_chains),
                "active_correlations": len(self._active_correlations),
            }

    # ─────────────────────────────────────────
    # Internal Detection Methods
    # ─────────────────────────────────────────

    def _update_target_profile(self, event: FlowEvent, now: float):
        """Aggregate flow events per target IP with windowed PPS reset."""
        target = event.dst_ip
        if target not in self._target_profiles:
            self._target_profiles[target] = TargetProfile(
                target_ip=target, first_event=now
            )
        prof = self._target_profiles[target]

        # BUGFIX: Reset accumulated stats if profile is older than window
        # This prevents unbounded total_pps growth causing false positives
        if now - prof.first_event > self._window_sec:
            prof.source_ips.clear()
            prof.attack_types.clear()
            prof.total_pps = 0.0
            prof.max_risk = 0.0
            prof.event_count = 0
            prof.first_event = now

        prof.source_ips.add(event.src_ip)
        prof.attack_types.add(event.attack_type)
        prof.total_pps += event.pps
        prof.max_risk = max(prof.max_risk, event.risk_score)
        prof.event_count += 1
        prof.last_event = now

    def _update_chain(self, event: FlowEvent, now: float):
        """Track attack type progression per source IP."""
        chain = self._attack_chains[event.src_ip]
        # Remove stale entries
        chain[:] = [(at, ts) for at, ts in chain if now - ts < self._chain_timeout_sec]
        # Add current
        if not chain or chain[-1][0] != event.attack_type:
            chain.append((event.attack_type, now))

    def _detect_distributed(self, target_ip: str, now: float) -> Optional[CorrelationSignal]:
        """Detect distributed attack: many source IPs targeting one destination."""
        prof = self._target_profiles.get(target_ip)
        if not prof:
            return None

        # Only look at recent window
        if now - prof.last_event > self._window_sec:
            return None

        num_sources = len(prof.source_ips)
        if (num_sources >= self._distributed_min_ips and
                prof.total_pps >= self._distributed_min_pps):

            cid = f"dist-{target_ip}"
            signal = CorrelationSignal(
                signal_type="distributed_attack",
                severity=min(1.0, 0.3 + (num_sources * 0.05) + (prof.total_pps / 500)),
                involved_ips=list(prof.source_ips)[:20],
                target_ip=target_ip,
                description=(
                    f"Distributed attack: {num_sources} source IPs targeting {target_ip} "
                    f"with aggregate {prof.total_pps:.0f} PPS"
                ),
                correlation_id=cid,
            )
            self._active_correlations[cid] = signal
            return signal
        return None

    def _detect_chain(self, src_ip: str, now: float) -> Optional[CorrelationSignal]:
        """Detect multi-stage attack chain from a single source."""
        chain = self._attack_chains.get(src_ip, [])
        if len(chain) < 2:
            return None

        observed_types = [at for at, _ in chain]

        for chain_name, chain_def in ATTACK_CHAINS.items():
            expected = chain_def["stages"]
            # Check if observed sequence contains the expected subsequence
            if self._is_subsequence(expected[:len(observed_types)], observed_types):
                stage_idx = min(len(observed_types), len(expected))
                cid = f"chain-{src_ip}-{chain_name}"

                signal = CorrelationSignal(
                    signal_type="attack_chain",
                    severity=min(1.0, 0.5 + chain_def["severity_boost"]),
                    involved_ips=[src_ip],
                    description=(
                        f"Attack chain '{chain_name}': {chain_def['description']} — "
                        f"Stage {stage_idx}/{len(expected)} from {src_ip} "
                        f"(observed: {' → '.join(observed_types)})"
                    ),
                    correlation_id=cid,
                    chain_stage=stage_idx,
                    total_stages=len(expected),
                )
                self._active_correlations[cid] = signal
                return signal
        return None

    def _detect_multi_vector(self, target_ip: str, now: float) -> Optional[CorrelationSignal]:
        """Detect simultaneous different attack types on the same target."""
        prof = self._target_profiles.get(target_ip)
        if not prof or now - prof.last_event > self._window_sec:
            return None

        # Filter to actual attack types (not Normal/Benign)
        active_vectors = {at for at in prof.attack_types
                          if at not in ("Normal", "BENIGN", "Anomaly")}

        if len(active_vectors) >= 2:
            cid = f"multi-{target_ip}"
            signal = CorrelationSignal(
                signal_type="multi_vector_attack",
                severity=min(1.0, 0.6 + len(active_vectors) * 0.1),
                involved_ips=list(prof.source_ips)[:20],
                target_ip=target_ip,
                description=(
                    f"Multi-vector attack on {target_ip}: "
                    f"{', '.join(active_vectors)} simultaneous vectors "
                    f"from {len(prof.source_ips)} source IPs"
                ),
                correlation_id=cid,
            )
            self._active_correlations[cid] = signal
            return signal
        return None

    def _detect_pulse(self, target_ip: str, now: float) -> Optional[CorrelationSignal]:
        """Detect pulse/wave attack patterns (on-off-on cycles)."""
        history = list(self._pulse_history.get(target_ip, []))
        if len(history) < 6:
            return None

        # Look at recent entries
        recent = [(pps, ts) for pps, ts in history if now - ts < 120]
        if len(recent) < 6:
            return None

        # Detect alternating high-low-high pattern
        pps_values = [p for p, _ in recent]
        transitions = 0
        avg_pps = sum(pps_values) / len(pps_values) if pps_values else 0
        if avg_pps < 10:
            return None
            
        was_high = pps_values[0] > avg_pps

        for pps in pps_values[1:]:
            is_high = pps > avg_pps
            if is_high != was_high:
                transitions += 1
                was_high = is_high

        if transitions >= self._pulse_min_cycles * 2:
            cid = f"pulse-{target_ip}"
            signal = CorrelationSignal(
                signal_type="pulse_attack",
                severity=min(1.0, 0.4 + transitions * 0.05),
                target_ip=target_ip,
                description=(
                    f"Pulse attack pattern on {target_ip}: "
                    f"{transitions} on/off transitions in {len(recent)} windows "
                    f"(avg PPS={avg_pps:.0f})"
                ),
                correlation_id=cid,
            )
            self._active_correlations[cid] = signal
            return signal
        return None

    def _detect_slow_ramp(self, src_ip: str, now: float) -> Optional[CorrelationSignal]:
        """Detect gradually increasing attack intensity (slow-ramp)."""
        history = list(self._rate_history.get(src_ip, []))
        if len(history) < 5:
            return None

        recent = [(pps, ts) for pps, ts in history if now - ts < 300]
        if len(recent) < 5:
            return None

        pps_values = [p for p, _ in recent]

        # Check for monotonically increasing trend
        increases = sum(1 for i in range(1, len(pps_values))
                        if pps_values[i] > pps_values[i - 1])

        increase_ratio = increases / (len(pps_values) - 1)

        # If 80%+ of transitions are increases and rate grew significantly
        if increase_ratio >= 0.8 and pps_values[-1] > pps_values[0] * 2:
            cid = f"ramp-{src_ip}"
            signal = CorrelationSignal(
                signal_type="slow_ramp",
                severity=min(1.0, 0.4 + increase_ratio * 0.3),
                involved_ips=[src_ip],
                description=(
                    f"Slow-ramp attack from {src_ip}: PPS increasing from "
                    f"{pps_values[0]:.0f} → {pps_values[-1]:.0f} over "
                    f"{len(recent)} windows ({increase_ratio:.0%} increasing)"
                ),
                correlation_id=cid,
            )
            self._active_correlations[cid] = signal
            return signal
        return None

    def _detect_micro_traffic(self, target_ip: str, now: float) -> Optional[CorrelationSignal]:
        """Detect many tiny flows that aggregate to significant traffic."""
        prof = self._target_profiles.get(target_ip)
        if not prof:
            return None

        num_sources = len(prof.source_ips)
        if num_sources < 5:
            return None

        # Average PPS per source
        avg_per_source = prof.total_pps / num_sources if num_sources > 0 else 0

        # Each source is below threshold, but aggregate is high
        if avg_per_source < 10 and prof.total_pps >= self._micro_traffic_threshold:
            cid = f"micro-{target_ip}"
            signal = CorrelationSignal(
                signal_type="micro_traffic_aggregation",
                severity=min(1.0, 0.3 + prof.total_pps / 200),
                involved_ips=list(prof.source_ips)[:20],
                target_ip=target_ip,
                description=(
                    f"Micro-traffic DDoS on {target_ip}: {num_sources} sources each "
                    f"sending ~{avg_per_source:.1f} PPS (aggregate={prof.total_pps:.0f} PPS)"
                ),
                correlation_id=cid,
            )
            self._active_correlations[cid] = signal
            return signal
        return None

    # ─────────────────────────────────────────
    # Utilities
    # ─────────────────────────────────────────

    @staticmethod
    def _is_subsequence(needle: list, haystack: list) -> bool:
        """Check if needle is a subsequence of haystack."""
        it = iter(haystack)
        return all(item in it for item in needle)

    def cleanup(self):
        """Remove stale entries from all tracking dictionaries."""
        now = time.time()
        with self._lock:
            # Clean target profiles older than 2x window
            stale_targets = [
                ip for ip, prof in self._target_profiles.items()
                if now - prof.last_event > self._window_sec * 2
            ]
            for ip in stale_targets:
                del self._target_profiles[ip]

            # Clean expired attack chains
            stale_chains = [
                ip for ip, chain in self._attack_chains.items()
                if not chain or now - chain[-1][1] > self._chain_timeout_sec
            ]
            for ip in stale_chains:
                del self._attack_chains[ip]

            # Clean expired correlations
            stale_corr = [
                cid for cid, sig in self._active_correlations.items()
                if now - getattr(sig, '_created_at', now) > self._window_sec * 3
            ]
            for cid in stale_corr:
                del self._active_correlations[cid]

            # Cap dictionary sizes
            for d in (self._rate_history, self._pulse_history):
                if len(d) > 5000:
                    keys = list(d.keys())
                    for k in keys[:len(keys) - 2500]:
                        del d[k]
