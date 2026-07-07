"""
Behaviour Analyzer Module
=========================
Adaptive network behaviour analysis using Exponential Moving Averages (EMA)
and TTL distribution tracking to detect MITM relay indicators.
"""

import time
import logging
import threading
from collections import defaultdict, deque, Counter
from dataclasses import dataclass, field
from typing import Dict, Optional, Deque, List, Tuple, Set

from mitm_config import BehaviourAnalyzerConfig, EmaConfig

logger = logging.getLogger("mitm.behaviour_analyzer")


@dataclass
class IpProfile:
    """Adaptive traffic profile for a single IP address."""
    ip: str
    first_seen: float
    last_seen: float

    # --- EMA-Based Rate Tracking ---
    # Current exponential moving average of packet rate
    ema_rate: float = 0.0
    
    # --- TTL (Time-to-Live) Analysis ---
    # Counts of observed TTL values.
    ttl_counts: Counter[int] = field(default_factory=Counter)
    
    # --- MAC Churn ---
    # Unique MACs associated with this IP
    seen_macs: Set[str] = field(default_factory=set)

    # Historical rate samples for baseline
    rate_history: Deque[float] = field(default_factory=lambda: deque(maxlen=200))

    # Internal state
    packet_times: Deque[float] = field(default_factory=lambda: deque(maxlen=5000))
    spike_count: int = 0


@dataclass
class BehaviourEvent:
    """Event raised when adaptive thresholds are breached."""
    event_type: str  # "rate_spike", "ttl_drift", "mac_churn"
    source_ip: str
    details: str
    confidence: float
    source_mac: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


class BehaviourAnalyzer:
    """
    Analyzes network patterns using adaptive thresholds and EMA.
    """

    def __init__(self, config: BehaviourAnalyzerConfig, ema_cfg: EmaConfig):
        self._cfg = config
        self._ema_cfg = ema_cfg
        self._lock = threading.Lock()
        
        # IP -> IpProfile
        self._profiles: Dict[str, IpProfile] = {}
        
        # Event queue
        self._event_queue: Deque[BehaviourEvent] = deque(maxlen=500)

        logger.info("BehaviourAnalyzer (Adaptive) initialized")

    def record_packet(self, src_ip: str, src_mac: str, ttl: int, timestamp: Optional[float] = None):
        """Record packet metadata for adaptive analysis."""
        if timestamp is None:
            timestamp = time.time()

        # Skip broadcasts
        if src_ip in ("0.0.0.0", "255.255.255.255") or src_ip.startswith("224."):
            return

        with self._lock:
            if src_ip not in self._profiles:
                if len(self._profiles) >= self._cfg.max_tracked_ips:
                    self._cleanup_expired()
                    if len(self._profiles) >= self._cfg.max_tracked_ips:
                        return

                self._profiles[src_ip] = IpProfile(
                    ip=src_ip, first_seen=timestamp, last_seen=timestamp
                )

            p = self._profiles[src_ip]
            p.packet_times.append(timestamp)
            p.last_seen = timestamp
            p.ttl_counts[ttl] += 1
            p.seen_macs.add(src_mac.lower())
            
            # --- Check MAC Churn ---
            if len(p.seen_macs) > self._cfg.max_macs_per_ip:
                self._raise_event("mac_churn", src_ip, 
                    f"IP associated with {len(p.seen_macs)} unique MACs: {p.seen_macs}", 0.8, mac=src_mac)

    def analyze(self) -> List[BehaviourEvent]:
        """Run periodic adaptive analysis."""
        events = []
        now = time.time()
        window = self._cfg.rate_window_seconds
        
        with self._lock:
            for ip, p in list(self._profiles.items()):
                # --- Rate Analysis (EMA) ---
                curr_count = sum(1 for ts in p.packet_times if ts >= (now - window))
                
                if curr_count >= self._cfg.min_packet_threshold:
                    # Update EMA
                    alpha = self._ema_cfg.rate_alpha
                    p.ema_rate = (alpha * curr_count) + (1.0 - alpha) * p.ema_rate
                    
                    # Spike Detection
                    if p.ema_rate > 0 and (curr_count / p.ema_rate) > self._cfg.rate_spike_multiplier:
                        p.spike_count += 1
                        if p.spike_count >= 2:
                            mac_hint = list(p.seen_macs)[0] if p.seen_macs else None
                            events.append(self._raise_event("rate_spike", ip, 
                                f"Rate {curr_count}/15s is {curr_count/p.ema_rate:.1f}x baseline {p.ema_rate:.1f}", 0.7, mac=mac_hint))
                    else:
                        p.spike_count = 0

                # --- TTL Drift Analysis ---
                if sum(p.ttl_counts.values()) > 50:
                    most_common_ttls = p.ttl_counts.most_common(2)
                    if len(most_common_ttls) > 1:
                        # If a secondary TTL holds more than 30% of traffic, it's anomalous
                        total = sum(p.ttl_counts.values())
                        secondary_ratio = most_common_ttls[1][1] / total
                        if secondary_ratio > 0.3:
                            # Use one of the seen MACs as a hint (not perfect but better than nothing)
                            mac_hint = list(p.seen_macs)[0] if p.seen_macs else None
                            events.append(self._raise_event("ttl_drift", ip,
                                f"Anomalous TTL distribution: {dict(p.ttl_counts.items())}", 0.6, mac=mac_hint))
                            p.ttl_counts.clear()

        return events

    def _raise_event(self, ev_type: str, ip: str, details: str, conf: float, mac: Optional[str] = None) -> BehaviourEvent:
        ev = BehaviourEvent(event_type=ev_type, source_ip=ip, details=details, confidence=conf, source_mac=mac)
        self._event_queue.append(ev)
        logger.warning(f"Behaviour Anomaly: [{ip}] {details}")
        return ev

    def _cleanup_expired(self):
        now = time.time()
        expired = [i for i, p in self._profiles.items() if (now - p.last_seen) > self._cfg.ip_expiry_seconds]
        for ip in expired: 
            self._profiles.pop(ip, None)

    def drain_events(self) -> List[BehaviourEvent]:
        with self._lock:
            evs = list(self._event_queue)
            self._event_queue.clear()
            return evs
