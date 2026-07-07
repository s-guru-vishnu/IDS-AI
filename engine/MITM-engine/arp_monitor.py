"""
ARP Monitor Module — Stealth-Aware
==================================
Enhanced detection for traditional ARP spoofing AND low-frequency stealth poisoning.
Includes OUI-based MAC randomization verification.
"""

import time
import logging
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Deque, List, Set

from scapy.layers.l2 import ARP, Ether
from mitm_config import ArpMonitorConfig

logger = logging.getLogger("mitm.arp_monitor")


@dataclass
class ArpEntry:
    """ARP entry tracking with EMA for stealth detection."""
    ip: str
    mac: str
    first_seen: float
    last_seen: float
    change_count: int = 0
    verified: bool = False
    
    # Track "Unsolicited Reply" rate via EMA for stealth detection
    unsolicited_ema: float = 0.0


@dataclass
class ArpEvent:
    """Recorded ARP anomaly event."""
    event_type: str  # "mac_change", "flood", "stealth_spoof", "gratuitous", "unsolicited"
    source_ip: str
    source_mac: str
    old_mac: str = ""
    details: str = ""
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)


class ArpMonitor:
    """
    Production-grade ARP monitor with stealth detection and OUI validation.
    """

    def __init__(self, config: ArpMonitorConfig, trusted_macs: Set[str] = None):
        self._cfg = config
        self._trusted_macs = trusted_macs or set()
        self._lock = threading.Lock()
        
        # IP -> ArpEntry
        self._arp_table: Dict[str, ArpEntry] = {}
        
        # Request Tracking: target_ip -> [timestamps]
        self._requests: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=100))
        
        # Current reply timestamps by MAC (for flood detection)
        self._reply_ts: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=200))

        logger.info("ArpMonitor (Stealth-Aware) initialized")

    def process_packet(self, pkt) -> Optional[ArpEvent]:
        if not pkt.haslayer(ARP): return None
        
        arp = pkt[ARP]
        now = time.time()
        op = arp.op  # 1=req, 2=rep
        sip, smac = arp.psrc, arp.hwsrc.lower()
        dip, dmac = arp.pdst, arp.hwdst.lower()

        if sip in ("0.0.0.0", "255.255.255.255") or smac in self._trusted_macs:
            return None

        if op == 1:
            with self._lock: self._requests[dip].append(now)
            return None
            
        elif op == 2:
            return self._process_reply(sip, smac, dip, dmac, now)

        return None

    def _process_reply(self, sip: str, smac: str, dip: str, dmac: str, now: float) -> Optional[ArpEvent]:
        with self._lock:
            # Update EMA for unsolicited replies manually
            has_request = any(ts >= (now - 5.0) for ts in self._requests.get(sip, []))
            
            if sip not in self._arp_table:
                self._arp_table[sip] = ArpEntry(sip, smac, now, now)

            entry = self._arp_table[sip]
            entry.last_seen = now
            
            # Update Stealth Detection EMA (EMA alpha = 0.2)
            alpha = 0.2
            is_unsolicited = 1.0 if not has_request else 0.0
            entry.unsolicited_ema = (alpha * is_unsolicited) + (1.0 - alpha) * entry.unsolicited_ema
            
            # --- Stealth Check ---
            if entry.unsolicited_ema > 0.6: # High unsolicited bias
                return self._raise_event("stealth_spoof", sip, smac, "", 
                    f"Sustained unsolicited replies (EMA={entry.unsolicited_ema:.2f})", 0.7)

            # --- MAC Change Check ---
            if entry.mac != smac:
                old_mac = entry.mac
                entry.mac = smac
                entry.change_count += 1
                entry.verified = False
                
                # Check for MAC randomization (Standard pattern check)
                is_rand = self._is_locally_administered(smac)
                confidence = 0.4 if is_rand else 0.8
                
                return self._raise_event("mac_change", sip, smac, old_mac,
                    f"Binding changed from {old_mac} to {smac} (RandMAC={is_rand})", confidence)

            # --- Flood Check ---
            self._reply_ts[smac].append(now)
            win_start = now - self._cfg.arp_flood_window_seconds
            count = sum(1 for ts in self._reply_ts[smac] if ts >= win_start)
            
            if count >= self._cfg.arp_flood_threshold:
                return self._raise_event("flood", sip, smac, "", 
                    f"Flood detected: {count} replies in window", 0.9)

        return None

    def _raise_event(self, etype: str, sip: str, smac: str, omac: str, details: str, conf: float) -> ArpEvent:
        ev = ArpEvent(etype, sip, smac, omac, details, conf)
        logger.warning(f"ARP Monitor: [{sip}] {details}")
        return ev

    def _is_locally_administered(self, mac: str) -> bool:
        try:
            # Second hex character: 2, 6, A, or E
            c = mac.replace(":", "")[1].lower()
            return c in ("2", "6", "a", "e")
        except: return False

    def mark_verified(self, ip: str, mac: str):
        with self._lock:
            if ip in self._arp_table and self._arp_table[ip].mac.lower() == mac.lower():
                self._arp_table[ip].verified = True

    def get_arp_table(self):
        with self._lock: return dict(self._arp_table)
        
    def cleanup_stale(self, ttl: float):
        now = time.time()
        with self._lock:
            stale_ips = [i for i, e in self._arp_table.items() if (now - e.last_seen) > ttl]
            for ip in stale_ips: 
                self._arp_table.pop(ip, None)
