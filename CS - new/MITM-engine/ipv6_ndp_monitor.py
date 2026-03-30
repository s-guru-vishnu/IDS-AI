"""
IPv6 NDP Spoofing Monitor
=========================
Monitors ICMPv6 Neighbor Discovery Protocol (Router Advertisements 
and Neighbor Advertisements) to detect IPv6 MITM equivalent of ARP spoofing.
"""
import logging
import time
from dataclasses import dataclass
from typing import List, Optional, Dict
from scapy.all import IPv6, ICMPv6ND_RA, ICMPv6ND_NA

logger = logging.getLogger("mitm.ipv6_ndp_monitor")

@dataclass
class Ipv6Event:
    event_type: str
    source_ip: str
    source_mac: str
    details: str
    confidence: float
    timestamp: float

class Ipv6NdpMonitor:
    def __init__(self):
        self._routers: Dict[str, str] = {} # IPv6 -> MAC
        self._event_queue = []
        self._ra_counts: Dict[str, list] = {}

    def process_packet(self, packet) -> Optional[Ipv6Event]:
        if not packet.haslayer(IPv6):
            return None
            
        ipv6_layer = packet[IPv6]
        src_ip = ipv6_layer.src
        
        # We need Ether for MAC
        from scapy.all import Ether
        if not packet.haslayer(Ether):
            return None
        src_mac = packet[Ether].src

        now = time.time()

        # Check for Router Advertisement (Type 134)
        if packet.haslayer(ICMPv6ND_RA):
            if src_ip in self._routers and self._routers[src_ip] != src_mac:
                ev = Ipv6Event(
                    event_type="IPV6_NDP_ATTACK",
                    source_ip=src_ip,
                    source_mac=src_mac,
                    details=f"IPv6 Router MAC changed from {self._routers[src_ip]} to {src_mac}",
                    confidence=0.9,
                    timestamp=now
                )
                self._event_queue.append(ev)
                return ev
                
            self._routers[src_ip] = src_mac
            
            # Flood logic
            if src_ip not in self._ra_counts:
                self._ra_counts[src_ip] = []
            self._ra_counts[src_ip].append(now)
            
            # Clean old
            self._ra_counts[src_ip] = [t for t in self._ra_counts[src_ip] if now - t < 10.0]
            if len(self._ra_counts[src_ip]) > 20: # 20 RAs in 10s is a flood
                ev = Ipv6Event(
                    event_type="IPV6_NDP_ATTACK",
                    source_ip=src_ip,
                    source_mac=src_mac,
                    details=f"IPv6 Router Advertisement Flood detected.",
                    confidence=0.8,
                    timestamp=now
                )
                self._event_queue.append(ev)
                self._ra_counts[src_ip].clear()
                return ev

        # Check for Neighbor Advertisement (Type 136)
        # Similar logic to ARP spoofing duplicate/conflict tracking could go here
        
        return None

    def drain_events(self) -> List[Ipv6Event]:
        evs = list(self._event_queue)
        self._event_queue.clear()
        return evs
