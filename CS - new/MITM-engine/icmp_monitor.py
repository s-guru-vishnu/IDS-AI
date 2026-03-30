"""
ICMP Redirect Monitor
=====================
Detects malicious ICMP Type 5 packets trying to manipulate
host routing tables independently of ARP.
"""
import logging
import time
from dataclasses import dataclass
from typing import List, Optional
from scapy.all import IP, ICMP

logger = logging.getLogger("mitm.icmp_monitor")

@dataclass
class IcmpEvent:
    event_type: str
    source_ip: str
    details: str
    confidence: float
    timestamp: float

class IcmpMonitor:
    def __init__(self, gateway_ips: List[str]):
        self._gateway_ips = set(gateway_ips)
        self._event_queue = []

    def set_gateways(self, gateways: List[str]):
        self._gateway_ips = set(gateways)

    def process_packet(self, packet) -> Optional[IcmpEvent]:
        if not packet.haslayer(ICMP) or not packet.haslayer(IP):
            return None
            
        icmp_layer = packet.getlayer(ICMP)
        ip_layer = packet.getlayer(IP)
        
        # ICMP Type 5 is Redirect
        if icmp_layer.type == 5:
            src_ip = ip_layer.src
            gw_redirectto = icmp_layer.gw
            
            # Legitimate redirects should only come from the true gateway
            if src_ip not in self._gateway_ips:
                ev = IcmpEvent(
                    event_type="ROUTE_REDIRECT_SPOOF",
                    source_ip=src_ip,
                    details=f"Illegitimate ICMP Redirect from {src_ip} pointing to {gw_redirectto}",
                    confidence=0.95,
                    timestamp=time.time()
                )
                self._event_queue.append(ev)
                return ev
                
        return None

    def drain_events(self) -> List[IcmpEvent]:
        evs = list(self._event_queue)
        self._event_queue.clear()
        return evs
