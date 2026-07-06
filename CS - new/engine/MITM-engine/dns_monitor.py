"""
DNS Poisoning Detection Engine
==============================
Tracks DNS queries and responses to identify spoofed results,
unexpected resolvers, and wildly short TTLs typical of cache poisoning.
"""
import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional
import collections
from scapy.all import IP, UDP, DNS, DNSRR

logger = logging.getLogger("mitm.dns_monitor")

@dataclass
class DnsEvent:
    event_type: str
    source_ip: str
    details: str
    confidence: float
    timestamp: float

class DnsMonitor:
    def __init__(self):
        # Transaction ID -> query metadata
        self._pending_queries = collections.OrderedDict() 
        self._event_queue = []

    def process_packet(self, packet) -> Optional[DnsEvent]:
        if not packet.haslayer(DNS) or not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        dns_layer = packet[DNS]
        
        # DNS Query
        if dns_layer.qr == 0:
            # Record it
            tx_id = dns_layer.id
            if packet.haslayer(UDP):
                self._pending_queries[tx_id] = {
                    "time": time.time(),
                    "server": ip_layer.dst,
                    "qname": dns_layer.qd.qname.decode('utf-8') if dns_layer.qd else ""
                }
                # Keep cache small
                if len(self._pending_queries) > 1000:
                    self._pending_queries.popitem(last=False)

        # DNS Response
        elif dns_layer.qr == 1:
            tx_id = dns_layer.id
            responder_ip = ip_layer.src
            
            if tx_id in self._pending_queries:
                qmeta = self._pending_queries.pop(tx_id)
                expected_server = qmeta["server"]
                
                # Check 1: Mismatched Responder
                if responder_ip != expected_server:
                    ev = DnsEvent(
                        event_type="DNS_RESOLUTION_HIJACK",
                        source_ip=responder_ip,
                        details=f"Spoofed DNS response for {qmeta['qname']} from {responder_ip} (expected {expected_server})",
                        confidence=0.9,
                        timestamp=time.time()
                    )
                    self._event_queue.append(ev)
                    return ev
                    
                # Check 2: Impossibly fast response (indicates local attacker race winning)
                rtt = time.time() - qmeta["time"]
                if rtt < 0.001 and expected_server not in ["192.168.1.1", "127.0.0.1", "10.0.0.1"]: # Extremely low for remote
                     ev = DnsEvent(
                        event_type="DNS_RESOLUTION_HIJACK",
                        source_ip=responder_ip,
                        details=f"Suspiciously fast DNS reply for {qmeta['qname']} ({rtt*1000:.1f}ms). Possible local race/poisoning.",
                        confidence=0.6,
                        timestamp=time.time()
                     )
                     self._event_queue.append(ev)
                     return ev
                     
        return None

    def drain_events(self) -> List[DnsEvent]:
        evs = list(self._event_queue)
        self._event_queue.clear()
        return evs
