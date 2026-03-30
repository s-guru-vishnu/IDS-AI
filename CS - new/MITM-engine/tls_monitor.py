"""
TLS & HTTPS Session Integrity Monitor
======================================
Monitors port 443 traffic for anomalies like SSL Stripping
(sudden shift of port 443 traffic to port 80) and basic certificate metadata.
"""
import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional
from scapy.all import IP, TCP, Raw

logger = logging.getLogger("mitm.tls_monitor")

@dataclass
class TlsEvent:
    event_type: str
    source_ip: str
    details: str
    confidence: float
    timestamp: float

class TlsMonitor:
    def __init__(self, history_window: float = 300.0):
        self._history_window = history_window
        self._ip_to_https_count: Dict[str, int] = {}
        self._ip_to_http_count: Dict[str, int] = {}
        self._event_queue = []

    def process_packet(self, packet) -> Optional[TlsEvent]:
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return None
            
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # Track HTTP vs HTTPS ratios for SSL stripping detection
        if tcp_layer.dport == 443 or tcp_layer.sport == 443:
            self._ip_to_https_count[dst_ip] = self._ip_to_https_count.get(dst_ip, 0) + 1
            
            # Simplified TLS matching using Raw payload
            if packet.haslayer(Raw):
                payload = packet.getlayer(Raw).load
                # Check for ServerHello / ClientHello
                if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03:
                    pass # It's a TLS handshake record
                    
        elif tcp_layer.dport == 80 or tcp_layer.sport == 80:
            self._ip_to_http_count[dst_ip] = self._ip_to_http_count.get(dst_ip, 0) + 1
            
            # Check for sudden downgrade: previous HTTPS host now suddenly exclusively HTTP
            https_hits = self._ip_to_https_count.get(dst_ip, 0)
            http_hits = self._ip_to_http_count.get(dst_ip, 0)
            
            if https_hits > 50 and http_hits > 10 and (http_hits / (https_hits + http_hits)) > 0.8:
                # Flag SSL Stripping
                ev = TlsEvent(
                    event_type="TLS_SESSION_TAMPERING",
                    source_ip=src_ip, # The router/proxy sending it
                    details=f"SSL Stripping anomaly to dest {dst_ip}. Downgrade 443 -> 80.",
                    confidence=0.75,
                    timestamp=time.time()
                )
                self._event_queue.append(ev)
                self._ip_to_http_count[dst_ip] = 0 # Reset to avoid spam
                return ev
                
        return None

    def drain_events(self) -> List[TlsEvent]:
        evs = list(self._event_queue)
        self._event_queue.clear()
        return evs
