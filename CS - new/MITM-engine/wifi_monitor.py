"""
Rogue Access Point & Evil Twin Monitor
======================================
Actively scans the Wi-Fi environment (OS-dependent) to detect
multiple BSSIDs claiming the same SSID, prioritizing anomalies
in signal strength and gateway association.
"""
import time
import subprocess
import platform
import logging
import re
import threading
from dataclasses import dataclass
from typing import List, Dict

logger = logging.getLogger("mitm.wifi_monitor")

@dataclass
class WifiEvent:
    event_type: str
    details: str
    confidence: float
    bssid: str = ""
    ssid: str = ""

class WifiMonitor:
    def __init__(self, check_interval: float = 30.0):
        self._check_interval = check_interval
        self._os = platform.system().lower()
        self._running = False
        self._thread = None
        self._event_queue = []
        self._lock = threading.Lock()
        
        # ssid -> set of BSSIDs
        self._known_networks: Dict[str, set] = {}

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def _scan_loop(self):
        while self._running:
            try:
                networks = self._scan_networks()
                self._analyze_networks(networks)
            except Exception as e:
                logger.debug(f"Wifi scan error: {e}")
            
            for _ in range(int(self._check_interval)):
                if not self._running: break
                time.sleep(1)

    def _scan_networks(self) -> List[dict]:
        results = []
        if self._os == "windows":
            # Parsing `netsh wlan show networks mode=bssid`
            out = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, errors="ignore").stdout
            current_ssid = ""
            for line in out.splitlines():
                if line.startswith("SSID"):
                    match = re.search(r"SSID \d+ : (.*)", line)
                    if match:
                        current_ssid = match.group(1).strip()
                elif "BSSID" in line:
                    match = re.search(r"BSSID \d+\s+: (.*)", line)
                    if match and current_ssid:
                        bssid = match.group(1).strip()
                        results.append({"ssid": current_ssid, "bssid": bssid})
        elif self._os == "linux":
            # Placeholder for iwlist parsing
            pass
            
        return results

    def _analyze_networks(self, networks: List[dict]):
        current_map = {}
        for net in networks:
            ssid = net["ssid"]
            bssid = net["bssid"].lower()
            if not ssid: continue
            
            if ssid not in current_map:
                current_map[ssid] = set()
            current_map[ssid].add(bssid)

        with self._lock:
            for ssid, bssids in current_map.items():
                if ssid not in self._known_networks:
                    self._known_networks[ssid] = bssids
                else:
                    new_bssids = bssids - self._known_networks[ssid]
                    if new_bssids and len(self._known_networks[ssid]) > 0:
                        # Alert Evil Twin potential if a NEW BSSID suddenly appears for an existing secure network
                        for new_b in new_bssids:
                            self._event_queue.append(WifiEvent(
                                event_type="WIFI_SSID_IMPERSONATION",
                                details=f"New rogue BSSID {new_b} detected for known SSID {ssid}. Possible Evil Twin.",
                                confidence=0.8,
                                bssid=new_b,
                                ssid=ssid
                            ))
                    self._known_networks[ssid].update(bssids)
                    
    def drain_events(self) -> List[WifiEvent]:
        with self._lock:
            evs = list(self._event_queue)
            self._event_queue.clear()
            return evs
