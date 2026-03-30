"""
Latency Monitor Module — Percentile-Aware
=========================================
Monitors gateway RTT for signs of MITM extra-hop insertion using 
90th-percentile anomaly detection for improved Wi-Fi stability.
"""

import time
import logging
import threading
import subprocess
import platform
import re
import statistics
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Optional, Deque, List, Dict

from mitm_config import LatencyMonitorConfig

logger = logging.getLogger("mitm.latency_monitor")


@dataclass
class LatencyEvent:
    """Event representing a significant RTT drift."""
    event_type: str  # "latency_drift"
    gateway_ip: str
    current_rtt_ms: float
    percentile_rtt_ms: float
    confidence: float
    details: str
    timestamp: float = field(default_factory=time.time)


class LatencyMonitor:
    """
    Monitors gateway RTT using percentile-based detection.
    """

    def __init__(self, config: LatencyMonitorConfig, gateway_ips: Optional[List[str]] = None):
        self._cfg = config
        self._gateway_ips: List[str] = gateway_ips or []
        self._lock = threading.Lock()
        
        # Per-IP RTT history
        self._history: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=200))
        
        # Consistent drift counters
        self._drift_count: Dict[str, int] = defaultdict(int)
        
        # Event queue
        self._event_queue: Deque[LatencyEvent] = deque(maxlen=200)
        self._running = False
        self._thread: Optional[threading.Thread] = None

        logger.info("LatencyMonitor initialized for: %s", self._gateway_ips)

    def start(self):
        """Start the background monitor thread."""
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, name="LatMonitor", daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the background monitor thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def _monitor_loop(self):
        """Background loop to periodically probe gateways."""
        while self._running:
            for gw in list(self._gateway_ips):
                try:
                    self._probe_and_analyze(gw)
                except Exception as e:
                    logger.debug("Probe failure for %s: %s", gw, e)
            
            # Adaptive sleep based on config
            time.sleep(self._cfg.probe_interval_seconds)

    def _probe_and_analyze(self, gw: str):
        """Execute a single probe and check against percentile baseline."""
        rtt = self._measure_rtt(gw)
        if not rtt or rtt > self._cfg.max_valid_rtt_ms:
            return

        with self._lock:
            h = self._history[gw]
            h.append(rtt)
            
            if len(h) < 20: 
                return # Need baseline

            # Calculate 90th percentile (robust to jitter)
            all_rtts = sorted(list(h))
            idx = int(len(all_rtts) * 0.9)
            p90 = all_rtts[idx]

            # Drift Check: Significant jump relative AND absolute
            # Use 50% jump AND at least 5ms to avoid micro-jitter
            if rtt > (p90 * 1.5) and (rtt - p90) > 5.0:
                self._drift_count[gw] += 1
                if self._drift_count[gw] >= self._cfg.sustained_drift_count:
                    self._raise_event(gw, rtt, p90)
            else:
                self._drift_count[gw] = 0

    def _measure_rtt(self, target: str) -> Optional[float]:
        """Perform system ping to measure AVG RTT."""
        try:
            sys_os = platform.system().lower()
            count_flag = "-n" if sys_os == "windows" else "-c"
            timeout_flag = "-w" if sys_os == "windows" else "-W"
            
            # Windows timeout is ms, Linux is seconds
            to_val = str(int(self._cfg.ping_timeout_seconds * 1000) if sys_os == "windows" else int(self._cfg.ping_timeout_seconds))
            
            cmd = ["ping", count_flag, str(self._cfg.pings_per_measurement), timeout_flag, to_val, target]
            res = subprocess.run(cmd, capture_output=True, text=True, errors="ignore", timeout=10)
            
            if res.returncode != 0: 
                return None
            
            # Extract AVG RTT using regex
            if sys_os == "windows":
                match = re.search(r"Average\s*=\s*(\d+)ms", res.stdout)
                if match: return float(match.group(1))
            else:
                # Linux/Mac patterns: min/avg/max/mdev = 0.043/0.051/0.062/0.007 ms
                match = re.search(r"min/avg/max/mdev\s*=\s*[\d.]+/([\d.]+)/", res.stdout)
                if match: return float(match.group(1))
                
        except Exception:
            return None
        return None

    def _raise_event(self, gw: str, rtt: float, p90: float):
        """Add latency event to queue."""
        detail = f"RTT jump: {rtt:.1f}ms (Baseline P90={p90:.1f}ms). Extra hop suspected."
        ev = LatencyEvent("latency_drift", gw, rtt, p90, 0.7, detail)
        self._event_queue.append(ev)
        logger.warning("Latency Drift Detected on %s: %s", gw, detail)

    def drain_events(self) -> List[LatencyEvent]:
        """Collect and clear all detected events."""
        with self._lock:
            evs = list(self._event_queue)
            self._event_queue.clear()
            return evs
