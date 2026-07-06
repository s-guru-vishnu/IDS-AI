"""
heartbeat.py — Engine Health Monitor
======================================
Sends periodic heartbeat POSTs to the backend so the dashboard
knows the engine is alive. Handles disconnects gracefully.
"""

import os
import sys
import time
import socket
import logging
import threading
import requests
from datetime import datetime

# Allow import from engine root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import EngineConfig

logger = logging.getLogger("ids.heartbeat")


class EngineHeartbeat:
    """Background heartbeat that never crashes the main engine."""

    def __init__(self):
        self.backend_url = EngineConfig.BACKEND_URL.rstrip("/")
        self.engine_name = EngineConfig.ENGINE_NAME
        self.interval = EngineConfig.HEARTBEAT_INTERVAL
        self.start_time = time.time()
        self._thread = None
        self._stop_event = threading.Event()

        # Tracked stats (updated externally by main.py)
        self.packets_processed = 0
        self.threats_detected = 0
        self.models_loaded = False
        self.mongo_connected = False

    def start(self):
        """Start the heartbeat background thread."""
        self._thread = threading.Thread(target=self._loop, daemon=True, name="heartbeat")
        self._thread.start()
        logger.info(f"[HEARTBEAT] Started — posting to {self.backend_url} every {self.interval}s")

    def stop(self):
        """Signal the heartbeat to stop."""
        self._stop_event.set()

    def _loop(self):
        while not self._stop_event.is_set():
            try:
                self._send()
            except Exception as e:
                logger.warning(f"[HEARTBEAT] Failed to send: {e}")
            self._stop_event.wait(self.interval)

    def _send(self):
        payload = {
            "engine_name": self.engine_name,
            "status": "running",
            "uptime_seconds": round(time.time() - self.start_time),
            "packets_processed": self.packets_processed,
            "threats_detected": self.threats_detected,
            "models_loaded": self.models_loaded,
            "mongo_connected": self.mongo_connected,
            "hostname": socket.gethostname(),
            "timestamp": datetime.utcnow().isoformat(),
            "environment": EngineConfig.ENVIRONMENT,
        }
        try:
            resp = requests.post(
                f"{self.backend_url}/api/health",
                json=payload,
                timeout=10,
            )
            if resp.status_code == 200:
                logger.debug("[HEARTBEAT] ✅ Sent successfully")
            else:
                logger.warning(f"[HEARTBEAT] Backend returned {resp.status_code}")
        except requests.ConnectionError:
            logger.warning("[HEARTBEAT] Backend unreachable — will retry")
        except requests.Timeout:
            logger.warning("[HEARTBEAT] Backend timeout — will retry")
