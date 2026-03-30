"""
Response Engine Module
======================
Automated response system for confirmed MITM attacks.

Capabilities:
  - Firewall-based IP blocking (Windows netsh / Linux iptables)
  - Structured alert generation (console + JSON log)
  - ARP correction broadcast (optional defensive response)
  - Quarantine with auto-unblock timer
  - Safety guards to NEVER block gateway or own host

Design:
  - Thread-safe blocking/unblocking operations
  - Maximum concurrent blocks limit (prevent runaway)
  - OS-aware firewall command generation
  - Scheduled auto-unblock using daemon threads
  - JSON-structured alert logging for SIEM integration
"""

import os
import sys
import json
import time
import logging
import platform
import threading
import subprocess
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Deque, List, Any

from mitm_config import ResponseConfig

logger = logging.getLogger("mitm.response_engine")


@dataclass
class BlockRecord:
    """Record of an active IP block."""
    ip: str
    score: float
    threat_level: str
    blocked_at: float
    unblock_at: float  # Scheduled unblock time
    reason: str
    active: bool = True


@dataclass
class Alert:
    """Structured alert for MITM detection."""
    alert_id: str
    timestamp: str
    timestamp_epoch: float
    source_ip: str
    threat_level: str
    risk_score: float
    detection_details: List[str]
    action_taken: str
    blocked: bool
    source_mac: Optional[str] = None
    blocked_mac: bool = False
    alert_type: str = "MITM_DETECTED"

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2)

    def to_console(self) -> str:
        """Format alert for console display with visual severity indicators."""
        severity_icons = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
        }
        icon = severity_icons.get(self.threat_level, "⚪")

        lines = [
            "",
            "╔══════════════════════════════════════════════════════════════╗",
            f"║  {icon} MITM DETECTION ALERT — {self.threat_level:<10}                    ║",
            "╠══════════════════════════════════════════════════════════════╣",
            f"║  Alert ID:    {self.alert_id:<46}║",
            f"║  Time:        {self.timestamp:<46}║",
            f"║  Source IP:   {self.source_ip:<46}║",
            f"║  Source MAC:  {str(self.source_mac):<46}║",
            f"║  Risk Score:  {self.risk_score:<46.1f}║",
            f"║  Action:      {self.action_taken:<46}║",
            "╠══════════════════════════════════════════════════════════════╣",
            "║  Detection Details:                                        ║",
        ]
        for detail in self.detection_details[-5:]:
            truncated = detail[:56]
            lines.append(f"║    • {truncated:<55}║")
        lines.append(
            "╚══════════════════════════════════════════════════════════════╝"
        )
        return "\n".join(lines)


class ResponseEngine:
    """
    Executes automated responses when high-confidence MITM attacks are detected.
    """

    def __init__(
        self,
        config: ResponseConfig,
        own_ip: Optional[str] = None,
        gateway_ips: Optional[List[str]] = None,
        alert_log_file: str = "mitm_alerts.json",
        db: Optional[Any] = None,
    ):
        self._config = config
        self._own_ip = own_ip
        self._alert_log_file = alert_log_file
        self._db = db
        self._lock = threading.Lock()
        
        # MongoDB collection for alerts
        self._mongo_collection = None
        if self._db is not None:
            try:
                self._mongo_collection = self._db["mitm_alerts"]
                logger.info("MongoDB alert collection 'mitm_alerts' initialized")
            except Exception as e:
                logger.error("Failed to initialize MongoDB alert collection: %s", e)

        # Build protected collections (never block these)
        self._protected_ips: Set[str] = set(config.protected_ips)
        self._protected_macs: Set[str] = set() # Optional extension
        if own_ip:
            self._protected_ips.add(own_ip)
        if gateway_ips:
            self._protected_ips.update(gateway_ips)
        self._protected_ips.add("127.0.0.1")
        self._protected_ips.add("0.0.0.0")

        # Active blocks
        self._active_blocks: Dict[str, BlockRecord] = {}

        # Alert counter for unique IDs
        self._alert_counter = 0

        # Alert history
        self._alert_history: Deque[Alert] = deque(maxlen=500)

        # Auto-detect OS for firewall commands
        self._os = platform.system().lower()
        self._setup_firewall_commands()

        logger.info(
            "ResponseEngine initialized (OS=%s, protected_ips=%s)",
            self._os,
            self._protected_ips,
        )

    def _setup_firewall_commands(self):
        """Configure OS-specific firewall commands."""
        if self._os == "windows":
            # Windows primarily supports IP blocking
            self._config.block_command_template = (
                'netsh advfirewall firewall add rule name="MITM_BLOCK_IP_{ip}" '
                "dir=in action=block remoteip={ip}"
            )
            self._config.unblock_command_template = (
                'netsh advfirewall firewall delete rule name="MITM_BLOCK_IP_{ip}"'
            )
            # MAC blocking on Windows is not natively supported via netsh advfirewall
            self._config.block_mac_command_template = None 
            self._config.unblock_mac_command_template = None
        else:
            # Linux / macOS (iptables)
            self._config.block_command_template = "iptables -A INPUT -s {ip} -j DROP"
            self._config.unblock_command_template = "iptables -D INPUT -s {ip} -j DROP"
            
            # MAC blocking for Linux
            self._config.block_mac_command_template = "iptables -A INPUT -m mac --mac-source {mac} -j DROP"
            self._config.unblock_mac_command_template = "iptables -D INPUT -m mac --mac-source {mac} -j DROP"

    def handle_alert(
        self,
        ip: str,
        score: float,
        threat_level: str,
        details: List[str],
        mac: Optional[str] = None,
    ):
        """
        Main entry point — handle a high-risk IP detection.
        Implements staged escalation and safety checks.
        """
        # 1. Safety Check: Never block protected IPs
        if ip in self._protected_ips:
            logger.warning("SAFETY: Refusing to take action on protected IP %s (score: %.1f)", ip, score)
            self._passive_action(ip, score, threat_level, details, action="PROTECTED_BYPASS", mac=mac)
            return

        # 2. Response Mode Check (from Config)
        mode = self._config.response_mode
        if mode == 0: # MONITOR_ONLY
            logger.info("STAGED_RESPONSE: Monitor-only mode — alert logged for %s", ip)
            self._passive_action(ip, score, threat_level, details, action="MONITORED", mac=mac)
            return

        # 3. Determine Staged Action
        action = "NONE"
        
        if score >= self._config.block_score_threshold:
            if threat_level == "CRITICAL":
                action = "ISOLATE (DETECTION-ONLY)"
            else:
                action = "QUARANTINE (DETECTION-ONLY)"
        elif score >= 50.0:
            action = "OBSERVE"
        
        # ACTIVE BLOCKING DISABLED for Unified IDS Integration
        # We only log and alert; DecisionEngine handles the actual block.
        self._passive_action(ip, score, threat_level, details, action=f"{action} [REPORTED]", mac=mac)

    def _execute_safe_block(self, ip: str, duration: float, action: str, score: float, threat_level: str, details: List[str], mac: Optional[str] = None):
        """Executes a block with pre-connectivity validation and rollback."""
        
        # 1. Pre-block Connectivity Check
        if not self._verify_connectivity():
            logger.error("SAFETY_CHECK: Internet unreachable BEFORE block — aborting block on %s", ip)
            self._passive_action(ip, score, threat_level, details, action="BLOCK_ABORTED_NET_DOWN", mac=mac)
            return

        # 2. Perform Block (IP and MAC)
        success_ip = self._block_ip(ip, duration, score, threat_level)
        success_mac = False
        if mac and self._config.block_mac_command_template:
            success_mac = self._block_mac(mac, duration, ip)
        
        if success_ip or success_mac:
            # 3. Post-block Sanity Check (Rollback if we blocked ourselves/gateway)
            time.sleep(0.5)
            if not self._verify_connectivity():
                logger.critical("SAFETY_CHECK: Internet unreachable AFTER block on %s — ROLLING BACK", ip)
                if success_ip: self.force_unblock(ip)
                if success_mac and mac: self._unblock_mac(mac)
                self._passive_action(ip, score, threat_level, details, action="BLOCK_ROLLED_BACK", mac=mac)
            else:
                block_desc = f"{action} (IP{'+MAC' if success_mac else ''})"
                logger.info("STAGED_RESPONSE: Successfully %s %s for %.0fs", block_desc, ip, duration)
                self._passive_action(ip, score, threat_level, details, action=block_desc, blocked=True, mac=mac)
                
                if self._config.auto_arp_correction_enabled:
                    self._send_arp_correction(ip)
        else:
            self._passive_action(ip, score, threat_level, details, action="BLOCK_FAILED", mac=mac)

    def _verify_connectivity(self) -> bool:
        """Verifies internet connectivity using safety check IPs."""
        targets = self._config.safety_check_ips
        for target in targets:
            try:
                if os.name == 'nt':
                     cmd = ["ping", "-n", "1", "-w", "800", target]
                else:
                     cmd = ["ping", "-c", "1", "-W", "1", target]
                
                result = subprocess.run(cmd, capture_output=True, timeout=1.5)
                if result.returncode == 0:
                    return True
            except Exception:
                continue
        return False

    def _passive_action(self, ip: str, score: float, threat_level: str, details: List[str], action: str = "ALERT", blocked: bool = False, mac: Optional[str] = None):
        """Standardized passive action: logging, console output, and history recording."""
        alert = self._create_alert(ip, score, threat_level, details, mac=mac)
        alert.action_taken = action
        alert.blocked = blocked
        
        # Console Output
        print(alert.to_console())
        logger.info("RESPONSE: %s - %s", action, alert.to_json())
        
        # JSON Log
        self._log_alert_json(alert)
        self._alert_history.append(alert)

    def _create_alert(
        self,
        ip: str,
        score: float,
        threat_level: str,
        details: List[str],
        mac: Optional[str] = None,
    ) -> Alert:
        """Create a structured Alert object."""
        self._alert_counter += 1
        now = time.time()

        return Alert(
            alert_id=f"MITM-{self._alert_counter:06d}",
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)),
            timestamp_epoch=now,
            source_ip=ip,
            source_mac=mac,
            threat_level=threat_level,
            risk_score=score,
            detection_details=details,
            action_taken="PENDING",
            blocked=False,
        )

    def _block_ip(self, ip: str, duration: float, score: float, threat_level: str) -> bool:
        """
        Internal method to block an IP and manage the BlockRecord.
        """
        with self._lock:
            # Already blocked check
            if ip in self._active_blocks and self._active_blocks[ip].active:
                logger.info("IP %s already blocked — extending duration", ip)
                self._active_blocks[ip].unblock_at = time.time() + duration
                return True

            # Limit check
            active_count = sum(1 for b in self._active_blocks.values() if b.active)
            if active_count >= self._config.max_concurrent_blocks:
                logger.warning("Max concurrent blocks reached — cannot block %s", ip)
                return False

        # Execute
        cmd = self._config.block_command_template.format(ip=ip)
        if self._execute_firewall_cmd(cmd, "block", ip):
            now = time.time()
            record = BlockRecord(
                ip=ip,
                score=score,
                threat_level=threat_level,
                blocked_at=now,
                unblock_at=now + duration,
                reason=f"MITM {threat_level} score {score:.1f}",
            )
            with self._lock:
                self._active_blocks[ip] = record
            
            self._schedule_unblock(ip, delay=duration)
            return True
        return False

    def _block_mac(self, mac: str, duration: float, ip_hint: str = "") -> bool:
        """Internal method to block a MAC address."""
        if not self._config.block_mac_command_template:
            return False
            
        cmd = self._config.block_mac_command_template.format(mac=mac)
        if self._execute_firewall_cmd(cmd, "block_mac", f"{mac} ({ip_hint})"):
            # We don't track MAC blocks in _active_blocks yet for unblock,
            # but we can schedule a specific unblock timer
            timer = threading.Timer(duration, self._unblock_mac, args=[mac])
            timer.daemon = True
            timer.start()
            return True
        return False

    def _unblock_mac(self, mac: str):
        """Unblock a MAC address."""
        if not self._config.unblock_mac_command_template or not mac:
            return
        cmd = self._config.unblock_mac_command_template.format(mac=mac)
        if self._execute_firewall_cmd(cmd, "unblock_mac", mac):
            logger.info("🔓 UNBLOCKED MAC %s", mac)

    def _unblock_ip(self, ip: str):
        """Unblock IP when quarantine expires."""
        with self._lock:
            if ip not in self._active_blocks or not self._active_blocks[ip].active:
                return

            record = self._active_blocks[ip]
            if time.time() < record.unblock_at:
                # Re-schedule (was extended)
                remaining = record.unblock_at - time.time()
                self._schedule_unblock(ip, remaining)
                return
            
            record.active = False

        cmd = self._config.unblock_command_template.format(ip=ip)
        if self._execute_firewall_cmd(cmd, "unblock", ip):
            logger.info("🔓 UNBLOCKED IP %s", ip)

    def _schedule_unblock(self, ip: str, delay: float):
        """Schedule the auto-unblock timer."""
        timer = threading.Timer(delay, self._unblock_ip, args=[ip])
        timer.daemon = True
        timer.start()

    def _execute_firewall_cmd(self, cmd: str, action: str, ip: str) -> bool:
        """Safely execute system commands for firewall management."""
        try:
            # Privilege check (Linux)
            if self._os != "windows" and hasattr(os, 'geteuid') and os.geteuid() != 0:
                logger.error("Root required for firewall %s", action)
                return False

            # Admin check (Windows) — best effort
            if self._os == "windows":
                try:
                    import ctypes
                    if not ctypes.windll.shell32.IsUserAnAdmin():
                        logger.error("Admin required for netsh %s", action)
                        return False
                except Exception: pass

            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, errors="ignore", timeout=10)
            if result.returncode == 0:
                return True
            logger.error("Firewall %s failed for %s: %s", action, ip, result.stderr.strip())
            return False
        except Exception as e:
            logger.error("Firewall %s exception for %s: %s", action, ip, e)
            return False

    def _send_arp_correction(self, attacker_ip: str):
        """Sends corrective ARP broadcast (Placeholder)."""
        logger.info("ARP correction triggered for %s (Requires Scapy + Gateway MAC)", attacker_ip)

    def _log_alert_json(self, alert: Alert):
        """Persistent JSON and MongoDB logging."""
        # 1. JSON File Log
        try:
            with open(self._alert_log_file, "a") as f:
                f.write(json.dumps(alert.__dict__) + "\n")
        except Exception as e:
            logger.error("Alert log file write failed: %s", e)
            
        # 2. MongoDB Log
        if self._mongo_collection is not None:
            try:
                # Convert alert object to dict for MongoDB
                self._mongo_collection.insert_one(alert.__dict__)
            except Exception as e:
                logger.error("MongoDB alert insert failed: %s", e)

    def force_unblock(self, ip: str):
        """Administrative unblock override."""
        with self._lock:
            if ip in self._active_blocks:
                self._active_blocks[ip].unblock_at = 0
                self._unblock_ip(ip)

    def get_alert_history(self) -> List[Alert]:
        return list(self._alert_history)

    def get_active_blocks(self) -> Dict[str, BlockRecord]:
        with self._lock:
            return {ip: record for ip, record in self._active_blocks.items() if record.active}

    def add_protected_ip(self, ip: str):
        """Add an IP to the protected set (never blocked)."""
        with self._lock:
            self._protected_ips.add(ip)
            logger.info("IP %s is now PROTECTED from automated responses", ip)
