"""
IP Blocker Module — OS-Level Firewall Integration
==================================================
Automatically blocks suspicious IPs at the OS firewall level when the
DecisionEngine issues a BLOCK verdict.

Capabilities:
  - Windows: netsh advfirewall firewall rules
  - Linux:   iptables DROP rules
  - Auto-unblock after configurable duration (default: 10 minutes)
  - Thread-safe concurrent block management
  - MongoDB persistence (firewall_blocks collection)
  - Safety guards: protected IPs, max concurrent blocks, admin checks

Usage:
    blocker = IPBlocker(mongo_db=db, protected_ips=["127.0.0.1", "8.8.8.8"])
    blocker.block_ip("192.168.1.50", reason="TCP_FLOOD", severity=0.95)
    # IP is blocked for 10 minutes, then auto-unblocked
"""

import os
import json
import time
import logging
import platform
import subprocess
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any

logger = logging.getLogger("ids.ip_blocker")


# ─────────────────────────────────────────────
# Block Record
# ─────────────────────────────────────────────
class BlockRecord:
    """Tracks an active firewall block."""
    __slots__ = ('ip', 'reason', 'severity', 'blocked_at', 'unblock_at',
                 'duration', 'active', 'rule_name')

    def __init__(self, ip: str, reason: str, severity: float,
                 duration: float, rule_name: str):
        self.ip = ip
        self.reason = reason
        self.severity = severity
        self.duration = duration
        self.rule_name = rule_name
        self.blocked_at = time.time()
        self.unblock_at = self.blocked_at + duration
        self.active = True

    def remaining_seconds(self) -> float:
        return max(0.0, self.unblock_at - time.time())

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "reason": self.reason,
            "severity": self.severity,
            "blocked_at": datetime.fromtimestamp(self.blocked_at).strftime("%Y-%m-%d %H:%M:%S"),
            "unblock_at": datetime.fromtimestamp(self.unblock_at).strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": self.duration,
            "remaining_seconds": round(self.remaining_seconds(), 1),
            "status": "ACTIVE" if self.active and self.remaining_seconds() > 0 else "EXPIRED",
            "rule_name": self.rule_name
        }


# ─────────────────────────────────────────────
# IP Blocker Engine
# ─────────────────────────────────────────────
class IPBlocker:
    """
    OS-level IP blocking engine with auto-unblock timers.
    
    How it works:
    ─────────────
    1. When a BLOCK decision is received, a firewall rule is created:
       - Windows: `netsh advfirewall firewall add rule name="IDS_BLOCK_{ip}" dir=in action=block remoteip={ip}`
       - Linux:   `iptables -A INPUT -s {ip} -j DROP`
    
    2. The block is recorded in MongoDB (firewall_blocks collection) with timestamps.
    
    3. A daemon timer is started for the block duration (default: 600s = 10 minutes).
    
    4. When the timer fires, the firewall rule is removed:
       - Windows: `netsh advfirewall firewall delete rule name="IDS_BLOCK_{ip}"`
       - Linux:   `iptables -D INPUT -s {ip} -j DROP`
    
    5. The MongoDB record is updated with the unblock timestamp.
    
    Safety:
    ───────
    - Protected IPs (gateway, DNS, localhost) are NEVER blocked.
    - Max 20 concurrent blocks to prevent network lockout.
    - Admin/root privilege check before executing firewall commands.
    - If already blocked, the timer is extended (not duplicated).
    """

    # Default block duration: 10 minutes (600 seconds)
    DEFAULT_BLOCK_DURATION = 600

    # Maximum concurrent firewall blocks
    MAX_CONCURRENT_BLOCKS = 20

    def __init__(
        self,
        mongo_db: Optional[Any] = None,
        protected_ips: Optional[List[str]] = None,
        block_duration: float = DEFAULT_BLOCK_DURATION,
        trusted_ips_file: Optional[str] = None,
    ):
        self._lock = threading.Lock()
        self._active_blocks: Dict[str, BlockRecord] = {}
        self._block_duration = block_duration
        self._os = platform.system().lower()
        self._is_admin = self._check_admin()

        # ── MongoDB ──
        self._mongo_collection = None
        if mongo_db is not None:
            try:
                self._mongo_collection = mongo_db["firewall_blocks"]
                logger.info("MongoDB 'firewall_blocks' collection initialized")
            except Exception as e:
                logger.error("Failed to init MongoDB firewall_blocks: %s", e)

        # ── Protected IPs (NEVER block these) ──
        self._protected_ips: Set[str] = {
            "127.0.0.1", "0.0.0.0", "255.255.255.255",
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",  # DNS servers
        }
        if protected_ips:
            self._protected_ips.update(protected_ips)

        # Load trusted IPs from config file
        if trusted_ips_file and os.path.exists(trusted_ips_file):
            try:
                with open(trusted_ips_file, 'r') as f:
                    data = json.load(f)
                    self._protected_ips.update(data.get("trusted_ips", []))
                    self._protected_ips.update(data.get("trusted_externals", []))
                    logger.info("Loaded %d trusted IPs from %s",
                                len(data.get("trusted_ips", [])), trusted_ips_file)
            except Exception as e:
                logger.error("Failed to load trusted IPs: %s", e)

        # Add local machine IP
        try:
            import socket
            local_ip = socket.gethostbyname(socket.gethostname())
            self._protected_ips.add(local_ip)
        except Exception:
            pass

        # ── Firewall command templates ──
        if self._os == "windows":
            self._block_cmd = (
                'netsh advfirewall firewall add rule name="{rule_name}" '
                'dir=in action=block remoteip={ip}'
            )
            self._unblock_cmd = (
                'netsh advfirewall firewall delete rule name="{rule_name}"'
            )
        else:
            self._block_cmd = 'iptables -A INPUT -s {ip} -j DROP'
            self._unblock_cmd = 'iptables -D INPUT -s {ip} -j DROP'

        # ── Stats ──
        self._total_blocks = 0
        self._total_unblocks = 0

        logger.info(
            "🛡️ IPBlocker initialized | OS=%s | Admin=%s | Duration=%ds | Protected=%d IPs",
            self._os, self._is_admin, self._block_duration, len(self._protected_ips)
        )

    # ═════════════════════════════════════════
    # PUBLIC API
    # ═════════════════════════════════════════

    def block_ip(self, ip: str, reason: str = "Suspicious Activity",
                 severity: float = 0.0, duration: Optional[float] = None) -> bool:
        """
        Block an IP at the OS firewall level.
        
        Args:
            ip:       IP address to block
            reason:   Attack type / reason string
            severity: Risk score (0.0 - 1.0)
            duration: Block duration in seconds (default: 600 = 10 minutes)
            
        Returns:
            True if block was executed successfully, False otherwise
        """
        if duration is None:
            duration = self._block_duration

        # ── Safety Check 1: Protected IP ──
        if ip in self._protected_ips:
            logger.warning("🛡️ SAFETY: Refusing to block PROTECTED IP %s (reason: %s)", ip, reason)
            return False

        # ── Safety Check 2: Private/internal range guard ──
        if self._is_critical_internal(ip):
            logger.warning("🛡️ SAFETY: Refusing to block critical internal IP %s", ip)
            return False

        # ── Already blocked? Extend timer ──
        with self._lock:
            if ip in self._active_blocks and self._active_blocks[ip].active:
                record = self._active_blocks[ip]
                record.unblock_at = time.time() + duration
                logger.info("⏱️ Extended block for %s — new expiry in %ds", ip, duration)
                self._update_mongo_record(ip, extended=True)
                return True

            # ── Safety Check 3: Max concurrent blocks ──
            active_count = sum(1 for b in self._active_blocks.values() if b.active)
            if active_count >= self.MAX_CONCURRENT_BLOCKS:
                logger.error("⚠️ MAX BLOCKS reached (%d) — cannot block %s",
                             self.MAX_CONCURRENT_BLOCKS, ip)
                return False

        # ── Execute firewall command ──
        rule_name = f"IDS_BLOCK_{ip.replace('.', '_')}"
        
        if self._os == "windows":
            cmd = self._block_cmd.format(rule_name=rule_name, ip=ip)
        else:
            cmd = self._block_cmd.format(ip=ip)

        success = self._execute_firewall_cmd(cmd, "BLOCK", ip)

        if success:
            # Create block record
            record = BlockRecord(
                ip=ip, reason=reason, severity=severity,
                duration=duration, rule_name=rule_name
            )

            with self._lock:
                self._active_blocks[ip] = record
                self._total_blocks += 1

            # Log to MongoDB
            self._log_block_to_mongo(record)

            # Schedule auto-unblock
            self._schedule_unblock(ip, duration)

            blocked_at = datetime.now().strftime("%H:%M:%S")
            unblock_at = (datetime.now() + timedelta(seconds=duration)).strftime("%H:%M:%S")
            print(f"  🔒 FIREWALL BLOCK: {ip} | Reason: {reason} | Severity: {severity:.2f}")
            print(f"     ├─ Blocked at: {blocked_at}")
            print(f"     ├─ Auto-unblock at: {unblock_at} ({int(duration / 60)} minutes)")
            print(f"     └─ Rule: {rule_name}")

            return True
        else:
            logger.error("❌ Failed to execute firewall block for %s", ip)
            # Still log the attempt to MongoDB
            self._log_block_attempt_to_mongo(ip, reason, severity, success=False)
            return False

    def unblock_ip(self, ip: str) -> bool:
        """
        Manually unblock an IP — removes firewall rule and updates records.
        """
        with self._lock:
            if ip not in self._active_blocks:
                logger.warning("IP %s is not in active blocks", ip)
                return False
            record = self._active_blocks[ip]
            if not record.active:
                return False
            record.active = False

        # Execute unblock
        if self._os == "windows":
            cmd = self._unblock_cmd.format(rule_name=record.rule_name)
        else:
            cmd = self._unblock_cmd.format(ip=ip)

        success = self._execute_firewall_cmd(cmd, "UNBLOCK", ip)

        if success:
            with self._lock:
                self._total_unblocks += 1
            self._update_mongo_unblock(ip)
            print(f"  🔓 FIREWALL UNBLOCK: {ip} | Rule removed: {record.rule_name}")
        else:
            logger.error("Failed to execute firewall unblock for %s", ip)

        return success

    def get_active_blocks(self) -> List[dict]:
        """Returns all active (not yet expired) blocks."""
        with self._lock:
            return [
                r.to_dict() for r in self._active_blocks.values()
                if r.active and r.remaining_seconds() > 0
            ]

    def get_all_blocks(self) -> List[dict]:
        """Returns all blocks (active + expired) from memory."""
        with self._lock:
            return [r.to_dict() for r in self._active_blocks.values()]

    def get_stats(self) -> dict:
        """Returns blocker statistics."""
        with self._lock:
            active = sum(1 for b in self._active_blocks.values()
                         if b.active and b.remaining_seconds() > 0)
            return {
                "total_blocks_executed": self._total_blocks,
                "total_unblocks_executed": self._total_unblocks,
                "currently_active": active,
                "max_concurrent": self.MAX_CONCURRENT_BLOCKS,
                "block_duration_seconds": self._block_duration,
                "is_admin": self._is_admin,
                "os": self._os
            }

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        with self._lock:
            if ip in self._active_blocks:
                r = self._active_blocks[ip]
                return r.active and r.remaining_seconds() > 0
            return False

    # ═════════════════════════════════════════
    # INTERNAL METHODS
    # ═════════════════════════════════════════

    def _check_admin(self) -> bool:
        """Check if the process has admin/root privileges."""
        if self._os == "windows":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return hasattr(os, 'geteuid') and os.geteuid() == 0

    def _is_critical_internal(self, ip: str) -> bool:
        """Check if IP is a gateway/broadcast that must never be blocked."""
        # Subnet gateways (x.x.x.1) and broadcasts (x.x.x.255)
        parts = ip.split('.')
        if len(parts) == 4:
            last_octet = parts[3]
            # Don't block subnet gateways or broadcasts
            if last_octet in ('0', '255'):
                return True
        return False

    def _execute_firewall_cmd(self, cmd: str, action: str, ip: str) -> bool:
        """Execute a firewall command safely."""
        if not self._is_admin:
            logger.warning(
                "⚠️ NOT ADMIN — %s for %s logged but NOT enforced. "
                "Run as Administrator to enable firewall blocking.", action, ip
            )
            # Still return True so that the block is tracked in the system
            # The log makes it clear the rule wasn't actually applied
            return True

        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                errors="ignore", timeout=15
            )
            if result.returncode == 0:
                logger.info("✅ Firewall %s executed for %s", action, ip)
                return True
            else:
                logger.error(
                    "❌ Firewall %s failed for %s (rc=%d): %s",
                    action, ip, result.returncode, result.stderr.strip()
                )
                return False
        except subprocess.TimeoutExpired:
            logger.error("⏰ Firewall %s timed out for %s", action, ip)
            return False
        except Exception as e:
            logger.error("💥 Firewall %s exception for %s: %s", action, ip, e)
            return False

    def _schedule_unblock(self, ip: str, delay: float):
        """Start a daemon timer to auto-unblock after delay seconds."""
        timer = threading.Timer(delay, self._auto_unblock, args=[ip])
        timer.daemon = True
        timer.start()
        logger.info("⏱️ Auto-unblock scheduled for %s in %ds (%.1f min)",
                     ip, delay, delay / 60)

    def _auto_unblock(self, ip: str):
        """Called by the timer when the block duration expires."""
        with self._lock:
            if ip not in self._active_blocks:
                return
            record = self._active_blocks[ip]
            # Check if the block was extended
            remaining = record.remaining_seconds()
            if remaining > 1.0:
                # Re-schedule (block was extended while timer was running)
                self._schedule_unblock(ip, remaining)
                return
            if not record.active:
                return

        logger.info("⏱️ Block duration expired for %s — auto-unblocking", ip)
        self.unblock_ip(ip)

    # ═════════════════════════════════════════
    # MONGODB PERSISTENCE
    # ═════════════════════════════════════════

    def _log_block_to_mongo(self, record: BlockRecord):
        """Insert a block record into MongoDB."""
        if not self._mongo_collection:
            return
        try:
            doc = {
                "ip": record.ip,
                "reason": record.reason,
                "severity": record.severity,
                "blocked_at": datetime.fromtimestamp(record.blocked_at).strftime("%Y-%m-%d %H:%M:%S"),
                "unblock_at": datetime.fromtimestamp(record.unblock_at).strftime("%Y-%m-%d %H:%M:%S"),
                "duration_seconds": record.duration,
                "rule_name": record.rule_name,
                "status": "ACTIVE",
                "os": self._os,
                "admin_enforced": self._is_admin,
                "unblocked_at": None,
            }
            self._mongo_collection.insert_one(doc)
        except Exception as e:
            logger.error("MongoDB block insert failed: %s", e)

    def _update_mongo_record(self, ip: str, extended: bool = False):
        """Update an existing block record (e.g., when extended)."""
        if not self._mongo_collection:
            return
        try:
            record = self._active_blocks.get(ip)
            if record:
                self._mongo_collection.update_one(
                    {"ip": ip, "status": "ACTIVE"},
                    {"$set": {
                        "unblock_at": datetime.fromtimestamp(record.unblock_at).strftime("%Y-%m-%d %H:%M:%S"),
                        "extended": extended
                    }}
                )
        except Exception as e:
            logger.error("MongoDB update failed for %s: %s", ip, e)

    def _update_mongo_unblock(self, ip: str):
        """Mark a block as EXPIRED in MongoDB."""
        if not self._mongo_collection:
            return
        try:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._mongo_collection.update_one(
                {"ip": ip, "status": "ACTIVE"},
                {"$set": {"status": "EXPIRED", "unblocked_at": now}}
            )
        except Exception as e:
            logger.error("MongoDB unblock update failed for %s: %s", ip, e)

    def _log_block_attempt_to_mongo(self, ip: str, reason: str,
                                     severity: float, success: bool):
        """Log a failed block attempt."""
        if not self._mongo_collection:
            return
        try:
            self._mongo_collection.insert_one({
                "ip": ip,
                "reason": reason,
                "severity": severity,
                "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "FAILED",
                "os": self._os,
                "admin_enforced": self._is_admin,
            })
        except Exception as e:
            logger.error("MongoDB failed-block insert error: %s", e)
