"""
Gateway Verifier Module
=======================
Active verification layer to confirm or deny suspicious gateway MAC changes.

When the ArpMonitor detects that the gateway's MAC has changed, this module
sends active ARP probes to the gateway to determine if the change is legitimate
(e.g., router reboot, firmware update) or an actual MITM attack.

This dramatically reduces false positives compared to passive-only detection.

Design:
  - Sends unicast ARP probes directly to the gateway IP
  - Compares response MAC to the claimed MAC
  - Implements retry logic and timeout
  - Cool-down period prevents probe storms
  - Thread-safe for concurrent verification requests
"""

import time
import logging
import threading
from dataclasses import dataclass
from typing import Optional, Dict

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

from mitm_config import GatewayVerifierConfig

logger = logging.getLogger("mitm.gateway_verifier")


@dataclass
class VerificationResult:
    """Result of a gateway MAC verification probe."""
    gateway_ip: str
    claimed_mac: str
    verified_mac: Optional[str]  # MAC from probe response, None if no response
    is_legitimate: bool  # True if claimed MAC matches verified MAC
    probe_count: int
    response_count: int
    timestamp: float
    details: str


class GatewayVerifier:
    """
    Performs active ARP probe verification of gateway MAC changes.

    When a MAC change is detected for a gateway IP, instead of immediately
    raising an alert, we send ARP probes directly to verify the current
    true MAC address. This handles:

    - Router reboots (MAC stays same after probe → legitimate)
    - Firmware updates (MAC may change → probe confirms new MAC)
    - MITM attacks (probe reveals real MAC differs from attacker's)
    - Mesh WiFi roaming (AP handoff → new MAC is legitimate)
    """

    def __init__(self, config: GatewayVerifierConfig, interface: str = None):
        self._config = config
        self._interface = interface
        self._lock = threading.Lock()

        # Track last verification time per IP to enforce cool-down
        self._last_verification: Dict[str, float] = {}

        # Cache of verified MACs per gateway IP
        self._verified_macs: Dict[str, str] = {}

        logger.info("GatewayVerifier initialized (interface=%s)", interface)

    def verify_gateway(
        self, gateway_ip: str, claimed_mac: str
    ) -> VerificationResult:
        """
        Actively verify if a gateway's claimed MAC is legitimate.

        Sends ARP probes to the gateway and compares the response MAC
        with the claimed MAC from the ARP table.

        Args:
            gateway_ip: IP address of the gateway to verify
            claimed_mac: The MAC address currently claimed for this IP

        Returns:
            VerificationResult with the outcome
        """
        now = time.time()

        # ── Cool-down Check ──
        with self._lock:
            last = self._last_verification.get(gateway_ip, 0)
            if (now - last) < self._config.verification_cooldown_seconds:
                logger.debug(
                    "Verification on cooldown for %s (%.1fs remaining)",
                    gateway_ip,
                    self._config.verification_cooldown_seconds - (now - last),
                )
                # Return cached result if available
                cached_mac = self._verified_macs.get(gateway_ip)
                return VerificationResult(
                    gateway_ip=gateway_ip,
                    claimed_mac=claimed_mac,
                    verified_mac=cached_mac,
                    is_legitimate=cached_mac and cached_mac.lower() == claimed_mac.lower(),
                    probe_count=0,
                    response_count=0,
                    timestamp=now,
                    details="Cooldown period — using cached verification",
                )
            self._last_verification[gateway_ip] = now

        # ── Grace Period ──
        # Wait briefly before probing to allow transient conditions to settle
        # (e.g., router finishing reboot sequence)
        logger.info(
            "Verifying gateway %s (claimed MAC: %s) — grace period %.1fs",
            gateway_ip,
            claimed_mac,
            self._config.verification_grace_period_seconds,
        )
        time.sleep(self._config.verification_grace_period_seconds)

        # ── Send ARP Probes ──
        response_macs = []
        for i in range(self._config.probe_count):
            mac = self._send_arp_probe(gateway_ip)
            if mac:
                response_macs.append(mac.lower())
            # Small delay between probes
            if i < self._config.probe_count - 1:
                time.sleep(0.3)

        # ── Analyze Responses ──
        if not response_macs:
            # No response — gateway may be down or unreachable
            result = VerificationResult(
                gateway_ip=gateway_ip,
                claimed_mac=claimed_mac,
                verified_mac=None,
                is_legitimate=False,
                probe_count=self._config.probe_count,
                response_count=0,
                timestamp=time.time(),
                details="No response to ARP probes — gateway unreachable or blocking",
            )
            logger.warning("Gateway %s did not respond to ARP probes", gateway_ip)
            return result

        # Count how many responses match the claimed MAC
        matching = sum(1 for m in response_macs if m == claimed_mac.lower())
        unique_macs = set(response_macs)

        if matching >= self._config.min_confirmations:
            # Claimed MAC confirmed by probes — legitimate change
            with self._lock:
                self._verified_macs[gateway_ip] = claimed_mac.lower()

            result = VerificationResult(
                gateway_ip=gateway_ip,
                claimed_mac=claimed_mac,
                verified_mac=claimed_mac,
                is_legitimate=True,
                probe_count=self._config.probe_count,
                response_count=len(response_macs),
                timestamp=time.time(),
                details=f"Verified: {matching}/{len(response_macs)} probes confirmed claimed MAC",
            )
            logger.info(
                "Gateway %s MAC verified as legitimate: %s", gateway_ip, claimed_mac
            )
            return result

        else:
            # Probe responses don't match claimed MAC — MITM likely!
            real_mac = max(set(response_macs), key=response_macs.count)
            result = VerificationResult(
                gateway_ip=gateway_ip,
                claimed_mac=claimed_mac,
                verified_mac=real_mac,
                is_legitimate=False,
                probe_count=self._config.probe_count,
                response_count=len(response_macs),
                timestamp=time.time(),
                details=(
                    f"MISMATCH: Claimed MAC {claimed_mac} but probes returned "
                    f"{unique_macs}. Real gateway MAC is likely {real_mac}"
                ),
            )
            logger.critical(
                "Gateway %s MAC MISMATCH! Claimed: %s, Actual: %s — MITM suspected!",
                gateway_ip,
                claimed_mac,
                real_mac,
            )
            return result

    def _send_arp_probe(self, target_ip: str) -> Optional[str]:
        """
        Send a single ARP request and return the response MAC.

        Uses Scapy's srp() for layer 2 send/receive.
        """
        try:
            # Construct ARP request
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1, pdst=target_ip
            )

            # Send and receive
            kwargs = {
                "timeout": self._config.probe_timeout_seconds,
                "verbose": 0,
            }
            if self._interface:
                kwargs["iface"] = self._interface

            answered, _ = srp(arp_request, **kwargs)

            if answered:
                # Return the source MAC from the first response
                response_mac = answered[0][1][ARP].hwsrc
                logger.debug(
                    "ARP probe to %s responded with MAC %s", target_ip, response_mac
                )
                return response_mac

        except PermissionError:
            logger.error(
                "Permission denied for ARP probe — run as root/admin"
            )
        except Exception as e:
            logger.error("ARP probe to %s failed: %s", target_ip, e)

        return None

    def get_verified_mac(self, gateway_ip: str) -> Optional[str]:
        """Get the last verified MAC for a gateway IP."""
        with self._lock:
            return self._verified_macs.get(gateway_ip)

    def set_initial_gateway(self, gateway_ip: str, mac: str):
        """
        Set the initial trusted gateway MAC (e.g., from system ARP cache).
        This establishes the baseline for change detection.
        """
        with self._lock:
            self._verified_macs[gateway_ip] = mac.lower()
            logger.info("Initial gateway set: %s → %s", gateway_ip, mac)
