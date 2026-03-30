"""
Risk Scoring Engine
===================
Multi-factor risk scoring system that aggregates signals from all
detection layers into a unified threat score per IP address.

Design Principles:
  - Each detection layer contributes weighted score components
  - Scores decay exponentially over time (no permanent flags)
  - Cool-down period prevents alert spam
  - Score capped to prevent runaway accumulation
  - Thread-safe for concurrent score updates
  - Supports score query by external IDS core system

Integration Point:
  The IDS core calls `report_suspicious_ip(ip, score)` to consume
  risk assessments from this module.
"""

import time
import json
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, Callable, List

from mitm_config import RiskScoreConfig

logger = logging.getLogger("mitm.risk_scoring")


@dataclass
class ScoreRecord:
    """Risk score tracking for a single IP address."""
    ip: str
    mac: Optional[str] = None  # Associated MAC address (if known)
    total_score: float = 0.0
    components: Dict[str, float] = field(default_factory=dict)
    last_updated: float = field(default_factory=time.time)
    last_alert_time: float = 0.0
    alert_count: int = 0
    peak_score: float = 0.0
    threat_level: str = "NONE"
    details: List[str] = field(default_factory=list)


class RiskScoringEngine:
    """
    Aggregates detection signals into per-IP risk scores.

    Score Categories:
      - NONE:     score < threshold_low (no concern)
      - LOW:      threshold_low ≤ score < threshold_medium
      - MEDIUM:   threshold_medium ≤ score < threshold_high
      - HIGH:     threshold_high ≤ score < threshold_critical
      - CRITICAL: score ≥ threshold_critical

    Score Lifecycle:
      1. Detection layers call add_score() with weighted components
      2. Scores decay over time via periodic decay_scores()
      3. When score crosses HIGH threshold, response engine is triggered
      4. Cool-down prevents multiple alerts for same IP in rapid succession
    """

    def __init__(
        self,
        config: RiskScoreConfig,
        alert_callback: Optional[Callable] = None,
    ):
        self._config = config
        self._lock = threading.Lock()

        # IP → ScoreRecord
        self._scores: Dict[str, ScoreRecord] = {}

        # Callback when score crosses HIGH threshold
        # Signature: alert_callback(ip: str, score: float, threat_level: str, details: list)
        self._alert_callback = alert_callback

        # For IDS integration: external consumers register here
        self._external_consumers: List[Callable] = []

        logger.info("RiskScoringEngine initialized")

    def add_score(
        self,
        ip: str,
        component: str,
        weight: float,
        detail: str = "",
        mac: Optional[str] = None,
    ):
        """
        Add a risk score component for an IP address.

        Args:
            ip: IP address to score
            component: Name of the detection layer (e.g., "gateway_mac_change")
            weight: Score weight for this component
            detail: Human-readable description
            mac: Optional MAC address associated with this event
        """
        now = time.time()

        with self._lock:
            # Get or create score record
            if ip not in self._scores:
                self._scores[ip] = ScoreRecord(ip=ip, mac=mac)

            record = self._scores[ip]
            
            # Update MAC if provided and not already set
            if mac and not record.mac:
                record.mac = mac

            # Add weighted component
            record.components[component] = weight
            
            # --- Apply Synergy / Internal Correlation ---
            # If multiple independent signals are present, boost the confidence
            base_total = sum(record.components.values())
            boosted_total = self._apply_synergy_boost(record, base_total)
            
            record.total_score = min(boosted_total, self._config.max_score)
            record.last_updated = now
            record.peak_score = max(record.peak_score, record.total_score)

            if detail:
                record.details.append(f"[{time.strftime('%H:%M:%S')}] {detail}")
                if len(record.details) > 20:
                    record.details = record.details[-20:]

            # Update threat level
            record.threat_level = self._calculate_threat_level(record.total_score)

            logger.info(
                "Score update: %s → %.1f (%s) [Raw: %.1f, Component: %s]",
                ip,
                record.total_score,
                record.threat_level,
                base_total,
                component,
            )

            # ── Check Alert Threshold ──
            if record.total_score >= self._config.threshold_high:
                self._check_and_alert(record, now)

    def _apply_synergy_boost(self, record: ScoreRecord, base_score: float) -> float:
        """
        Calculates a confidence boost if multiple detection signals are correlated.
        Example: ARP MAC Change + Latency Drift = High Confidence MITM.
        """
        synergy_units = 0
        comps = record.components.keys()
        
        # Scenario 1: ARP modification + Network performance drift
        if ("mac_change" in comps or "gateway_mac_change_unverified" in comps) and "latency_drift" in comps:
            synergy_units += 1
            
        # Scenario 2: Stealth spoofing + Behavioural volume anomaly
        if "stealth_spoof" in comps and "behaviour_anomaly" in comps:
            synergy_units += 1
            
        # Scenario 3: Gateway MAC change + Duplicate replies (Flood)
        if "gateway_mac_change_unverified" in comps and "arp_flood" in comps:
            synergy_units += 1

        # Scenario 4: Port scan + Gateway MAC change (Recon → Attack)
        if "port_scan" in comps and (
            "mac_change" in comps or "gateway_mac_change_unverified" in comps
        ):
            synergy_units += 1

        # Scenario 5: Port flood + DDoS indicator (Multi-vector attack)
        if "port_flood" in comps and "ddos_indicator" in comps:
            synergy_units += 1

        # Scenario 6: Sensitive port access + Suspicious external IP
        if "sensitive_port" in comps and "suspicious_external" in comps:
            synergy_units += 1

        if synergy_units > 0:
            multiplier = self._config.correlation_multiplier ** synergy_units
            boosted = base_score * multiplier
            logger.debug("Synergy BOOST applied to %s: %.1f -> %.1f (x%.2f)", 
                        record.ip, base_score, boosted, multiplier)
            return boosted
            
        return base_score

    def _calculate_threat_level(self, score: float) -> str:
        """Map a numeric score to a threat level string."""
        if score >= self._config.threshold_critical:
            return "CRITICAL"
        elif score >= self._config.threshold_high:
            return "HIGH"
        elif score >= self._config.threshold_medium:
            return "MEDIUM"
        elif score >= self._config.threshold_low:
            return "LOW"
        return "NONE"

    def _check_and_alert(self, record: ScoreRecord, now: float):
        """
        Check cool-down and trigger alert if appropriate.

        Cool-down prevents alert flooding for the same IP.
        """
        # Cool-down check
        if (now - record.last_alert_time) < self._config.alert_cooldown_seconds:
            return  # Still in cool-down

        record.last_alert_time = now
        record.alert_count += 1

        logger.critical(
            "🚨 ALERT: IP %s reached %s level (score: %.1f, alerts: %d)",
            record.ip,
            record.threat_level,
            record.total_score,
            record.alert_count,
        )

        # Trigger callback (usually the ResponseEngine)
        if self._alert_callback:
            try:
                self._alert_callback(
                    record.ip,
                    record.total_score,
                    record.threat_level,
                    list(record.details),
                    mac=record.mac,
                )
            except Exception as e:
                logger.error("Alert callback failed: %s", e)

        # Notify external consumers (IDS integration)
        for consumer in self._external_consumers:
            try:
                # V60 Update: Pass all parameters to support unified IDS reporting
                consumer(
                    record.ip,
                    record.total_score,
                    record.threat_level,
                    list(record.details),
                    mac=record.mac
                )
            except Exception as e:
                logger.error("External consumer notification failed: %s", e)

    def decay_scores(self):
        """
        Apply exponential decay to all scores.

        Should be called periodically (e.g., every decay_interval_seconds).
        This ensures that old events don't permanently flag IPs — scores
        gradually return to zero if no new events occur.
        """
        with self._lock:
            ips_to_remove = []
            for ip, record in self._scores.items():
                # Apply decay to each component
                for component in list(record.components.keys()):
                    record.components[component] *= self._config.decay_factor
                    if record.components[component] < 0.5:
                        record.components.pop(component, None)

                # Recalculate total
                record.total_score = min(
                    sum(record.components.values()),
                    self._config.max_score,
                )
                record.threat_level = self._calculate_threat_level(record.total_score)

                # Remove zeroed-out records
                if record.total_score < 0.5 and not record.components:
                    ips_to_remove.append(ip)

            for ip in ips_to_remove:
                self._scores.pop(ip, None)

            if ips_to_remove:
                logger.debug("Cleaned %d zeroed score records", len(ips_to_remove))

    # ─────────────────────────────────────────────
    # Public API / IDS Integration
    # ─────────────────────────────────────────────

    def get_score(self, ip: str) -> Optional[ScoreRecord]:
        """Get the current risk score record for an IP."""
        with self._lock:
            return self._scores.get(ip)

    def get_all_scores(self) -> Dict[str, ScoreRecord]:
        """Get a copy of all score records."""
        with self._lock:
            return dict(self._scores)

    def get_high_risk_ips(self) -> List[ScoreRecord]:
        """Get all IPs at HIGH or CRITICAL threat level."""
        with self._lock:
            return [
                record
                for record in self._scores.values()
                if record.threat_level in ("HIGH", "CRITICAL")
            ]

    def register_consumer(self, callback: Callable):
        """
        Register an external consumer for risk score alerts.

        This is the integration point for the IDS core system.
        The callback signature should be: callback(ip: str, score: float)
        """
        self._external_consumers.append(callback)
        logger.info("Registered external consumer: %s", callback.__name__)

    def export_scores_json(self) -> str:
        """Export all current scores as JSON for logging/reporting."""
        with self._lock:
            data = {}
            for ip, record in self._scores.items():
                data[ip] = {
                    "score": round(record.total_score, 1),
                    "threat_level": record.threat_level,
                    "peak_score": round(record.peak_score, 1),
                    "alert_count": record.alert_count,
                    "components": {
                        k: round(v, 1)
                        for k, v in record.components.items()
                    },
                    "details": record.details[-5:],  # Last 5 details
                    "last_updated": time.strftime(
                        "%Y-%m-%dT%H:%M:%S",
                        time.localtime(record.last_updated),
                    ),
                }
            return json.dumps(data, indent=2)
