"""
output_schema.py — Strict JSON Output Schema for Cyber Defense AI V3
=====================================================================
10-Layer Flow-Based Architecture with Buffered Stream Processing.

Fields:
  - flow_id:        5-tuple flow identifier
  - attack_type:    BENIGN | DDoS | MITM | AI_ATTACK | STEALTH_ATTACK | HYBRID_ATTACK | UNKNOWN_ATTACK
  - confidence:     0.0–1.0
  - risk_level:     LOW | MEDIUM | HIGH | CRITICAL
  - action:         ALLOW | MONITOR | THROTTLE | BLOCK | ISOLATE
  - buffer_stats:   Flow buffer aggregation metrics
  - timing:         Per-layer latency in milliseconds (10 layers)
  - anomaly_score:  0.0–1.0
  - is_zero_day:    boolean
  - optimization_applied: List of optimizations used
  - reason:         Human-readable detection explanation
"""

import json
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

VALID_ATTACK_TYPES = frozenset({
    "BENIGN", "DDoS", "MITM", "AI_ATTACK",
    "STEALTH_ATTACK", "HYBRID_ATTACK", "UNKNOWN_ATTACK"
})

VALID_RISK_LEVELS = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})

VALID_ACTIONS = frozenset({
    "ALLOW", "MONITOR", "THROTTLE", "BLOCK", "ISOLATE"
})

# Legacy → new mapping (backward compat with DecisionEngine V72)
LEGACY_ATTACK_MAP = {
    "Normal":          "BENIGN",
    "DoS":             "DDoS",
    "DDoS":            "DDoS",
    "MITM":            "MITM",
    "Scan":            "STEALTH_ATTACK",
    "WAF_Injection":   "AI_ATTACK",
    "Slowloris":       "DDoS",
    "Distributed_SYN": "DDoS",
    "Anomaly":         "UNKNOWN_ATTACK",
}

LEGACY_DECISION_MAP = {
    "allow":    "ALLOW",
    "alert":    "MONITOR",
    "monitor":  "MONITOR",
    "throttle": "THROTTLE",
    "block":    "BLOCK",
    "isolate":  "ISOLATE",
}


# ─────────────────────────────────────────────
# Timing Data (10 Layers)
# ─────────────────────────────────────────────

@dataclass
class PipelineTiming:
    """Per-layer latency measurements in milliseconds (10-layer architecture)."""
    # Layer 1: Flow Aggregation (Buffer)
    capture_time_ms: float = 0.0
    # Layer 2: Feature Extraction
    feature_time_ms: float = 0.0
    # Layer 3: Behavioral Analysis
    behavior_time_ms: float = 0.0
    # Layer 4: ML Ensemble
    ml_time_ms: float = 0.0
    # Layer 5: AI Attack Defense
    ai_defense_time_ms: float = 0.0
    # Layer 6: Threat Intelligence
    intelligence_time_ms: float = 0.0
    # Layer 7: Correlation
    correlation_time_ms: float = 0.0
    # Layer 8: Zero-Day Detection
    zero_day_time_ms: float = 0.0
    # Layer 9: Decision
    decision_time_ms: float = 0.0
    # Layer 10: Response
    response_time_ms: float = 0.0

    @property
    def total_detection_time_ms(self) -> float:
        """Layers 1-9 (everything except response)."""
        return round(
            self.capture_time_ms + self.feature_time_ms +
            self.behavior_time_ms + self.ml_time_ms +
            self.ai_defense_time_ms + self.intelligence_time_ms +
            self.correlation_time_ms + self.zero_day_time_ms +
            self.decision_time_ms, 4
        )

    @property
    def total_response_time_ms(self) -> float:
        """Layers 1-10 (full pipeline)."""
        return round(self.total_detection_time_ms + self.response_time_ms, 4)

    def to_dict(self) -> dict:
        return {
            "capture_time_ms": round(self.capture_time_ms, 4),
            "feature_time_ms": round(self.feature_time_ms, 4),
            "behavior_time_ms": round(self.behavior_time_ms, 4),
            "ml_time_ms": round(self.ml_time_ms, 4),
            "ai_defense_time_ms": round(self.ai_defense_time_ms, 4),
            "intelligence_time_ms": round(self.intelligence_time_ms, 4),
            "correlation_time_ms": round(self.correlation_time_ms, 4),
            "zero_day_time_ms": round(self.zero_day_time_ms, 4),
            "decision_time_ms": round(self.decision_time_ms, 4),
            "response_time_ms": round(self.response_time_ms, 4),
            "total_detection_time_ms": self.total_detection_time_ms,
            "total_response_time_ms": self.total_response_time_ms,
        }


# ─────────────────────────────────────────────
# Buffer Stats
# ─────────────────────────────────────────────

@dataclass
class BufferStatsOutput:
    """Flow buffer aggregation metrics for output schema."""
    packet_count: int = 0
    total_bytes: int = 0
    duration_sec: float = 0.0
    packet_rate: float = 0.0
    byte_rate: float = 0.0
    entropy: float = 0.0
    avg_iat: float = 0.0
    burst_count: int = 0

    def to_dict(self) -> dict:
        return {
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "duration_sec": round(self.duration_sec, 4),
            "packet_rate": round(self.packet_rate, 2),
            "byte_rate": round(self.byte_rate, 2),
            "entropy": round(self.entropy, 4),
            "avg_iat": round(self.avg_iat, 6),
            "burst_count": self.burst_count,
        }


# ─────────────────────────────────────────────
# Pipeline Result (10-Layer)
# ─────────────────────────────────────────────

@dataclass
class PipelineResult:
    """
    Strict JSON output for a single flow through the 10-layer pipeline.
    All fields are validated on construction via build_result().
    """
    # Core output (strict schema)
    flow_id: str = ""
    attack_type: str = "BENIGN"
    confidence: float = 0.0
    risk_level: str = "LOW"
    action: str = "ALLOW"
    buffer_stats: BufferStatsOutput = field(default_factory=BufferStatsOutput)
    timing: PipelineTiming = field(default_factory=PipelineTiming)
    anomaly_score: float = 0.0
    is_zero_day: bool = False
    optimization_applied: List[str] = field(default_factory=list)
    reason: str = ""

    # Extended fields (dashboard / diagnostics)
    source_ip: str = ""
    dest_ip: str = ""
    pps: float = 0.0
    protocol: str = ""
    sub_attack_type: str = ""
    ml_scores: Dict[str, float] = field(default_factory=dict)
    correlation_id: str = ""
    threat_intel_hits: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Produce the strict JSON output (core fields only)."""
        return {
            "flow_id": self.flow_id,
            "attack_type": self.attack_type,
            "confidence": round(self.confidence, 4),
            "risk_level": self.risk_level,
            "action": self.action,
            "buffer_stats": self.buffer_stats.to_dict(),
            "timing": self.timing.to_dict(),
            "anomaly_score": round(self.anomaly_score, 4),
            "is_zero_day": self.is_zero_day,
            "optimization_applied": self.optimization_applied,
            "reason": self.reason,
        }

    def to_extended_dict(self) -> dict:
        """Full output including extended diagnostic fields."""
        base = self.to_dict()
        base.update({
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "pps": round(self.pps, 2),
            "protocol": self.protocol,
            "sub_attack_type": self.sub_attack_type,
            "ml_scores": {k: round(v, 4) for k, v in self.ml_scores.items()},
            "correlation_id": self.correlation_id,
            "threat_intel_hits": self.threat_intel_hits,
        })
        return base

    def to_json(self, extended: bool = False) -> str:
        """Serialize to JSON string."""
        d = self.to_extended_dict() if extended else self.to_dict()
        return json.dumps(d, indent=2)


# ─────────────────────────────────────────────
# Builder / Validator
# ─────────────────────────────────────────────

def risk_level_from_score(score: float) -> str:
    """Map a 0.0–1.0 risk score to a risk level."""
    if score >= 0.85:
        return "CRITICAL"
    elif score >= 0.6:
        return "HIGH"
    elif score >= 0.3:
        return "MEDIUM"
    return "LOW"


def action_from_risk(risk_level: str, is_zero_day: bool = False) -> str:
    """Default action mapping from risk level."""
    if risk_level == "CRITICAL":
        return "ISOLATE" if is_zero_day else "BLOCK"
    elif risk_level == "HIGH":
        return "BLOCK"
    elif risk_level == "MEDIUM":
        return "THROTTLE"
    elif risk_level == "LOW":
        return "MONITOR"
    return "ALLOW"


def normalize_attack_type(raw_type: str) -> str:
    """Normalize a raw attack type to the valid enum."""
    upper = raw_type.upper().strip()
    if upper in VALID_ATTACK_TYPES:
        return upper
    return LEGACY_ATTACK_MAP.get(raw_type, "UNKNOWN_ATTACK")


def normalize_action(raw_action: str) -> str:
    """Normalize a raw action to the valid enum."""
    lower = raw_action.lower().strip()
    mapped = LEGACY_DECISION_MAP.get(lower, raw_action.upper())
    if mapped in VALID_ACTIONS:
        return mapped
    return "MONITOR"


def build_result(
    attack_type: str,
    confidence: float,
    risk_score: float,
    action: str,
    timing: PipelineTiming,
    anomaly_score: float = 0.0,
    is_zero_day: bool = False,
    reason: str = "",
    flow_id: str = "",
    buffer_stats: Optional[BufferStatsOutput] = None,
    source_ip: str = "",
    dest_ip: str = "",
    pps: float = 0.0,
    protocol: str = "",
    sub_attack_type: str = "",
    ml_scores: Optional[Dict[str, float]] = None,
    correlation_id: str = "",
    threat_intel_hits: Optional[List[str]] = None,
    optimization_applied: Optional[List[str]] = None,
) -> PipelineResult:
    """
    Build and validate a PipelineResult.

    Normalizes attack types and actions, clamps scores to valid ranges,
    and computes risk_level from risk_score.
    """
    # Normalize enums
    norm_attack = normalize_attack_type(attack_type)
    norm_action = normalize_action(action)

    # Clamp scores
    confidence = max(0.0, min(1.0, confidence))
    risk_score = max(0.0, min(1.0, risk_score))
    anomaly_score = max(0.0, min(1.0, anomaly_score))

    # Derive risk_level
    risk_level = risk_level_from_score(risk_score)

    # If action wasn't explicitly set, derive from risk
    if norm_action == "ALLOW" and risk_level != "LOW" and norm_attack != "BENIGN":
        norm_action = action_from_risk(risk_level, is_zero_day)

    # Generate flow_id if not provided
    if not flow_id and source_ip and dest_ip:
        flow_id = f"{source_ip} \u2192 {dest_ip}"

    return PipelineResult(
        flow_id=flow_id,
        attack_type=norm_attack,
        confidence=confidence,
        risk_level=risk_level,
        action=norm_action,
        buffer_stats=buffer_stats or BufferStatsOutput(),
        timing=timing,
        anomaly_score=anomaly_score,
        is_zero_day=is_zero_day,
        reason=reason,
        optimization_applied=optimization_applied or [],
        source_ip=source_ip,
        dest_ip=dest_ip,
        pps=pps,
        protocol=protocol,
        sub_attack_type=sub_attack_type or attack_type,
        ml_scores=ml_scores or {},
        correlation_id=correlation_id,
        threat_intel_hits=threat_intel_hits or [],
    )


# ─────────────────────────────────────────────
# Stage Timer Context Manager
# ─────────────────────────────────────────────

class StageTimer:
    """
    High-precision timer for measuring individual pipeline layer latency.

    Usage:
        timing = PipelineTiming()
        with StageTimer() as t:
            do_capture()
        timing.capture_time_ms = t.elapsed_ms
    """

    def __init__(self):
        self._start: float = 0.0
        self._end: float = 0.0

    def __enter__(self):
        self._start = time.perf_counter_ns()
        return self

    def __exit__(self, *args):
        self._end = time.perf_counter_ns()

    @property
    def elapsed_ms(self) -> float:
        """Elapsed time in milliseconds (nanosecond precision)."""
        return (self._end - self._start) / 1_000_000

    @property
    def elapsed_us(self) -> float:
        """Elapsed time in microseconds."""
        return (self._end - self._start) / 1_000
