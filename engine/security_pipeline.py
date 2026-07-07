"""
security_pipeline.py — 10-Layer Flow-Based Cyber Defense AI Pipeline V3
=========================================================================
Multi-layer defense pipeline with buffered stream processing.

10 Layers:
  Layer 1:  Flow Aggregation (Buffer)     → capture_time_ms
  Layer 2:  Feature Extraction            → feature_time_ms
  Layer 3:  Behavioral Analysis           → behavior_time_ms
  Layer 4:  ML Ensemble                   → ml_time_ms
  Layer 5:  AI Attack Defense             → ai_defense_time_ms
  Layer 6:  Threat Intelligence (Cached)  → intelligence_time_ms
  Layer 7:  Correlation Engine            → correlation_time_ms
  Layer 8:  Zero-Day Detection            → zero_day_time_ms
  Layer 9:  Decision Engine               → decision_time_ms
  Layer 10: Response Engine               → response_time_ms

Optimizations carried forward from V2:
  - Fast-path for trusted/benign flows
  - LRU-cached threat intelligence (5s TTL)
  - High-confidence ML skip
  - Singleton empty results
  - Per-IP trust scoring via flow buffer
"""

import os
import sys
import time
import logging
import threading
from typing import Dict, List, Optional, Any

# Ensure imports work from any launch point
_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _root)
sys.path.insert(0, os.path.join(_root, 'DDoS-engine'))
sys.path.insert(0, os.path.join(_root, 'MITM-engine'))
sys.path.insert(0, os.path.join(_root, 'model'))

from output_schema import (
    PipelineTiming, PipelineResult, StageTimer, BufferStatsOutput,
    build_result, normalize_attack_type, normalize_action,
    risk_level_from_score,
)
from flow_buffer import FlowBufferManager, FlowRecord, BufferStats, make_flow_key
from threat_intelligence import ThreatIntelligenceEngine
from correlation_engine import CorrelationEngine, FlowEvent
from zero_day_detector import ZeroDayDetector
from ai_attack_detector import AIAttackDetector
from stealth_detector import StealthDetector

logger = logging.getLogger("ids.pipeline")

# ─────────────────────────────────────────────
# Fast-path thresholds
# ─────────────────────────────────────────────
_BENIGN_XGB_THRESHOLD = 0.15
_BENIGN_PPS_THRESHOLD = 30.0
_BENIGN_SYN_THRESHOLD = 0.05
_BENIGN_MITM_THRESHOLD = 0.05
_HIGH_CONFIDENCE_XGB = 0.85
_TRUSTED_IP_THRESHOLD = 0.8


class SecurityPipeline:
    """
    10-Layer Flow-Based Cyber Defense AI Pipeline V3.

    Processes flows (not individual packets) through a multi-layer
    defense architecture with buffered stream processing.

    Thread-safe: designed for concurrent access from batch processing.
    """

    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        self._lock = threading.Lock()

        # ── Layer 1: Flow Buffer Manager ──
        self._flow_buffer = FlowBufferManager(
            config=cfg.get("flow_buffer")
        )

        # ── Layer 3: Stealth Detector (Behavioral) ──
        self._stealth = StealthDetector(
            config=cfg.get("stealth")
        )

        # ── Layer 4: ML Ensemble (results come from upstream) ──
        # No init needed — XGBoost/IF/AE run in main.py

        # ── Layer 5: AI Attack Defense ──
        self._ai_attack = AIAttackDetector(
            config=cfg.get("ai_attack")
        )

        # ── Layer 6: Threat Intelligence (Cached) ──
        self._threat_intel = ThreatIntelligenceEngine(
            config=cfg.get("threat_intelligence")
        )

        # ── Layer 7: Correlation Engine ──
        self._correlation = CorrelationEngine(
            config=cfg.get("correlation")
        )

        # ── Layer 8: Zero-Day Detector ──
        self._zero_day = ZeroDayDetector(
            config=cfg.get("zero_day")
        )

        # ── Pipeline Statistics ──
        self._total_flows = 0
        self._fast_path_flows = 0
        self._timing_accumulator = {
            "capture": 0.0, "feature": 0.0, "behavior": 0.0,
            "ml": 0.0, "ai_defense": 0.0, "intelligence": 0.0,
            "correlation": 0.0, "zero_day": 0.0,
            "decision": 0.0, "response": 0.0,
        }

        # Decision thresholds
        self._decision_thresholds = cfg.get("decision_thresholds", {
            "alert_pps": 80, "alert_syn": 0.15, "block_pps": 200,
        })

        self._cleanup_counter = 0

        logger.info("SecurityPipeline V3 initialized — 10-layer flow-based architecture online")

    # ─────────────────────────────────────────
    # Flow Buffer API (for main.py integration)
    # ─────────────────────────────────────────

    @property
    def flow_buffer(self) -> FlowBufferManager:
        """Direct access to FlowBufferManager for packet ingestion."""
        return self._flow_buffer

    def ingest_packet(self, src_ip: str, dst_ip: str, src_port: int = 0,
                      dst_port: int = 0, protocol: str = "TCP",
                      size: int = 0, flags: str = "", timestamp: float = 0.0):
        """
        Ingest a single packet into the flow buffer.
        Returns (flow_key, triggered_flow_or_None).
        """
        return self._flow_buffer.ingest_packet(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            protocol=protocol, size=size, flags=flags,
            timestamp=timestamp,
        )

    # ─────────────────────────────────────────
    # Main Pipeline API
    # ─────────────────────────────────────────

    def process_flow(
        self,
        src_ip: str,
        dst_ip: str,
        features: Dict[str, Any],
        xgb_score: float = 0.0,
        if_anomaly: bool = False,
        ae_mse: float = 0.0,
        ae_baseline: float = 1.0,
        decision_engine_result: Optional[dict] = None,
        mitm_risk: float = 0.0,
        pps: float = 0.0,
        syn_ratio: float = 0.0,
        protocol: str = "TCP",
        ttl: int = 0,
        flags: str = "",
        payload: bytes = b"",
        was_recently_blocked: bool = False,
        flow_key: str = "",
        src_port: int = 0,
        dst_port: int = 0,
    ) -> PipelineResult:
        """
        Process a single flow through all 10 layers.

        This is the hot path — all optimizations applied here.
        """
        timing = PipelineTiming()
        de_result = decision_engine_result or {}
        optimizations = []

        # ═══════════════════════════════════════
        # LAYER 1: FLOW AGGREGATION (BUFFER)
        # ═══════════════════════════════════════
        with StageTimer() as t1:
            # Get or create flow key
            if not flow_key:
                flow_key = make_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)

            # Get buffer stats from flow buffer
            flow_record = self._flow_buffer.get_flow(flow_key)
            if flow_record:
                buffer_stats_raw = flow_record.get_stats()
                is_trusted = flow_record.trust_score >= _TRUSTED_IP_THRESHOLD
            else:
                buffer_stats_raw = BufferStats()
                is_trusted = self._flow_buffer.is_trusted(src_ip)

            # Build output buffer stats
            buf_out = BufferStatsOutput(
                packet_count=buffer_stats_raw.packet_count,
                total_bytes=buffer_stats_raw.total_bytes,
                duration_sec=buffer_stats_raw.duration_sec,
                packet_rate=buffer_stats_raw.packet_rate,
                byte_rate=buffer_stats_raw.byte_rate,
                entropy=buffer_stats_raw.entropy,
                avg_iat=buffer_stats_raw.avg_iat,
                burst_count=buffer_stats_raw.burst_count,
            )

            # Use buffer's packet_rate if available, otherwise fallback
            if buffer_stats_raw.packet_rate > 0:
                pps = buffer_stats_raw.packet_rate
            if buffer_stats_raw.syn_ratio > 0:
                syn_ratio = buffer_stats_raw.syn_ratio

            capture_ts = time.time()

            # Flow ID for output
            flow_id = f"{src_ip}:{src_port} \u2192 {dst_ip}:{dst_port}"
        timing.capture_time_ms = t1.elapsed_ms

        # ═══════════════════════════════════════
        # LAYER 2: FEATURE EXTRACTION
        # ═══════════════════════════════════════
        with StageTimer() as t2:
            pps = features.get("packet_rate", pps)
            syn_ratio = features.get("syn_flag_ratio", syn_ratio)
            byte_rate = features.get("byte_rate", buf_out.byte_rate)
            burst_count = features.get("burst_count", buf_out.burst_count)
            iat_mean = features.get("iat_mean", buf_out.avg_iat)
            iat_std = features.get("iat_std", 0)

            # Merge buffer-computed features into features dict
            if buffer_stats_raw.entropy > 0 and "entropy" not in features:
                features["entropy"] = buffer_stats_raw.entropy
            if buffer_stats_raw.packet_rate > 0 and "packet_rate" not in features:
                features["packet_rate"] = buffer_stats_raw.packet_rate
        timing.feature_time_ms = t2.elapsed_ms

        # ═══════════════════════════════════════
        # FAST-PATH DETECTION
        # ═══════════════════════════════════════
        base_risk = de_result.get("risk_score", 0.0)
        base_decision = de_result.get("decision", "allow")
        base_attack = de_result.get("attack_type", "Normal")

        is_clearly_benign = (
            base_decision == "allow" and
            base_risk < 0.2 and
            xgb_score < _BENIGN_XGB_THRESHOLD and
            not if_anomaly and
            pps < _BENIGN_PPS_THRESHOLD and
            syn_ratio < _BENIGN_SYN_THRESHOLD and
            mitm_risk < _BENIGN_MITM_THRESHOLD and
            not was_recently_blocked and
            base_attack in ("Normal", "BENIGN")
        )

        is_high_confidence_attack = (
            xgb_score >= _HIGH_CONFIDENCE_XGB and
            base_risk >= 0.7
        )

        # Trusted IP fast-path (even more aggressive skip)
        if is_clearly_benign and is_trusted:
            optimizations.append("trusted_ip_fast_path")

        # ═══════════════════════════════════════
        # LAYER 3: BEHAVIORAL ANALYSIS
        # ═══════════════════════════════════════
        with StageTimer() as t3:
            if is_clearly_benign and is_trusted:
                stealth_result = _EMPTY_STEALTH
                optimizations.append("trusted_skip_stealth")
            elif is_clearly_benign:
                stealth_result = _EMPTY_STEALTH
                optimizations.append("benign_skip_stealth")
            else:
                stealth_result = self._stealth.analyze(
                    src_ip=src_ip,
                    features=features,
                    decision_thresholds=self._decision_thresholds,
                )
        timing.behavior_time_ms = t3.elapsed_ms

        # ═══════════════════════════════════════
        # LAYER 4: ML ENSEMBLE
        # ═══════════════════════════════════════
        with StageTimer() as t4:
            # ML results (XGBoost, IF, AE) come from upstream main.py
            # We just validate and normalize here
            ml_ensemble_score = max(xgb_score, 1.0 if if_anomaly else 0.0)
        timing.ml_time_ms = t4.elapsed_ms

        # ═══════════════════════════════════════
        # LAYER 5: AI ATTACK DEFENSE
        # ═══════════════════════════════════════
        with StageTimer() as t5:
            if is_clearly_benign:
                ai_result = _EMPTY_AI_ATTACK
                optimizations.append("benign_skip_ai_defense")
            elif is_high_confidence_attack:
                ai_result = _EMPTY_AI_ATTACK
                optimizations.append("high_confidence_skip_ai_defense")
            else:
                ai_result = self._ai_attack.analyze(
                    src_ip=src_ip,
                    features=features,
                    xgb_score=xgb_score,
                    if_anomaly=if_anomaly,
                    ae_mse=ae_mse,
                    was_recently_blocked=was_recently_blocked,
                )
        timing.ai_defense_time_ms = t5.elapsed_ms

        # ═══════════════════════════════════════
        # LAYER 6: THREAT INTELLIGENCE (CACHED)
        # ═══════════════════════════════════════
        with StageTimer() as t6:
            intel_result = self._threat_intel.analyze(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                ttl=ttl,
                flags=flags,
                pps=pps,
                payload=payload,
            )
            # Track cache usage
            ti_stats = self._threat_intel.get_stats()
            if ti_stats.get("cache_hits", 0) > 0:
                optimizations.append("cached_threat_intel")
        timing.intelligence_time_ms = t6.elapsed_ms

        # ═══════════════════════════════════════
        # LAYER 7: CORRELATION ENGINE
        # ═══════════════════════════════════════
        with StageTimer() as t7:
            flow_event = FlowEvent(
                src_ip=src_ip, dst_ip=dst_ip,
                attack_type=base_attack if not is_clearly_benign else "Normal",
                risk_score=base_risk if not is_clearly_benign else 0.0,
                pps=pps, timestamp=capture_ts,
                syn_ratio=syn_ratio, mitm_risk=mitm_risk,
            )
            correlation_signals = self._correlation.ingest(flow_event)
            if is_clearly_benign and not correlation_signals:
                optimizations.append("lightweight_correlation")
        timing.correlation_time_ms = t7.elapsed_ms

        # ═══════════════════════════════════════
        # LAYER 8: ZERO-DAY DETECTION
        # ═══════════════════════════════════════
        with StageTimer() as t8:
            # Zero-day detector runs on ALL flows (needs full baseline)
            zd_result = self._zero_day.analyze(
                features=features,
                classification_confidence=xgb_score,
                known_attack_type=base_attack,
            )
        timing.zero_day_time_ms = t8.elapsed_ms

        # ═══════════════════════════════════════
        # LAYER 9: DECISION ENGINE
        # ═══════════════════════════════════════
        with StageTimer() as t9:
            if is_clearly_benign and not zd_result.is_zero_day and not correlation_signals:
                final_result = {
                    "attack_type": "BENIGN",
                    "sub_attack_type": "Normal",
                    "risk_score": base_risk,
                    "confidence": 1.0 - base_risk,
                    "action": "ALLOW",
                    "reason": de_result.get("reason", []),
                }
                optimizations.append("fast_path_benign_decision")

                # Increase trust for this IP
                self._flow_buffer.update_trust(src_ip, 0.005)
            else:
                final_result = self._fuse_decisions(
                    de_result=de_result,
                    zd_result=zd_result,
                    stealth_result=stealth_result,
                    ai_result=ai_result,
                    intel_result=intel_result,
                    correlation_signals=correlation_signals,
                    mitm_risk=mitm_risk,
                    pps=pps,
                    syn_ratio=syn_ratio,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                )

                # Decrease trust for suspicious IPs
                if final_result["action"] in ("BLOCK", "ISOLATE"):
                    self._flow_buffer.update_trust(src_ip, -0.2)
                elif final_result["action"] == "THROTTLE":
                    self._flow_buffer.update_trust(src_ip, -0.05)
        timing.decision_time_ms = t9.elapsed_ms

        # ═══════════════════════════════════════
        # LAYER 10: RESPONSE ENGINE
        # ═══════════════════════════════════════
        with StageTimer() as t10:
            action = final_result["action"]
            risk_score = final_result["risk_score"]

            if action in ("BLOCK", "ISOLATE"):
                self._threat_intel.report_threat(
                    src_ip, final_result["attack_type"], score_delta=0.1
                )
                self._ai_attack.record_block_event(src_ip)
        timing.response_time_ms = t10.elapsed_ms

        # ═══════════════════════════════════════
        # BUILD OUTPUT
        # ═══════════════════════════════════════
        reason_parts = []
        if de_result.get("reason"):
            r = de_result["reason"]
            if isinstance(r, list):
                reason_parts.extend(r[:3])
            else:
                reason_parts.append(str(r))

        if zd_result.is_zero_day:
            reason_parts.append(f"ZERO-DAY: {zd_result.reason}")
        if hasattr(stealth_result, 'is_stealth') and stealth_result.is_stealth:
            reason_parts.append(f"STEALTH: {stealth_result.attack_subtype}")
        if hasattr(ai_result, 'is_ai_attack') and ai_result.is_ai_attack:
            reason_parts.append(f"AI ATTACK: {ai_result.attack_subtype}")
        if intel_result.combined_score > 0.3:
            reason_parts.extend(intel_result.reasons[:2])
        for sig in correlation_signals[:2]:
            reason_parts.append(f"CORRELATION: {sig.description[:80]}")

        # Buffer context in reason
        if buf_out.packet_count > 0:
            reason_parts.append(
                f"[BUFFER: {buf_out.packet_count}pkts/{buf_out.duration_sec:.1f}s "
                f"entropy={buf_out.entropy:.2f}]"
            )

        if optimizations:
            reason_parts.append(f"[OPT: {', '.join(optimizations[:4])}]")

        reason_str = " | ".join(reason_parts) if reason_parts else "Normal traffic \u2014 all signals clear"

        ml_scores = {
            "xgb": xgb_score,
            "if_anomaly": 1.0 if if_anomaly else 0.0,
            "ae_mse": ae_mse,
            "ensemble": ml_ensemble_score,
            "zero_day": zd_result.anomaly_score,
            "stealth": stealth_result.stealth_score if hasattr(stealth_result, 'stealth_score') else 0.0,
            "ai_attack": ai_result.ai_attack_score if hasattr(ai_result, 'ai_attack_score') else 0.0,
            "threat_intel": intel_result.combined_score,
        }

        correlation_id = ""
        if correlation_signals:
            correlation_id = correlation_signals[0].correlation_id

        pipeline_result = build_result(
            attack_type=final_result["attack_type"],
            confidence=final_result["confidence"],
            risk_score=risk_score,
            action=action,
            timing=timing,
            anomaly_score=zd_result.anomaly_score,
            is_zero_day=zd_result.is_zero_day,
            reason=reason_str,
            flow_id=flow_id,
            buffer_stats=buf_out,
            source_ip=src_ip,
            dest_ip=dst_ip,
            pps=pps,
            protocol=protocol,
            sub_attack_type=final_result.get("sub_attack_type", ""),
            ml_scores=ml_scores,
            correlation_id=correlation_id,
            threat_intel_hits=intel_result.reasons[:5],
            optimization_applied=optimizations,
        )

        # ── Update Statistics ──
        with self._lock:
            self._total_flows += 1
            if is_clearly_benign:
                self._fast_path_flows += 1
            self._timing_accumulator["capture"] += timing.capture_time_ms
            self._timing_accumulator["feature"] += timing.feature_time_ms
            self._timing_accumulator["behavior"] += timing.behavior_time_ms
            self._timing_accumulator["ml"] += timing.ml_time_ms
            self._timing_accumulator["ai_defense"] += timing.ai_defense_time_ms
            self._timing_accumulator["intelligence"] += timing.intelligence_time_ms
            self._timing_accumulator["correlation"] += timing.correlation_time_ms
            self._timing_accumulator["zero_day"] += timing.zero_day_time_ms
            self._timing_accumulator["decision"] += timing.decision_time_ms
            self._timing_accumulator["response"] += timing.response_time_ms

        # Periodic cleanup
        self._cleanup_counter += 1
        if self._cleanup_counter >= 200:
            self._cleanup_counter = 0
            self._periodic_cleanup()

        return pipeline_result

    # ─────────────────────────────────────────
    # Decision Fusion
    # ─────────────────────────────────────────

    def _fuse_decisions(
        self,
        de_result: dict,
        zd_result: Any,
        stealth_result: Any,
        ai_result: Any,
        intel_result: Any,
        correlation_signals: list,
        mitm_risk: float,
        pps: float,
        syn_ratio: float,
        src_ip: str,
        dst_ip: str,
    ) -> dict:
        """Fuse all layer results into a final classification."""
        base_risk = de_result.get("risk_score", 0.0)
        base_decision = de_result.get("decision", "allow")
        base_attack = de_result.get("attack_type", "Normal")
        base_reasons = de_result.get("reason", [])

        is_stealth = hasattr(stealth_result, 'is_stealth') and stealth_result.is_stealth
        is_ai = hasattr(ai_result, 'is_ai_attack') and ai_result.is_ai_attack

        scores = {
            "decision_engine": base_risk,
            "zero_day": zd_result.anomaly_score if zd_result.is_zero_day else 0.0,
            "stealth": stealth_result.stealth_score if is_stealth else 0.0,
            "ai_attack": ai_result.ai_attack_score if is_ai else 0.0,
            "threat_intel": intel_result.combined_score,
            "correlation": max((s.severity for s in correlation_signals), default=0.0),
            "mitm": mitm_risk,
        }

        final_risk = max(scores.values())

        if intel_result.is_known_bad:
            final_risk = min(1.0, final_risk + 0.2)
        if correlation_signals:
            max_corr = max(s.severity for s in correlation_signals)
            if max_corr > 0.5:
                final_risk = min(1.0, final_risk + max_corr * 0.15)

        final_risk = max(0.0, min(1.0, final_risk))

        # Attack Type (Priority Order)
        attack_type = "BENIGN"
        sub_attack_type = base_attack
        confidence = 1.0 - final_risk if final_risk < 0.3 else final_risk

        active_vectors = 0
        if base_attack not in ("Normal", "BENIGN") and base_risk > 0.3:
            active_vectors += 1
        if is_stealth:
            active_vectors += 1
        if is_ai:
            active_vectors += 1
        if mitm_risk > 0.4:
            active_vectors += 1

        if zd_result.is_zero_day:
            attack_type = "UNKNOWN_ATTACK"
            sub_attack_type = "Zero-Day"
            confidence = zd_result.anomaly_score
        elif active_vectors >= 2:
            attack_type = "HYBRID_ATTACK"
            vectors = []
            if base_attack not in ("Normal", "BENIGN"):
                vectors.append(base_attack)
            if is_stealth:
                vectors.append(f"Stealth:{stealth_result.attack_subtype}")
            if is_ai:
                vectors.append(f"AI:{ai_result.attack_subtype}")
            if mitm_risk > 0.4:
                vectors.append("MITM")
            sub_attack_type = "+".join(vectors)
            confidence = min(1.0, final_risk + 0.1)
        elif is_ai and ai_result.ai_attack_score > 0.5:
            attack_type = "AI_ATTACK"
            sub_attack_type = f"AI:{ai_result.attack_subtype}"
            confidence = ai_result.ai_attack_score
        elif mitm_risk > 0.4 and base_attack in ("MITM", "Normal", "Anomaly"):
            attack_type = "MITM"
            sub_attack_type = "MITM"
            confidence = mitm_risk
        elif base_attack in ("DDoS", "DoS", "Distributed_SYN", "Slowloris"):
            attack_type = "DDoS"
            sub_attack_type = base_attack
            confidence = base_risk
        elif is_stealth:
            attack_type = "STEALTH_ATTACK"
            sub_attack_type = f"Stealth:{stealth_result.attack_subtype}"
            confidence = stealth_result.stealth_score
        elif base_attack not in ("Normal", "BENIGN") and base_risk > 0.3:
            attack_type = normalize_attack_type(base_attack)
            sub_attack_type = base_attack
            confidence = base_risk
        else:
            attack_type = "BENIGN"
            confidence = 1.0 - final_risk

        # Action
        risk_level = risk_level_from_score(final_risk)
        if attack_type == "BENIGN":
            action = "ALLOW"
        elif risk_level == "CRITICAL":
            action = "ISOLATE" if zd_result.is_zero_day or active_vectors >= 2 else "BLOCK"
        elif risk_level == "HIGH":
            action = "BLOCK"
        elif risk_level == "MEDIUM":
            action = "THROTTLE"
        elif risk_level == "LOW":
            action = "MONITOR"
        else:
            action = normalize_action(base_decision)

        if intel_result.is_known_bad and action == "ALLOW":
            action = "MONITOR"
        if base_decision == "block" and action in ("ALLOW", "MONITOR"):
            action = "BLOCK"
            final_risk = max(final_risk, 0.7)

        return {
            "attack_type": attack_type,
            "sub_attack_type": sub_attack_type,
            "risk_score": final_risk,
            "confidence": max(0.0, min(1.0, confidence)),
            "action": action,
            "reason": base_reasons,
        }

    # ─────────────────────────────────────────
    # Statistics API
    # ─────────────────────────────────────────

    def get_pipeline_stats(self) -> dict:
        with self._lock:
            n = max(self._total_flows, 1)
            return {
                "total_flows_processed": self._total_flows,
                "fast_path_flows": self._fast_path_flows,
                "fast_path_ratio": f"{self._fast_path_flows / n:.1%}",
                "avg_timing_ms": {
                    stage: round(total / n, 4)
                    for stage, total in self._timing_accumulator.items()
                },
                "avg_total_detection_ms": round(
                    sum(v for k, v in self._timing_accumulator.items()
                        if k != "response") / n, 4
                ),
                "avg_total_response_ms": round(
                    sum(self._timing_accumulator.values()) / n, 4
                ),
                "sub_engine_stats": {
                    "flow_buffer": self._flow_buffer.get_stats(),
                    "threat_intelligence": self._threat_intel.get_stats(),
                    "correlation": self._correlation.get_stats(),
                    "zero_day": self._zero_day.get_stats(),
                    "ai_attack": self._ai_attack.get_stats(),
                    "stealth": self._stealth.get_stats(),
                },
            }

    def get_zero_day_alerts(self) -> List[dict]:
        return self._zero_day.get_novel_patterns()

    def get_correlation_events(self) -> List[dict]:
        return self._correlation.get_active_correlations()

    def _periodic_cleanup(self):
        try:
            self._flow_buffer.cleanup()
            self._threat_intel.cleanup()
            self._correlation.cleanup()
            self._ai_attack.cleanup()
            self._stealth.cleanup()
        except Exception as e:
            logger.error("Pipeline cleanup error: %s", e)


# ─────────────────────────────────────────────
# Empty result singletons
# ─────────────────────────────────────────────

class _EmptyStealthResult:
    __slots__ = ()
    is_stealth = False
    stealth_score = 0.0
    attack_subtype = ""
    reasons = []

class _EmptyAIAttackResult:
    __slots__ = ()
    is_ai_attack = False
    ai_attack_score = 0.0
    attack_subtype = ""
    reasons = []

_EMPTY_STEALTH = _EmptyStealthResult()
_EMPTY_AI_ATTACK = _EmptyAIAttackResult()
