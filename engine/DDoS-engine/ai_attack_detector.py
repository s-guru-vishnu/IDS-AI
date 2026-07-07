"""
ai_attack_detector.py — AI/ML Attack Detection Module
======================================================
Detects attacks specifically targeting the ML models within the IDS:
  - Adversarial input manipulation
  - Data poisoning (training distribution drift)
  - Model evasion (systematic threshold avoidance)
  - Model extraction attempts (systematic probing)
  - Adaptive feedback-based attacks (response-aware attackers)
  - Feature distribution monitoring

This module works alongside the ML Detection Layer (Stage 4)
to protect the AI system against AI-targeted threats.
"""

import time
import math
import logging
import threading
import numpy as np
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

logger = logging.getLogger("ids.ai_attack")


# ─────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────

@dataclass
class AIAttackResult:
    """Output from AI attack detection analysis."""
    ai_attack_score: float = 0.0         # 0.0–1.0 composite score
    attack_subtype: str = ""              # adversarial | poisoning | evasion | extraction | adaptive
    is_ai_attack: bool = False
    reasons: List[str] = field(default_factory=list)

    # Individual detector scores
    adversarial_score: float = 0.0
    poisoning_score: float = 0.0
    evasion_score: float = 0.0
    extraction_score: float = 0.0
    adaptive_score: float = 0.0


# ─────────────────────────────────────────────
# AI Attack Detector
# ─────────────────────────────────────────────

class AIAttackDetector:
    """
    Detects attacks targeting the AI/ML components of the IDS.

    Detection Methods:
    ─────────────────────
    1. Adversarial Input Detection:
       - Monitor for feature vectors near decision boundaries
       - Detect suspiciously precise feature values (too clean)
       - Check for feature combinations that shouldn't naturally occur

    2. Data Poisoning Detection:
       - Track feature distribution KL-divergence over time
       - Detect sudden shifts in input distribution
       - Compare current batch distribution against training baseline

    3. Model Evasion Detection:
       - Track per-IP prediction confidence history
       - Detect systematic hovering just below detection thresholds
       - Identify patterns that consistently produce edge-case scores

    4. Model Extraction Detection:
       - Detect systematic feature probing (grid-search patterns)
       - Track query patterns that suggest model boundary mapping
       - Flag high-frequency queries with controlled variation

    5. Adaptive Attack Detection:
       - Compare attacker behavior before/after detection events
       - Detect immediate behavioral shifts following blocks
       - Track response-correlated pattern changes

    Thread-safe for concurrent pipeline access.
    """

    def __init__(self, config: Optional[dict] = None):
        self._lock = threading.Lock()
        cfg = config or {}

        # Thresholds
        self._adversarial_threshold = cfg.get("adversarial_threshold", 0.7)
        self._poisoning_threshold = cfg.get("poisoning_threshold", 0.6)
        self._evasion_threshold = cfg.get("evasion_threshold", 0.65)
        self._extraction_threshold = cfg.get("extraction_threshold", 0.7)
        self._adaptive_threshold = cfg.get("adaptive_threshold", 0.6)

        # ── Per-IP tracking state ──

        # Evasion: track prediction scores per IP to detect boundary-riding
        self._prediction_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=50)
        )

        # Extraction: track feature variation patterns per IP
        self._feature_query_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=100)
        )

        # Adaptive: track behavior before/after blocks
        self._block_events: Dict[str, List[float]] = defaultdict(list)  # ip → [block_timestamps]
        self._pre_block_behavior: Dict[str, dict] = {}
        self._post_block_behavior: Dict[str, dict] = {}

        # ── Global distribution tracking ──

        # Feature means for distribution drift detection
        self._feature_means: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=100)  # Rolling window of per-batch means
        )
        self._baseline_means: Dict[str, float] = {}
        self._baseline_set = False
        self._batch_count = 0
        self._baseline_batches = 50  # Learn baseline from first 50 batches

        # Stats
        self._total_analyzed = 0
        self._ai_attacks_detected = 0

        logger.info("AIAttackDetector initialized")

    # ─────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────

    def analyze(
        self,
        src_ip: str,
        features: Dict[str, float],
        xgb_score: float = 0.0,
        if_anomaly: bool = False,
        ae_mse: float = 0.0,
        was_recently_blocked: bool = False,
    ) -> AIAttackResult:
        """
        Analyze a flow for AI-targeted attack patterns.

        Args:
            src_ip: Source IP address
            features: Feature vector from FeatureExtractor
            xgb_score: XGBoost prediction probability
            if_anomaly: Isolation Forest anomaly flag
            ae_mse: Autoencoder reconstruction error
            was_recently_blocked: Whether this IP was blocked in the last N windows

        Returns:
            AIAttackResult with composite score and subtype
        """
        result = AIAttackResult()

        with self._lock:
            self._total_analyzed += 1

            # 1. Adversarial Input Detection
            self._detect_adversarial(features, xgb_score, result)

            # 2. Data Poisoning Detection
            self._detect_poisoning(features, result)

            # 3. Model Evasion Detection
            self._detect_evasion(src_ip, xgb_score, result)

            # 4. Model Extraction Detection
            self._detect_extraction(src_ip, features, result)

            # 5. Adaptive Attack Detection
            self._detect_adaptive(src_ip, features, was_recently_blocked, result)

            # ── Composite Score ──
            scores = [
                result.adversarial_score,
                result.poisoning_score,
                result.evasion_score,
                result.extraction_score,
                result.adaptive_score,
            ]
            result.ai_attack_score = min(1.0, max(scores) * 0.6 + sum(scores) / len(scores) * 0.4)

            # Determine dominant subtype
            score_map = {
                "adversarial": result.adversarial_score,
                "poisoning": result.poisoning_score,
                "evasion": result.evasion_score,
                "extraction": result.extraction_score,
                "adaptive": result.adaptive_score,
            }
            max_subtype = max(score_map, key=score_map.get)
            max_score = score_map[max_subtype]

            if max_score >= self._adversarial_threshold * 0.7:  # Use 70% of threshold as minimum
                result.attack_subtype = max_subtype
                result.is_ai_attack = result.ai_attack_score >= 0.5

            if result.is_ai_attack:
                self._ai_attacks_detected += 1
                logger.warning(
                    "🤖 AI Attack detected from %s: %s (score=%.2f)",
                    src_ip, result.attack_subtype, result.ai_attack_score,
                )

        return result

    def record_block_event(self, ip: str):
        """Record that an IP was blocked (for adaptive attack detection)."""
        with self._lock:
            self._block_events[ip].append(time.time())
            # Keep only last 10 block events
            if len(self._block_events[ip]) > 10:
                self._block_events[ip] = self._block_events[ip][-10:]

    def get_stats(self) -> dict:
        """Return AI attack detector statistics."""
        with self._lock:
            return {
                "total_analyzed": self._total_analyzed,
                "ai_attacks_detected": self._ai_attacks_detected,
                "tracked_ips": len(self._prediction_history),
                "baseline_established": self._baseline_set,
            }

    # ─────────────────────────────────────────
    # Detection Methods
    # ─────────────────────────────────────────

    def _detect_adversarial(self, features: Dict[str, float],
                            xgb_score: float, result: AIAttackResult):
        """
        Detect adversarial input manipulation.

        Checks:
          - Feature values suspiciously close to known decision boundaries
          - Unnaturally uniform or precise feature distributions
          - Feature combinations that are physically impossible in real traffic
        """
        score = 0.0
        reasons = []

        # Check 1: Decision boundary proximity
        # If XGBoost score is very close to 0.5 (decision boundary), it could be
        # an adversarial sample crafted to be ambiguous
        if 0.45 <= xgb_score <= 0.55:
            boundary_proximity = 1.0 - abs(xgb_score - 0.5) * 20  # Max at exactly 0.5
            score += boundary_proximity * 0.3
            if boundary_proximity > 0.5:
                reasons.append(
                    f"Prediction near decision boundary (xgb={xgb_score:.3f})"
                )

        # Check 2: Impossible feature combinations
        pps = features.get("packet_rate", 0)
        byte_rate = features.get("byte_rate", 0)
        avg_size = features.get("avg_packet_size", 0)

        if pps > 0 and avg_size > 0:
            expected_byte_rate = pps * avg_size
            if byte_rate > 0 and abs(expected_byte_rate - byte_rate) / max(byte_rate, 1) > 0.5:
                score += 0.3
                reasons.append("Inconsistent packet_rate × avg_size vs byte_rate")

        # Check 3: Protocol ratios don't sum to ~1.0
        tcp = features.get("tcp_ratio", 0)
        udp = features.get("udp_ratio", 0)
        icmp = features.get("icmp_ratio", 0)
        proto_sum = tcp + udp + icmp
        if proto_sum > 0 and abs(proto_sum - 1.0) > 0.15:
            score += 0.2
            reasons.append(f"Protocol ratios sum to {proto_sum:.2f} (expected ~1.0)")

        # Check 4: Zero variance across traffic (unnaturally uniform)
        std_size = features.get("std_packet_size", 0)
        iat_std = features.get("iat_std", 0)
        if pps > 20 and std_size < 0.1 and iat_std < 0.0001:
            score += 0.25
            reasons.append("Unnaturally uniform traffic (zero variance in size and timing)")

        result.adversarial_score = min(1.0, score)
        result.reasons.extend(reasons)

    def _detect_poisoning(self, features: Dict[str, float], result: AIAttackResult):
        """
        Detect data poisoning attempts.

        Monitors feature distribution drift over time. A poisoning attack
        gradually shifts the input distribution to corrupt the model.
        """
        score = 0.0
        reasons = []

        # Track batch-level feature means
        self._batch_count += 1
        key_features = ["packet_rate", "syn_flag_ratio", "byte_rate", "iat_mean"]

        for feat in key_features:
            val = features.get(feat, 0.0)
            self._feature_means[feat].append(val)

        # Establish baseline
        if self._batch_count == self._baseline_batches:
            for feat in key_features:
                values = list(self._feature_means[feat])
                if values:
                    self._baseline_means[feat] = sum(values) / len(values)
            self._baseline_set = True
            return

        if not self._baseline_set:
            return

        # Check for distribution drift
        drift_count = 0
        for feat in key_features:
            baseline = self._baseline_means.get(feat, 0)
            if baseline == 0:
                continue

            recent = list(self._feature_means[feat])[-20:]
            if not recent:
                continue

            current_mean = sum(recent) / len(recent)
            drift_ratio = abs(current_mean - baseline) / max(abs(baseline), 0.001)

            if drift_ratio > 2.0:  # More than 2x drift from baseline
                drift_count += 1
                score += 0.2
                reasons.append(
                    f"Distribution drift in {feat}: baseline={baseline:.3f}, "
                    f"current={current_mean:.3f} (drift={drift_ratio:.1f}x)"
                )

        if drift_count >= 2:
            score += 0.2  # Multiple features drifting simultaneously
            reasons.append(f"Multi-feature distribution drift ({drift_count} features)")

        result.poisoning_score = min(1.0, score)
        result.reasons.extend(reasons)

    def _detect_evasion(self, src_ip: str, xgb_score: float, result: AIAttackResult):
        """
        Detect model evasion attempts.

        An evasion attacker crafts traffic to produce ML scores just below
        the detection threshold. This manifests as a suspiciously stable
        prediction score hovering near (but below) the threshold.
        """
        score = 0.0
        reasons = []

        history = self._prediction_history[src_ip]
        history.append(xgb_score)

        if len(history) < 5:
            return

        recent = list(history)[-10:]

        # Check 1: Scores clustered just below threshold (0.3-0.5 range)
        in_evasion_band = sum(1 for s in recent if 0.2 <= s <= 0.5)
        evasion_ratio = in_evasion_band / len(recent)

        if evasion_ratio >= 0.7 and len(recent) >= 5:
            score += 0.4
            reasons.append(
                f"Prediction scores clustered in evasion band "
                f"({evasion_ratio:.0%} of {len(recent)} windows between 0.2-0.5)"
            )

        # Check 2: Suspiciously low variance in scores (too consistent)
        if len(recent) >= 5:
            score_std = np.std(recent)
            if score_std < 0.02 and np.mean(recent) > 0.1:
                score += 0.3
                reasons.append(
                    f"Suspiciously stable prediction scores (std={score_std:.4f})"
                )

        # Check 3: Scores repeatedly reaching exactly the same value
        rounded = [round(s, 2) for s in recent]
        most_common = max(set(rounded), key=rounded.count) if rounded else 0
        repeat_count = rounded.count(most_common)
        if repeat_count >= len(recent) * 0.6 and len(recent) >= 5:
            score += 0.2
            reasons.append(
                f"Repeating prediction value {most_common:.2f} "
                f"({repeat_count}/{len(recent)} windows)"
            )

        result.evasion_score = min(1.0, score)
        result.reasons.extend(reasons)

    def _detect_extraction(self, src_ip: str, features: Dict[str, float],
                           result: AIAttackResult):
        """
        Detect model extraction/theft attempts.

        Extraction attacks send many queries with controlled feature variation
        to map the model's decision boundaries. This looks like:
          - High frequency queries from the same IP
          - Systematic variation of one feature at a time
          - Grid-search-like patterns in feature space
        """
        score = 0.0
        reasons = []

        # Store feature vector for this IP
        key_features = ["packet_rate", "syn_flag_ratio", "byte_rate", "avg_packet_size"]
        current = tuple(features.get(f, 0) for f in key_features)
        history = self._feature_query_history[src_ip]
        history.append(current)

        if len(history) < 10:
            return

        recent = list(history)[-20:]

        # Check 1: High query frequency (many evaluations of same IP)
        if len(recent) >= 15:
            score += 0.2
            reasons.append(f"High query frequency from {src_ip} ({len(recent)} recent evaluations)")

        # Check 2: Systematic single-feature variation
        # For each feature dimension, check if only that dimension changes
        for dim in range(len(key_features)):
            other_dims_stable = True
            dim_varies = False

            for i in range(1, len(recent)):
                for d in range(len(key_features)):
                    if d == dim:
                        if abs(recent[i][d] - recent[i - 1][d]) > 0.01:
                            dim_varies = True
                    else:
                        if abs(recent[i][d] - recent[i - 1][d]) > 0.01:
                            other_dims_stable = False

            if dim_varies and other_dims_stable and len(recent) >= 5:
                score += 0.3
                reasons.append(
                    f"Systematic variation of {key_features[dim]} "
                    f"while other features remain stable (model probing pattern)"
                )
                break  # One detection is enough

        # Check 3: Grid-search pattern (even spacing in feature values)
        if len(recent) >= 8:
            for dim in range(len(key_features)):
                dim_values = sorted(set(r[dim] for r in recent))
                if len(dim_values) >= 4:
                    # Check for even spacing
                    diffs = [dim_values[i + 1] - dim_values[i]
                             for i in range(len(dim_values) - 1)]
                    if diffs and max(diffs) > 0:
                        spacing_ratio = min(diffs) / max(diffs)
                        if spacing_ratio > 0.8:  # Very even spacing
                            score += 0.25
                            reasons.append(
                                f"Grid-search pattern in {key_features[dim]} "
                                f"({len(dim_values)} evenly-spaced values)"
                            )
                            break

        result.extraction_score = min(1.0, score)
        result.reasons.extend(reasons)

    def _detect_adaptive(self, src_ip: str, features: Dict[str, float],
                         was_recently_blocked: bool, result: AIAttackResult):
        """
        Detect adaptive/feedback-based attacks.

        Adaptive attackers change their behavior after being detected/blocked.
        We detect this by comparing pre-block and post-block traffic patterns.
        """
        score = 0.0
        reasons = []

        block_times = self._block_events.get(src_ip, [])
        if not block_times:
            return

        now = time.time()
        recent_blocks = [t for t in block_times if now - t < 600]  # Last 10 minutes

        if not recent_blocks:
            return

        # Check 1: Multiple blocks followed by continued activity
        if len(recent_blocks) >= 2:
            score += 0.3
            reasons.append(
                f"Persistent after {len(recent_blocks)} blocks in 10 minutes"
            )

        # Check 2: Behavior change after block
        # If the IP was recently blocked and is now sending traffic with
        # different characteristics, it's adapting
        if was_recently_blocked:
            current_pps = features.get("packet_rate", 0)
            current_syn = features.get("syn_flag_ratio", 0)

            # Store current behavior as post-block
            self._post_block_behavior[src_ip] = {
                "pps": current_pps,
                "syn": current_syn,
                "timestamp": now,
            }

            pre = self._pre_block_behavior.get(src_ip)
            post = self._post_block_behavior.get(src_ip)

            if pre and post:
                pps_change = abs(pre.get("pps", 0) - post.get("pps", 0))
                syn_change = abs(pre.get("syn", 0) - post.get("syn", 0))

                if pps_change > 20 or syn_change > 0.1:
                    score += 0.4
                    reasons.append(
                        f"Behavioral adaptation detected: PPS changed by {pps_change:.0f}, "
                        f"SYN ratio changed by {syn_change:.2f} after block"
                    )
        else:
            # Store current behavior as pre-block baseline
            self._pre_block_behavior[src_ip] = {
                "pps": features.get("packet_rate", 0),
                "syn": features.get("syn_flag_ratio", 0),
                "timestamp": now,
            }

        result.adaptive_score = min(1.0, score)
        result.reasons.extend(reasons)

    # ─────────────────────────────────────────
    # Cleanup
    # ─────────────────────────────────────────

    def cleanup(self):
        """Remove stale tracking entries."""
        now = time.time()
        with self._lock:
            for d in (self._prediction_history, self._feature_query_history):
                if len(d) > 5000:
                    keys = list(d.keys())
                    for k in keys[:len(keys) - 2500]:
                        del d[k]

            # Clean old block events
            for ip in list(self._block_events.keys()):
                self._block_events[ip] = [
                    t for t in self._block_events[ip] if now - t < 3600
                ]
                if not self._block_events[ip]:
                    del self._block_events[ip]
