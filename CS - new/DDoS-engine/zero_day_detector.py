"""
zero_day_detector.py — Unknown / Zero-Day Attack Detection (Stage 3+4)
=======================================================================
Detects novel attack patterns that don't match any known attack signatures
using statistical profiling, distribution analysis, and clustering.

When no known classification achieves sufficient confidence, the flow is
flagged as UNKNOWN_ATTACK with is_zero_day=True and a computed anomaly_score.
"""

import time
import math
import logging
import threading
import numpy as np
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("ids.zero_day")


# ─────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────

@dataclass
class FeatureProfile:
    """Running statistics for a single feature dimension."""
    name: str
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0         # Running variance accumulator (Welford's algorithm)
    min_val: float = float('inf')
    max_val: float = float('-inf')

    @property
    def variance(self) -> float:
        return self.m2 / self.count if self.count > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance) if self.variance > 0 else 0.0

    def update(self, value: float):
        """Update running statistics using Welford's online algorithm."""
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2
        self.min_val = min(self.min_val, value)
        self.max_val = max(self.max_val, value)

    def z_score(self, value: float) -> float:
        """Compute z-score of a value against the running distribution."""
        if self.std < 1e-9:
            return 0.0
        return abs(value - self.mean) / self.std


@dataclass
class ZeroDayResult:
    """Output from zero-day detection analysis."""
    anomaly_score: float = 0.0        # 0.0–1.0 (higher = more anomalous)
    is_zero_day: bool = False
    deviating_features: List[str] = field(default_factory=list)
    max_z_score: float = 0.0
    avg_z_score: float = 0.0
    pattern_id: str = ""               # Unique ID for novel pattern cluster
    reason: str = ""


# ─────────────────────────────────────────────
# Feature Keys Used for Profiling
# ─────────────────────────────────────────────

PROFILE_FEATURES = [
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "std_packet_size",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "syn_flag_ratio",
    "ack_flag_ratio",
    "fin_flag_ratio",
    "rst_flag_ratio",
    "unique_src_ips",
    "unique_dst_ips",
    "iat_mean",
    "iat_std",
    "burst_count",
    "connection_duration",
    "pkts_per_src_ip",
]


# ─────────────────────────────────────────────
# Zero-Day Detector
# ─────────────────────────────────────────────

class ZeroDayDetector:
    """
    Detects unknown/zero-day attack patterns using statistical profiling.

    Approach:
      1. Maintain running statistics (mean, variance, min, max) for 18+ features
         using Welford's online algorithm (O(1) per update, no stored history needed)
      2. For each incoming flow, compute z-scores against the learned distribution
      3. If multiple features deviate significantly (> threshold sigma), and no
         known attack classification achieves high confidence → flag as zero-day
      4. Compute anomaly_score as normalized aggregate of z-scores
      5. Track novel patterns for future recognition

    The detector has two phases:
      - Learning (first N flows): Builds baseline distributions, no detection
      - Active: Detects deviations from learned baseline

    Thread-safe for concurrent access.
    """

    def __init__(self, config: Optional[dict] = None):
        self._lock = threading.Lock()
        cfg = config or {}

        # Configuration
        self._z_threshold = cfg.get("z_threshold", 3.0)           # Sigma for individual feature
        self._min_deviating = cfg.get("min_deviating_features", 3)  # Min features that must deviate
        self._anomaly_threshold = cfg.get("anomaly_threshold", 0.75)  # Score to flag as zero-day
        self._learning_flows = cfg.get("learning_flows", 500)      # Flows before active detection
        self._classification_confidence_min = cfg.get("classification_confidence_min", 0.6)

        # Per-feature running statistics
        self._profiles: Dict[str, FeatureProfile] = {}
        for feat in PROFILE_FEATURES:
            self._profiles[feat] = FeatureProfile(name=feat)

        # Global counters
        self._total_flows = 0
        self._zero_day_count = 0
        self._is_learning = True

        # Novel pattern storage (limited to prevent memory growth)
        self._novel_patterns: deque = deque(maxlen=1000)
        self._pattern_clusters: Dict[str, int] = defaultdict(int)  # pattern_hash → count

        logger.info(
            "ZeroDayDetector initialized | features=%d | z_threshold=%.1f | "
            "learning_flows=%d | anomaly_threshold=%.2f",
            len(PROFILE_FEATURES), self._z_threshold,
            self._learning_flows, self._anomaly_threshold,
        )

    # ─────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────

    def analyze(
        self,
        features: Dict[str, float],
        classification_confidence: float = 1.0,
        known_attack_type: str = "Normal",
    ) -> ZeroDayResult:
        """
        Analyze a feature vector for zero-day anomalies.

        Args:
            features: Dict of feature_name → value (from FeatureExtractor)
            classification_confidence: Confidence of the strongest known classifier (0–1)
            known_attack_type: The attack type assigned by the ML/rule engine

        Returns:
            ZeroDayResult with anomaly_score and is_zero_day flag
        """
        result = ZeroDayResult()

        with self._lock:
            self._total_flows += 1

            # Extract values for profiled features
            feature_values = {}
            for feat in PROFILE_FEATURES:
                val = features.get(feat, 0.0)
                try:
                    val = float(val)
                except (TypeError, ValueError):
                    val = 0.0
                feature_values[feat] = val

            # Update running statistics
            for feat, val in feature_values.items():
                self._profiles[feat].update(val)

            # Learning phase check
            if self._total_flows <= self._learning_flows:
                self._is_learning = True
                return result  # No detection during learning

            self._is_learning = False

            # ── Compute Z-Scores ──
            z_scores = {}
            for feat, val in feature_values.items():
                z = self._profiles[feat].z_score(val)
                z_scores[feat] = z

            # ── Identify Deviating Features ──
            deviating = [
                (feat, z) for feat, z in z_scores.items()
                if z > self._z_threshold
            ]
            deviating.sort(key=lambda x: x[1], reverse=True)

            result.deviating_features = [f"{feat} (z={z:.1f})" for feat, z in deviating]
            result.max_z_score = max(z_scores.values()) if z_scores else 0.0
            result.avg_z_score = (
                sum(z_scores.values()) / len(z_scores) if z_scores else 0.0
            )

            # ── Compute Anomaly Score ──
            # Composite: weighted combination of max z-score, number of deviating features,
            # and inverse of classification confidence
            if deviating:
                z_component = min(1.0, result.max_z_score / 10.0)  # Saturates at z=10
                breadth_component = min(1.0, len(deviating) / len(PROFILE_FEATURES))
                confidence_penalty = max(0.0, 1.0 - classification_confidence)

                result.anomaly_score = (
                    z_component * 0.4 +
                    breadth_component * 0.3 +
                    confidence_penalty * 0.3
                )
                result.anomaly_score = min(1.0, result.anomaly_score)
            else:
                result.anomaly_score = 0.0

            # ── Zero-Day Decision ──
            is_zero_day = (
                result.anomaly_score >= self._anomaly_threshold and
                len(deviating) >= self._min_deviating and
                classification_confidence < self._classification_confidence_min
            )

            # Also flag if the classifier says Normal but anomaly is very high
            if (known_attack_type in ("Normal", "BENIGN") and
                    result.anomaly_score >= 0.85 and
                    len(deviating) >= 4):
                is_zero_day = True

            result.is_zero_day = is_zero_day

            if is_zero_day:
                self._zero_day_count += 1

                # Generate pattern fingerprint for clustering
                pattern_hash = self._compute_pattern_hash(deviating)
                result.pattern_id = pattern_hash
                self._pattern_clusters[pattern_hash] += 1

                # Store novel pattern
                self._novel_patterns.append({
                    "timestamp": time.time(),
                    "anomaly_score": result.anomaly_score,
                    "deviating_features": result.deviating_features[:5],
                    "pattern_id": pattern_hash,
                    "features": {k: round(v, 4) for k, v in feature_values.items()},
                })

                cluster_count = self._pattern_clusters[pattern_hash]
                result.reason = (
                    f"ZERO-DAY: {len(deviating)} features deviate >={self._z_threshold}σ from baseline "
                    f"(max_z={result.max_z_score:.1f}, anomaly={result.anomaly_score:.2f}). "
                    f"Pattern cluster '{pattern_hash}' seen {cluster_count} time(s). "
                    f"Top deviations: {', '.join(result.deviating_features[:3])}"
                )

                logger.warning("🔴 ZERO-DAY detected: %s", result.reason)
            else:
                result.reason = (
                    f"Anomaly analysis: score={result.anomaly_score:.2f}, "
                    f"deviating={len(deviating)}/{len(PROFILE_FEATURES)}, "
                    f"max_z={result.max_z_score:.1f}"
                )

        return result

    def get_stats(self) -> dict:
        """Return zero-day detector statistics."""
        with self._lock:
            return {
                "total_flows_analyzed": self._total_flows,
                "is_learning": self._is_learning,
                "learning_progress": min(100, int(self._total_flows / self._learning_flows * 100)),
                "zero_day_detections": self._zero_day_count,
                "known_patterns": len(self._pattern_clusters),
                "novel_patterns_stored": len(self._novel_patterns),
                "feature_profiles": {
                    feat: {
                        "mean": round(p.mean, 4),
                        "std": round(p.std, 4),
                        "min": round(p.min_val, 4) if p.min_val != float('inf') else 0,
                        "max": round(p.max_val, 4) if p.max_val != float('-inf') else 0,
                        "count": p.count,
                    }
                    for feat, p in self._profiles.items()
                },
            }

    def get_novel_patterns(self, limit: int = 50) -> List[dict]:
        """Return recent novel patterns for the API."""
        with self._lock:
            return list(self._novel_patterns)[-limit:]

    # ─────────────────────────────────────────
    # Internal Methods
    # ─────────────────────────────────────────

    @staticmethod
    def _compute_pattern_hash(deviating: List[Tuple[str, float]]) -> str:
        """Generate a short hash identifying which features are deviating."""
        # Use the names of deviating features (sorted) as a fingerprint
        feat_names = sorted([f for f, _ in deviating])
        key = "|".join(feat_names)
        # Short hash
        import hashlib
        return hashlib.md5(key.encode()).hexdigest()[:8]
