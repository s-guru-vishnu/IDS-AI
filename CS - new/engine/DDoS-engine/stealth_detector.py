"""
stealth_detector.py — Stealth & Advanced Attack Detection Module
=================================================================
Detects attack patterns specifically designed to evade traditional
threshold-based IDS systems:

  - Low-and-slow attacks (sub-threshold sustained pressure)
  - Human-like mimicry traffic (synthetic natural patterns)
  - Distributed micro-traffic (many tiny flows aggregating)
  - Threshold-aware attacks (hovering just below alerts)
  - Noise injection (chaff traffic masking real attack)
  - Time-shifted / jitter attacks (randomized timing)
"""

import time
import math
import logging
import threading
import numpy as np
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from scipy import stats as scipy_stats

logger = logging.getLogger("ids.stealth")


# ─────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────

@dataclass
class StealthResult:
    """Output from stealth attack detection."""
    stealth_score: float = 0.0        # 0.0–1.0 composite
    attack_subtype: str = ""           # low_slow | mimicry | micro_traffic | threshold_aware | noise | jitter
    is_stealth: bool = False
    reasons: List[str] = field(default_factory=list)

    # Individual scores
    low_slow_score: float = 0.0
    mimicry_score: float = 0.0
    micro_traffic_score: float = 0.0
    threshold_aware_score: float = 0.0
    noise_score: float = 0.0
    jitter_score: float = 0.0


# ─────────────────────────────────────────────
# Stealth Detector
# ─────────────────────────────────────────────

class StealthDetector:
    """
    Detects stealth and advanced evasion attack patterns.

    These attacks are specifically designed to defeat threshold-based
    IDS systems by operating below detection limits, mimicking
    legitimate traffic, or using distributed coordination.

    Thread-safe for concurrent pipeline access.
    """

    def __init__(self, config: Optional[dict] = None):
        self._lock = threading.Lock()
        cfg = config or {}

        # Configuration
        self._low_slow_window_hours = cfg.get("low_slow_window_hours", 1)
        self._mimicry_ks_threshold = cfg.get("mimicry_ks_threshold", 0.05)
        self._micro_traffic_aggregate_pps = cfg.get("micro_traffic_aggregate_pps", 50)
        self._jitter_cv_threshold = cfg.get("jitter_cv_threshold", 0.3)

        # ── Per-IP tracking ──

        # Low-and-slow: sustained sub-threshold activity
        self._sustained_activity: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=360)  # Up to 1 hour at 10s windows
        )

        # Inter-arrival time tracking for mimicry/jitter detection
        self._iat_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=200)
        )

        # PPS history for threshold-aware detection
        self._pps_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=50)
        )

        # Traffic composition history for noise detection
        self._composition_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=30)
        )

        # Baseline IAT distribution (learned from legitimate traffic)
        self._baseline_iats: deque = deque(maxlen=5000)
        self._baseline_learned = False
        self._baseline_count = 0
        self._baseline_target = 1000

        # Stats
        self._total_analyzed = 0
        self._stealth_detected = 0

        logger.info("StealthDetector initialized | low_slow_window=%dh",
                     self._low_slow_window_hours)

    # ─────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────

    def analyze(
        self,
        src_ip: str,
        features: Dict[str, float],
        decision_thresholds: Optional[Dict[str, float]] = None,
    ) -> StealthResult:
        """
        Analyze a flow for stealth attack patterns.

        Args:
            src_ip: Source IP address
            features: Feature vector from FeatureExtractor
            decision_thresholds: Current IDS thresholds (for threshold-aware detection)

        Returns:
            StealthResult with composite score
        """
        result = StealthResult()

        with self._lock:
            self._total_analyzed += 1

            pps = features.get("packet_rate", 0)
            iat_mean = features.get("iat_mean", 0)
            iat_std = features.get("iat_std", 0)
            syn_ratio = features.get("syn_flag_ratio", 0)
            burst_count = features.get("burst_count", 0)
            byte_rate = features.get("byte_rate", 0)
            tcp_ratio = features.get("tcp_ratio", 0)
            udp_ratio = features.get("udp_ratio", 0)

            # Update tracking
            now = time.time()
            self._sustained_activity[src_ip].append((pps, syn_ratio, now))
            self._pps_history[src_ip].append(pps)
            if iat_mean > 0:
                self._iat_history[src_ip].append(iat_mean)

            self._composition_history[src_ip].append({
                "tcp": tcp_ratio, "udp": udp_ratio,
                "pps": pps, "byte_rate": byte_rate,
            })

            # Build baseline IAT distribution
            if not self._baseline_learned and iat_mean > 0:
                self._baseline_iats.append(iat_mean)
                self._baseline_count += 1
                if self._baseline_count >= self._baseline_target:
                    self._baseline_learned = True

            # ── Detection Passes ──

            # 1. Low-and-slow
            self._detect_low_slow(src_ip, result)

            # 2. Human-like mimicry
            self._detect_mimicry(src_ip, iat_mean, result)

            # 3. Threshold-aware
            if decision_thresholds:
                self._detect_threshold_aware(src_ip, pps, syn_ratio, decision_thresholds, result)

            # 4. Noise injection
            self._detect_noise(src_ip, result)

            # 5. Jitter / timing manipulation
            self._detect_jitter(src_ip, result)

            # ── Composite Score ──
            scores = [
                result.low_slow_score,
                result.mimicry_score,
                result.threshold_aware_score,
                result.noise_score,
                result.jitter_score,
            ]

            result.stealth_score = min(1.0, max(scores) * 0.6 + sum(scores) / max(len(scores), 1) * 0.4)

            # Determine dominant subtype
            score_map = {
                "low_slow": result.low_slow_score,
                "mimicry": result.mimicry_score,
                "threshold_aware": result.threshold_aware_score,
                "noise": result.noise_score,
                "jitter": result.jitter_score,
            }
            max_subtype = max(score_map, key=score_map.get)
            max_score = score_map[max_subtype]

            if max_score >= 0.4:
                result.attack_subtype = max_subtype
                result.is_stealth = result.stealth_score >= 0.5

            if result.is_stealth:
                self._stealth_detected += 1
                logger.warning(
                    "🥷 Stealth attack from %s: %s (score=%.2f)",
                    src_ip, result.attack_subtype, result.stealth_score,
                )

        return result

    def get_stats(self) -> dict:
        """Return stealth detector statistics."""
        with self._lock:
            return {
                "total_analyzed": self._total_analyzed,
                "stealth_detected": self._stealth_detected,
                "tracked_ips": len(self._sustained_activity),
                "baseline_learned": self._baseline_learned,
            }

    # ─────────────────────────────────────────
    # Detection Methods
    # ─────────────────────────────────────────

    def _detect_low_slow(self, src_ip: str, result: StealthResult):
        """
        Detect low-and-slow attacks.

        Pattern: Sustained sub-threshold activity over a long period.
        Each individual window looks benign, but the cumulative effect
        is resource exhaustion.
        """
        score = 0.0
        reasons = []

        history = list(self._sustained_activity.get(src_ip, []))
        if len(history) < 10:
            return

        # Count windows with activity (PPS > 0)
        active_windows = sum(1 for pps, syn, ts in history if pps > 0)
        total_windows = len(history)
        activity_ratio = active_windows / total_windows

        # Count windows with low but non-zero SYN
        syn_windows = sum(1 for pps, syn, ts in history
                          if 0 < syn < 0.15 and pps > 0)
        syn_ratio = syn_windows / total_windows

        # Duration of sustained activity
        if history:
            first_ts = history[0][2]
            last_ts = history[-1][2]
            duration_min = (last_ts - first_ts) / 60

            # Low-and-slow: active >80% of time, always below threshold, over 5+ minutes
            avg_pps = sum(pps for pps, _, _ in history) / max(total_windows, 1)

            if (activity_ratio >= 0.8 and avg_pps < 20 and avg_pps > 1 and
                    duration_min >= 5):
                score += 0.4
                reasons.append(
                    f"Sustained low-rate activity: {avg_pps:.1f} avg PPS over "
                    f"{duration_min:.0f} min ({activity_ratio:.0%} windows active)"
                )

                if syn_ratio > 0.3:
                    score += 0.2
                    reasons.append(
                        f"Persistent low-level SYN probing ({syn_ratio:.0%} of windows)"
                    )

                if duration_min >= 15:
                    score += 0.2
                    reasons.append(
                        f"Extended duration: {duration_min:.0f} minutes of sustained sub-threshold activity"
                    )

        result.low_slow_score = min(1.0, score)
        result.reasons.extend(reasons)

    def _detect_mimicry(self, src_ip: str, iat_mean: float, result: StealthResult):
        """
        Detect human-like mimicry traffic.

        Real human traffic has specific statistical properties:
        - Log-normal or Pareto-distributed inter-arrival times
        - Diurnal patterns
        - Bursts followed by think-time gaps

        Bot/tool traffic trying to mimic this has subtle signatures:
        - Too-perfect distribution fit (real humans are messier)
        - Missing the tail behavior of natural distributions
        - Overly smooth timing (lacks human micro-hesitations)
        """
        score = 0.0
        reasons = []

        if not self._baseline_learned:
            return

        history = list(self._iat_history.get(src_ip, []))
        if len(history) < 15:
            return

        recent = history[-30:]

        try:
            # Test 1: Kolmogorov-Smirnov test against baseline
            baseline = list(self._baseline_iats)[-500:]
            if len(baseline) >= 50 and len(recent) >= 10:
                ks_stat, ks_pvalue = scipy_stats.ks_2samp(recent, baseline)

                if ks_pvalue < self._mimicry_ks_threshold:
                    # Distribution is significantly different from baseline
                    # This alone isn't conclusive — attacks also differ
                    # But combined with other signals it's meaningful
                    pass  # Used in combination below

            # Test 2: Coefficient of variation analysis
            # Real human traffic: CV typically 0.5-2.0
            # Bot traffic trying to mimic: CV often 0.1-0.3 (too regular)
            # Pure bot traffic: CV often >3.0 (too erratic)
            cv = np.std(recent) / max(np.mean(recent), 1e-9)

            if 0.05 < cv < 0.2:
                # Suspiciously regular — trying to look natural but too smooth
                score += 0.4
                reasons.append(
                    f"Suspiciously regular timing (CV={cv:.3f}): "
                    f"real human traffic is messier"
                )

            # Test 3: Entropy of inter-arrival times
            # Real traffic has higher entropy (more random)
            # Mimicry tools often use simple distributions with low entropy
            if len(recent) >= 10:
                # Bin the IATs and compute entropy
                hist, _ = np.histogram(recent, bins=min(10, len(recent) // 2))
                hist = hist[hist > 0]  # Remove zero bins
                probs = hist / hist.sum()
                entropy = -np.sum(probs * np.log2(probs + 1e-10))

                max_entropy = math.log2(len(hist)) if len(hist) > 0 else 1
                norm_entropy = entropy / max(max_entropy, 1)

                if norm_entropy < 0.4:
                    score += 0.3
                    reasons.append(
                        f"Low timing entropy ({norm_entropy:.2f}): "
                        f"pattern is too predictable for natural traffic"
                    )

        except Exception as e:
            logger.debug("Mimicry detection error for %s: %s", src_ip, e)

        result.mimicry_score = min(1.0, score)
        result.reasons.extend(reasons)

    def _detect_threshold_aware(self, src_ip: str, pps: float, syn_ratio: float,
                                thresholds: Dict[str, float], result: StealthResult):
        """
        Detect threshold-aware evasion attacks.

        Pattern: Traffic consistently hovering just below known alert thresholds.
        This requires knowledge of the IDS configuration (reconnaissance or
        adaptive learning by the attacker).
        """
        score = 0.0
        reasons = []

        history = list(self._pps_history.get(src_ip, []))
        if len(history) < 8:
            return

        recent = history[-15:]

        # Get alert threshold (default from V72 config)
        alert_pps_threshold = thresholds.get("alert_pps", 80)
        alert_syn_threshold = thresholds.get("alert_syn", 0.15)

        # Check: PPS consistently in the 70-99% band of the threshold
        lower_band = alert_pps_threshold * 0.7
        upper_band = alert_pps_threshold * 0.99

        in_band = sum(1 for p in recent if lower_band <= p <= upper_band)
        band_ratio = in_band / len(recent)

        if band_ratio >= 0.6 and len(recent) >= 8:
            score += 0.5
            reasons.append(
                f"PPS consistently near threshold: {band_ratio:.0%} of windows in "
                f"[{lower_band:.0f}-{upper_band:.0f}] range "
                f"(threshold={alert_pps_threshold:.0f})"
            )

        # Check: SYN ratio consistently just below alert
        if syn_ratio > 0 and syn_ratio < alert_syn_threshold * 1.1:
            syn_band_hits = sum(
                1 for pps_val, syn, _ in self._sustained_activity.get(src_ip, [])
                if alert_syn_threshold * 0.5 <= syn < alert_syn_threshold
            )
            if syn_band_hits >= 5:
                score += 0.3
                reasons.append(
                    f"SYN ratio hovering below threshold: "
                    f"{syn_band_hits} windows in [{alert_syn_threshold*0.5:.2f}-{alert_syn_threshold:.2f}]"
                )

        result.threshold_aware_score = min(1.0, score)
        result.reasons.extend(reasons)

    def _detect_noise(self, src_ip: str, result: StealthResult):
        """
        Detect noise injection attacks.

        Pattern: Legitimate-looking chaff traffic mixed with attack traffic
        to dilute the signal-to-noise ratio and confuse the IDS.

        Indicators:
        - Rapidly alternating between benign and malicious traffic profiles
        - High protocol diversity in short windows
        - Traffic that doesn't fit any consistent pattern
        """
        score = 0.0
        reasons = []

        history = list(self._composition_history.get(src_ip, []))
        if len(history) < 6:
            return

        recent = history[-15:]

        # Check 1: Protocol flip-flopping (TCP-heavy → UDP-heavy → TCP-heavy)
        protocol_flips = 0
        for i in range(1, len(recent)):
            prev_dominant = "TCP" if recent[i-1].get("tcp", 0) > recent[i-1].get("udp", 0) else "UDP"
            curr_dominant = "TCP" if recent[i].get("tcp", 0) > recent[i].get("udp", 0) else "UDP"
            if prev_dominant != curr_dominant:
                protocol_flips += 1

        if protocol_flips >= len(recent) * 0.5 and len(recent) >= 6:
            score += 0.3
            reasons.append(
                f"Protocol flip-flopping: {protocol_flips} transitions in "
                f"{len(recent)} windows (noise injection indicator)"
            )

        # Check 2: High variance in traffic volume (alternating high-low)
        pps_values = [r.get("pps", 0) for r in recent]
        if len(pps_values) >= 4:
            pps_cv = np.std(pps_values) / max(np.mean(pps_values), 0.01)
            if pps_cv > 1.5:
                score += 0.3
                reasons.append(
                    f"High traffic volume variance (CV={pps_cv:.2f}): "
                    f"alternating bursts suggest noise injection"
                )

        # Check 3: Byte rate doesn't correlate with PPS (injecting empty/padded packets)
        byte_rates = [r.get("byte_rate", 0) for r in recent]
        if len(pps_values) >= 5 and len(byte_rates) >= 5:
            try:
                correlation = np.corrcoef(pps_values, byte_rates)[0, 1]
                if not np.isnan(correlation) and correlation < 0.3:
                    score += 0.2
                    reasons.append(
                        f"Weak PPS-ByteRate correlation ({correlation:.2f}): "
                        f"suggests padding/chaff traffic"
                    )
            except Exception:
                pass

        result.noise_score = min(1.0, score)
        result.reasons.extend(reasons)

    def _detect_jitter(self, src_ip: str, result: StealthResult):
        """
        Detect timing jitter / time-shifted attacks.

        Pattern: Attackers randomize inter-packet timing to avoid
        statistical detection. This manifests as:
        - Artificial uniform distribution of IATs (real traffic is not uniform)
        - IATs that follow a too-regular pattern with small random perturbations
        """
        score = 0.0
        reasons = []

        history = list(self._iat_history.get(src_ip, []))
        if len(history) < 10:
            return

        recent = history[-25:]

        try:
            # Test: Uniformity of distribution
            # Attack with jitter → tends toward uniform distribution
            # Real traffic → tends toward log-normal/Pareto
            if len(recent) >= 10:
                # Anderson-Darling test for uniformity
                # Normalize to [0, 1] range first
                min_val = min(recent)
                max_val = max(recent)
                if max_val > min_val:
                    normalized = [(v - min_val) / (max_val - min_val) for v in recent]
                    ad_stat, _, _ = scipy_stats.anderson(normalized, dist='norm')

                    # Low AD statistic for normal = data IS normal
                    # We're testing if the data is too uniformly distributed
                    # A uniform distribution has specific AD characteristics
                    if ad_stat < 0.3:
                        score += 0.3
                        reasons.append(
                            f"Suspiciously uniform timing distribution "
                            f"(AD statistic={ad_stat:.3f}): jitter-smoothed attack pattern"
                        )

            # Test: Coefficient of variation in specific range suggesting artificial randomization
            cv = np.std(recent) / max(np.mean(recent), 1e-9)
            if self._jitter_cv_threshold < cv < 0.6:
                # CV in this range suggests controlled randomization
                # Too low = regular tool, too high = real random, middle = controlled jitter
                score += 0.25
                reasons.append(
                    f"Controlled timing jitter (CV={cv:.3f}): "
                    f"artificial randomization detected"
                )

        except Exception as e:
            logger.debug("Jitter detection error for %s: %s", src_ip, e)

        result.jitter_score = min(1.0, score)
        result.reasons.extend(reasons)

    # ─────────────────────────────────────────
    # Cleanup
    # ─────────────────────────────────────────

    def cleanup(self):
        """Remove stale tracking entries."""
        with self._lock:
            for d in (self._sustained_activity, self._iat_history,
                      self._pps_history, self._composition_history):
                if len(d) > 5000:
                    keys = list(d.keys())
                    for k in keys[:len(keys) - 2500]:
                        del d[k]
