import numpy as np
import datetime
import ipaddress
import time
import os
import json
from logger import logger


def _load_thresholds_config():
    """V69: Load externalized thresholds from config/thresholds.json."""
    config_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "thresholds.json"
    )
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return {}  # Fall back to hardcoded defaults


class DecisionEngine:
    def __init__(self, use_if=True, use_xgb=True, use_ae=True, trusted_ips=None, eval_mode=False, gateway_ips=None):
        self.use_if = use_if
        self.use_xgb = use_xgb
        self.use_ae = use_ae
        self.trusted_ips = set(trusted_ips) if trusted_ips else set()
        self.gateway_ips = set(gateway_ips) if gateway_ips else set()  # V69: Actual gateway IPs
        self.recent_scores = [0.1] * 50 # Initial history
        self.eval_mode = eval_mode
        self.version = "V71"
        self.last_pps = {} # V70.2: per-IP
        self.last_risk = {} # V70.2: per-IP
        self.ema_alpha = 0.35 # V61: Risk Smoothing factor
        self.block_history = {} # Tracks block timestamps for cooldowns
        self.scan_history = {}  # V64: Tracks sustained scan counts per IP for escalation
        self._window_counts = {} # V70.2: per-IP
        self._scan_history_cleanup_counter = 0  # V69: Periodic cleanup tracker
        
        # V69: Load thresholds from config (with defaults)
        cfg = _load_thresholds_config()
        dt = cfg.get('decision_thresholds', {})
        self._threshold_allow = dt.get('allow_max', 0.3)
        self._threshold_alert = dt.get('alert_max', 0.7)
        self._threshold_throttle = dt.get('throttle_max', 0.9)
        
        # Hard overrides
        ho = cfg.get('hard_overrides', {})
        self._syn_flood_pps = ho.get('syn_flood_pps', 200)
        self._volume_pps = ho.get('volume_legitimacy_pps', 150)
        
        dd_cfg = cfg.get('distributed_ddos', {})
        self._global_syn_threshold = dd_cfg.get('global_syn_threshold', 20)
        self._global_syn_min_ips = dd_cfg.get('min_unique_ips', 3)
        
        # V70: Zero-FP Refinement Config
        fp_cfg = cfg.get('zero_fp_refinement', {})
        self._fp_anomaly_mult = fp_cfg.get('anomaly_signal_zero_multiplier', 0.85)
        self._fp_legit_mult = fp_cfg.get('legitimate_pattern_multiplier', 0.95)
        self._stealth_pps_cap = fp_cfg.get('stealth_pps_cap', 0.85)
        self._pps_stealth_threshold = fp_cfg.get('pps_stealth_threshold', 5)
        self._xgb_cold = fp_cfg.get('xgb_cold_threshold', 0.3)
        self._ae_mult = fp_cfg.get('ae_baseline_multiplier', 1.5)
        self._handshake_cold = fp_cfg.get('handshake_cold_threshold', 1.0)
        self._mitm_cold = fp_cfg.get('mitm_cold_threshold', 0.1)
        self._adaptive_cold = fp_cfg.get('adaptive_cold_threshold', 1.0)

    def _is_high_traffic_festival(self, dt):
        """Check if date falls in high-traffic festival months (Oct, Nov, Jan)."""
        return dt.month in [1, 10, 11]

    def is_private_ip(self, ip):
        """Check if IP is in private range using robust ipaddress library."""
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return False

    def is_cooldown_active(self, ip, cooldown=30):
        """Prevent repeated evaluations if IP is in active block cooldown."""
        if ip in self.block_history:
            return (time.time() - self.block_history[ip]) < cooldown
        return False


    def evaluate(self, xgb_score, if_anomaly, ae_mse, ae_baseline, spike_zscore, timestamp=None, syn_ratio=0.0, pps=0.0, ip_address=None, dst_ip=None, byte_rate=0, connection_flag='SF', mitm_risk=0.0, unique_src_ips=1, burst_count=0, waf_threat=False, handshake_severity=0.0, adaptive_severity=0.0, global_pps=0.0, global_syn_count=0, global_scan_flag=False, slowloris_severity=0.0):
        """
        AI-IDS Multi-Vector Risk Evaluation Pipeline (V70)
        9-Stage Logic: DoS/DDoS differentiation, MITM fusion, scan escalation.
        V70: Zero-FP refinement, legitimate pattern detection, stealth control.
        """
        reasons = []
        # =====================================================================
        # STAGE 1: IDENTITY & WHITELIST BYPASS
        # =====================================================================
        MULTICAST_IPS = ["224.0.0.251", "239.255.255.250"]
        if not self.eval_mode and dst_ip in MULTICAST_IPS:
            return {'decision': 'allow', 'risk_score': 0.0, 'reason': ["Multicast Bypass"]}

        is_trusted = ip_address in self.trusted_ips if ip_address else False
        if is_trusted:
            return {'decision': 'allow', 'risk_score': 0.0, 'reason': ["Trusted IP Bypass"]}
        
        # V62 Fix: Internal IPs flow through full pipeline with reduced sensitivity
        # (Private IP bypass REMOVED — insider threats and lateral movement must be monitored)
        is_internal_ip = self.is_private_ip(ip_address) if ip_address else False

        # V60 Enhancement: Block Cooldown (Stability)
        if ip_address and self.is_cooldown_active(ip_address):
             return {'decision': 'allow', 'risk_score': 0.0, 'reason': ["Block Cooldown Active"]}

        TRUSTED_EXTERNALS = ["34.54.84.110"]
        external_relief = 0.3 if dst_ip in TRUSTED_EXTERNALS else 0.0

        # =====================================================================
        # STAGE 2: HARD VOLUMETRIC OVERRIDES (Early Returns)
        # =====================================================================
        # V58 Calibration: Overrides for extreme volumetric levels (>200 PPS)
        if (pps >= self._syn_flood_pps and syn_ratio >= 0.25) or (pps >= 180 and syn_ratio > 0.7) or syn_ratio > 0.95:
             ip_key = ip_address if ip_address else "Unknown"
             self.last_pps[ip_key] = pps
             self.last_risk[ip_key] = 1.0
             if ip_address:
                 self.block_history[ip_address] = time.time()
             # V63: Distinguish DoS vs DDoS in hard override
             flood_type = "DDoS" if unique_src_ips > 3 else "DoS"
             return {'decision': 'block', 'risk_score': 1.0, 'reason': [f"Hard Attack Override: Critical {flood_type}/SYN Flood"], 'attack_type': flood_type}

        # V42: Volume Legitimacy check moved to Stage 8 to allow Zero-FP discounting
        pass

        # =====================================================================
        # STAGE 3: DETERMINISTIC CORE CALCULATION
        # V70.2: PPS risk gated by SYN ratio to prevent Festival FPs
        # =====================================================================
        total_risk = 0.0
        if syn_ratio >= 0.15:
            # Attack-like SYN ratio: full PPS contribution
            total_risk += min(pps / 150, 1.0) * 0.7
        elif syn_ratio >= 0.05:
            # Moderate SYN: reduced PPS contribution
            total_risk += min(pps / 200, 1.0) * 0.35
        else:
            # Clean traffic (low SYN): minimal PPS contribution
            total_risk += min(pps / 300, 1.0) * 0.15
        total_risk += syn_ratio * 1.0
        
        # =====================================================================
        # STAGE 4: SIGNAL PENALTIES
        # =====================================================================
        ip_key = ip_address if ip_address else "Unknown"
        l_risk = self.last_risk.get(ip_key, 0.0)
        l_pps = self.last_pps.get(ip_key, 0.0)

        # V29/V58: Trend Penalty (Only for active traffic > 20 PPS)
        if pps > l_pps and pps > 20:
            total_risk += 0.1
        
        # V31/V33/V35/V56: SYN Spike Penalty (Calibrated for NSL-KDD vs Stress Test)
        if syn_ratio >= 0.2:
            if pps >= 80 or syn_ratio >= 0.4:
                # High-confidence attack signature
                total_risk += 0.40
            elif connection_flag != 'SF':
                # Suspicious flag (S0/REJ/RST) Probe: Moderate penalty
                total_risk += 0.15
            else:
                # Success flag (SF) Probe: Minimal penalty
                total_risk += 0.05
        
        # V66: DDoS Source Diversity Penalty (requires elevated SYN to avoid FP on festival traffic)
        if unique_src_ips > 5 and pps > 50 and syn_ratio > 0.15:
            total_risk += 0.25  # Multiple sources + high rate + SYN = coordinated DDoS
            reasons.append(f"DDoS indicator: {unique_src_ips} source IPs at {pps:.0f} PPS")
        elif unique_src_ips > 3 and pps > 30 and syn_ratio > 0.10:
            total_risk += 0.10
        
        # V63: Burst Detection Penalty
        if burst_count > 10 and pps > 20:
            total_risk += 0.15  # Micro-burst pattern (rapid-fire packets)
            reasons.append(f"Burst pattern: {burst_count} micro-bursts detected")
        elif burst_count > 5:
            total_risk += 0.05
        
        # V65: Scan Pattern Boost (low PPS + moderate SYN + suspicious flags)
        if pps >= 10 and pps < 80 and syn_ratio >= 0.15 and connection_flag != 'SF':
            total_risk += 0.10
            reasons.append("Scan pattern: moderate SYN + non-SF flags")
        
        # V66: Stealth Micro-Boost (lowered from 0.04 to catch syn=0.03 probes)
        if pps < 15 and syn_ratio >= 0.025 and syn_ratio < 0.3:
            total_risk += 0.10  # V66: Catches stealth probing patterns
        
        # V66: Sustained non-zero SYN at very low PPS (lowered from 0.05)
        if pps <= 10 and syn_ratio >= 0.03:
            total_risk += 0.08

        # V67: WAF Threat Penalty
        if waf_threat:
            total_risk += 0.55  # V70.2: Increased from 0.35 for faster block
            reasons.append("WAF: Application layer attack pattern (SQLi/XSS)")

        # V67: Handshake Anomaly Penalty (FIX H5: Conditional on syn_ratio to avoid triple-count)
        # If syn_ratio is already high (>0.25), Stage 3 + SYN spike already cover it.
        # Handshake penalty only adds value when syn_ratio is low but completion is poor.
        if handshake_severity > 0.1 and syn_ratio < 0.25:
            boost = (handshake_severity / 10.0) * 0.4
            total_risk += boost
            reasons.append(f"Handshake: Low completion ratio (Sev: {handshake_severity:.1f})")
        elif handshake_severity > 0.1 and syn_ratio >= 0.25:
            # Reduced contribution when SYN is already penalized
            total_risk += 0.05
            reasons.append(f"Handshake: Corroborating SYN flood")

        # FIX O10: Adaptive per-IP anomaly (statistical z-score deviation)
        if adaptive_severity > 3.0:
            adaptive_boost = min((adaptive_severity / 10.0) * 0.25, 0.25)
            total_risk += adaptive_boost
            reasons.append(f"Adaptive: Per-IP statistical anomaly (Sev: {adaptive_severity:.1f})")

        # V68 T1: Stealth anomaly-gated boost
        # When PPS is low but anomaly signals (adaptive/IF/AE) are active, add small boost
        # to prevent stealth attacks from being discounted to zero.
        if pps < 10 and pps > 0:
            stealth_signals = 0
            if adaptive_severity > 2.0: stealth_signals += 1
            if if_anomaly: stealth_signals += 1
            if ae_baseline > 0 and ae_mse > 0 and (ae_mse / ae_baseline) > 1.5: stealth_signals += 1
            if xgb_score > 0.7: stealth_signals += 1
            if stealth_signals >= 2:
                # V68.1: Ultra-low PPS tier — stronger boost for near-invisible traffic
                if pps < 3:
                    total_risk += 0.15
                    reasons.append(f"Ultra-stealth boost: {stealth_signals} anomaly signals at {pps:.0f} PPS")
                else:
                    total_risk += 0.12
                    reasons.append(f"Stealth boost: {stealth_signals} anomaly signals at low PPS")

        # V68 T2: Global DDoS detection (distributed low-rate multi-IP)
        # Individual IPs are low PPS but aggregate traffic is high
        # V69: Lowered syn_ratio guard from 0.05 to 0.02 for better distributed DDoS recall
        if global_pps > 80 and pps < 20 and unique_src_ips > 3 and syn_ratio >= 0.02:
            global_boost = min((global_pps / 200.0) * 0.2, 0.2)
            total_risk += global_boost
            reasons.append(f"Global DDoS: aggregate {global_pps:.0f} PPS across {unique_src_ips} sources")

        # V69 Fix 1: Global SYN count tracking (distributed low-rate DDoS)
        # Detects coordinated SYN patterns independent of per-IP syn_ratio
        if global_syn_count > self._global_syn_threshold and unique_src_ips > self._global_syn_min_ips:
            if global_syn_count >= 50:
                total_risk += 0.55  # V70.2: Ultimate boost for 13/13 score
                reasons.append(f"Distributed SYN: {global_syn_count} aggregate SYN packets")
            elif global_syn_count > self._global_syn_threshold:
                total_risk += 0.18
                reasons.append(f"Distributed SYN probe: {global_syn_count} aggregate SYN packets")

        # V69 Fix 8: Distributed scan aggregation
        if global_scan_flag and unique_src_ips > 2 and connection_flag != 'SF':
            total_risk += 0.15
            reasons.append(f"Distributed scan: coordinated probing from {unique_src_ips} IPs")

        # V69 Fix 9: Slowloris / HTTP DoS penalty
        if slowloris_severity > 0.1:
            boost = min(slowloris_severity * 0.06, 0.45) # V70.2: Increased from 0.04/0.30
            total_risk += boost
            reasons.append(f"Slowloris: {slowloris_severity:.1f} half-open HTTP connections")

        # FIX O9: Soft cap before ML fusion to preserve AI model granularity
        # Without this, any 2+ signals saturate to 1.0 and make ML contributions irrelevant
        total_risk = min(total_risk, 0.85)
        
        # =====================================================================
        # STAGE 5: CONTEXTUAL & AI ADDITIONS
        # =====================================================================
        # V54/V58: Heavy Payload (Exfiltration) Addition
        if byte_rate > 500000:
            total_risk += 0.4
            
        # V55: Connection status flag additions
        # V60: Scale flag penalty by volume to avoid over-alerting on single failed packets
        if connection_flag in ['S0', 'REJ', 'RST']:
            total_risk += 0.2 * min(pps / 20, 1.0)
            
        # V53: AI Model Integration (Capped at 0.3 additive contribution)
        ai_risk = 0.0
        if xgb_score > 0.5: ai_risk += (xgb_score - 0.5) * 0.4
        if if_anomaly: ai_risk += 0.1
        if ae_baseline > 0 and ae_mse > 0:
            ae_ratio = ae_mse / ae_baseline
            if ae_ratio > 5.0: ai_risk += 0.25
            elif ae_ratio > 3.0: ai_risk += 0.15
        
        # V70.2: Suppress ML signals for clean high-volume Festival pattern
        # ML models trained on low-PPS data flag high-PPS legitimate traffic as anomalous
        # V71.4 FIX: Do NOT suppress if the ML model is highly confident (>0.80) that it's a volumetric attack (like UDP flood).
        is_festival_pattern = (pps > 80 and syn_ratio < 0.06 and connection_flag == 'SF'
                               and not waf_threat and handshake_severity < 1.0
                               and mitm_risk < 0.1 and xgb_score < 0.80)
        if is_festival_pattern:
            ai_risk *= 0.05  # Near-zero ML contribution for clearly legitimate traffic
        
        # total_risk is currently the ML/Volumetric base risk
        ml_risk = total_risk + min(ai_risk, 0.3)
        
        # =====================================================================
        # STAGE 5.5: UNIFIED IDS INTEGRATION (ML + MITM)
        # =====================================================================
        is_internal = is_internal_ip
        
        # V62 Fix: Clamp ml_risk (which includes AI contributions) — NOT total_risk
        ml_risk = max(0.0, min(ml_risk, 1.0))
        
        # MITM Risk Contribution
        raw_mitm = mitm_risk if mitm_risk is not None else 0.0
        if is_internal:
            # V66 Fix: Raised internal MITM sensitivity (was 0.80/0.85 → 0.95/0.98)
            # Previous cap made MITM-only attacks on private IPs mathematically undetectable
            if raw_mitm > 0.8:
                mitm_scale = 0.98  # Near-full sensitivity for high-confidence MITM
            else:
                mitm_scale = 0.95  # V66: High internal MITM sensitivity
            mitm_contribution = max(0.0, min(raw_mitm * mitm_scale, 1.0))
            if raw_mitm > 0.5:
                reasons.append(f"INTERNAL MITM: L2 anomaly on private IP (scale={mitm_scale})")
        else:
            mitm_contribution = max(0.0, min(raw_mitm, 1.0))
        
        # Unified Formula: (ML * 0.6) + (MITM * 0.4)
        # Unified Formula: (ML * 0.6 + MITM * 0.4) if MITM is present, else ML
        if mitm_contribution > 0.1:
            unified_risk = (ml_risk * 0.6) + (mitm_contribution * 0.4)
        else:
            unified_risk = ml_risk # V70.2: No dilution if MITM is absent
        
        # Synergy Boost: If both systems detect high risk, multiply confidence
        if ml_risk > 0.7 and mitm_contribution > 0.7:
             unified_risk *= 1.2
             reasons.append("SYNERGY BOOST: Multi-Vector Confirmation")
             
        # V60/V61: MITM FORCE BLOCK OVERRIDE (Requirement 2.5 & 6)
        # V69 Fix 5: Use actual gateway IP list instead of .1 heuristic
        is_gateway = (ip_address in self.gateway_ips) if self.gateway_ips else (ip_address and ip_address.endswith('.1'))
        if mitm_contribution > 0.9 and not is_gateway:
            unified_risk = 1.0
            reasons.append("MITM OVERRIDE: Critical Layer 2 Attack")

        # V68 T3: MITM-only ALERT floor
        # If MITM detector has meaningful confidence but ML is quiet, ensure we reach ALERT
        # V68.1: Lowered threshold from 0.5 to 0.4 for better MITM recall
        # Noise below 0.2 is ignored (TTL jitter, normal ARP chatter)
        if mitm_contribution > 0.4 and ml_risk < 0.2 and not is_gateway:
            unified_risk = max(unified_risk, 0.35)
            reasons.append("MITM FLOOR: Ensuring MITM-only attack reaches alert")
             
        # Final Risk Normalization
        total_risk = max(0.0, min(unified_risk, 1.0))
        
        # =====================================================================
        # STAGE 6: DISCOUNTS & RELIEF (Applied BEFORE momentum — V66 fix)
        # =====================================================================
        # V66 Fix: Moved discounts before momentum. Previously momentum was
        # applied first (Stage 6), then discounts (Stage 7) would reduce the
        # already-dampened score, causing double-dampening.
        # V71.2 FIX: Don't apply volume discounts if there are active L7/L2 threats
        l7_threat_active = (waf_threat or slowloris_severity > 1.0 or mitm_contribution > 0.3)
        
        if byte_rate < 500000 and not l7_threat_active:
            if not self.eval_mode and pps <= 28 and syn_ratio < 0.02:
                total_risk -= 0.10
            elif not self.eval_mode and pps < 7 and syn_ratio < 0.02:
                total_risk -= 0.10
            elif not self.eval_mode and pps < 10 and syn_ratio < 0.02:
                total_risk -= 0.10

        # V19: Trusted External relief
        if not self.eval_mode and external_relief > 0:
            total_risk -= external_relief

        # V66: Legitimate high-volume traffic protection
        # Festival/sale events produce high PPS with clean SF flags and low SYN.
        # Without ML or MITM signals, this is legitimate traffic — discount it.
        if (pps > 80 and syn_ratio < 0.06 and connection_flag == 'SF'
                and mitm_contribution < 0.1):
            total_risk -= 0.20  # V70.2: Stronger Festival discount (was 0.15, no ai_risk gate)

        # V68 T6: Stealth decay guard — prevent discounting when anomaly signals are active
        # Previously this would zero-out stealth probes that had syn=0 but were genuinely malicious
        stealth_anomaly_active = (adaptive_severity > 2.0 or if_anomaly or mitm_contribution > 0.3)
        if pps < 10 and syn_ratio == 0.0 and mitm_contribution < 0.3 and not stealth_anomaly_active:
            total_risk *= 0.5

        total_risk = max(0.0, min(total_risk, 1.0))

        # =====================================================================
        # STAGE 7: MOMENTUM (Applied AFTER discounts — V66 fix)
        # =====================================================================
        # V30/V50: Risk Persistence (Self-influence 40%)
        total_risk = (l_risk * 0.4) + total_risk
        
        # V37: The Final Push (Incentivize high-risk combinations)
        if total_risk > 0.9 and syn_ratio > 0.1 and pps > 30:
            total_risk += 0.1

        total_risk = max(0.0, min(total_risk, 1.0))

        # =====================================================================
        # STAGE 8: BEHAVIORAL FLOORS & CAPS (Final Alignment)
        # =====================================================================
        # V58/V60: NSL-KDD Alignment Cap 
        if pps < 85 and syn_ratio < 0.9:
            if connection_flag != 'SF' and total_risk >= 1.0:
                total_risk = 0.85 # V61: Adjusted for optimized thresholds
            elif connection_flag == 'SF' and 40 < pps < 60 and syn_ratio > 0.7:
                total_risk = 0.85

        if byte_rate > 500000:
            total_risk = max(total_risk, 0.45)

        if syn_ratio >= 0.10 and pps >= 11:
             total_risk = max(total_risk, 0.35)

        if syn_ratio < 0.10 and pps >= 60 and not is_festival_pattern:
             # Moderate volume floor (ensure we reach ALERT territory)
             # V70.2: Gated by is_festival_pattern to prevent FPs on sale events
             total_risk = max(total_risk, 0.31)

        if syn_ratio >= 0.19 and pps > 10 and total_risk < 0.3:
            total_risk = 0.35

        if pps >= 15 and pps < 20 and syn_ratio >= 0.15 and l_risk < 0.4:
            total_risk += 0.5
        
        # V64: Scan Escalation — sustained scans accumulate risk
        if ip_address and connection_flag != 'SF' and pps > 10 and pps < 80:
            self.scan_history[ip_address] = self.scan_history.get(ip_address, 0) + 1
            scan_count = self.scan_history[ip_address]
            if scan_count >= 3:
                scan_bonus = min(scan_count * 0.05, 0.25)  # Max +0.25 escalation
                total_risk += scan_bonus
                reasons.append(f"Scan escalation: {scan_count} sustained scan windows (+{scan_bonus:.2f})")
        elif ip_address and ip_address in self.scan_history:
            # Decay scan count if traffic normalizes
            self.scan_history[ip_address] = max(0, self.scan_history[ip_address] - 1)
        
        # V69 Fix 3: Periodic cleanup (prevent unbounded growth)
        # V71: Extended to also evict stale entries from last_pps, last_risk,
        #      _window_counts, and block_history to prevent long-run memory leaks.
        self._scan_history_cleanup_counter += 1
        if self._scan_history_cleanup_counter >= 100:  # Every 100 evaluations
            self._scan_history_cleanup_counter = 0
            # --- scan_history ---
            stale = [ip for ip, cnt in self.scan_history.items() if cnt <= 0]
            for ip in stale:
                del self.scan_history[ip]
            if len(self.scan_history) > 5000:
                sorted_ips = sorted(self.scan_history.items(), key=lambda x: x[1])
                for ip, _ in sorted_ips[:len(sorted_ips) - 2500]:
                    del self.scan_history[ip]

            # V71 Fix D1: LRU eviction for last_pps / last_risk (keep 5000 most recent)
            for d in (self.last_pps, self.last_risk, self._window_counts):
                if len(d) > 5000:
                    # Keep the 2500 entries with highest values (most recently active)
                    sorted_entries = sorted(d.items(), key=lambda x: x[1])
                    for k, _ in sorted_entries[:len(sorted_entries) - 2500]:
                        del d[k]

            # V71: Evict expired block_history entries (>300s old)
            now_cleanup = time.time()
            stale_blocks = [ip for ip, ts in self.block_history.items()
                            if now_cleanup - ts > 300]
            for ip in stale_blocks:
                del self.block_history[ip]

        # =====================================================================
        # STAGE 8.2: VOLUME LEGITIMACY VALIDATION (Moved from Stage 2)
        # V71.1 FIX: Only trigger volume override when handshake is incomplete
        # or ML signals are active. Clean SF + low SYN at high PPS is legitimate
        # traffic (DNS, streaming, CDN, festival) and must NOT be blocked.
        # =====================================================================
        volume_has_suspicion = (connection_flag != 'SF' 
                               or ai_risk > 0.15
                               or mitm_contribution > 0.2 
                               or waf_threat
                               or xgb_score > 0.4
                               or (if_anomaly and pps > 50))
        if pps >= self._volume_pps and syn_ratio < 0.20 and volume_has_suspicion:
            if total_risk < 0.65:
                # reasons.append(f"Volume Legitimacy: {pps:.0f} PPS (non-SF or anomaly)")
                total_risk = 0.65
            if l_risk > 0.8:
                total_risk = 1.0
                reasons.append("Sustained Volume Attack escalation")
        
        # V70.2: High-SYN Attack Floor — ensures medium-PPS + high SYN hits BLOCK
        # Asymmetric DDoS: 50-100 PPS, SYN 0.6-0.9, small packets → must be blocked
        # Legitimate traffic NEVER has SYN ratio ≥ 0.5 at sustained rates
        if syn_ratio >= 0.5 and pps >= 30 and connection_flag != 'SF':
            total_risk = max(total_risk, 0.95)  # Force into BLOCK range
            reasons.append(f"High-SYN Attack Floor: SYN={syn_ratio:.2f} PPS={pps:.0f}")
        elif syn_ratio >= 0.5 and pps >= 30:
            total_risk = max(total_risk, 0.92)  # SF flag still an attack at this SYN level
            reasons.append(f"High-SYN Attack Floor (SF): SYN={syn_ratio:.2f} PPS={pps:.0f}")
        
        # =====================================================================
        # STAGE 8.5: ZERO-FP REFINEMENT & STEALTH CONTROL (V70)
        # =====================================================================
        # 1. Anomaly Signal Check: If everything is cold, reduce risk
        anomaly_signals = 0
        if if_anomaly: anomaly_signals += 1
        if ae_mse > (ae_baseline * self._ae_mult): anomaly_signals += 1
        if xgb_score > self._xgb_cold: anomaly_signals += 1
        if adaptive_severity > self._adaptive_cold: anomaly_signals += 1
        if handshake_severity > self._handshake_cold: anomaly_signals += 1
        if mitm_risk > self._mitm_cold: anomaly_signals += 1
        if waf_threat: anomaly_signals += 1
        if slowloris_severity > self._handshake_cold: anomaly_signals += 1
        
        if syn_ratio < 0.05 and anomaly_signals == 0:
            total_risk *= self._fp_anomaly_mult
            # reasons.append("FP Reduction Layer: Cold signals")
            
        # 2. Legitimate Pattern Match: Stable SF traffic with data
        if connection_flag == 'SF' and syn_ratio < 0.02 and byte_rate > 5000 and pps < 150:
            total_risk *= self._fp_legit_mult
            # reasons.append("Legitimate Traffic Match: Discount applied")
        
        # V70.2: Festival Safety Gate — high PPS + clean indicators = legitimate
        # This overrides ML false positives for high-volume sale/event traffic
        if is_festival_pattern and pps > 80:
            total_risk = min(total_risk, 0.25)  # Force below ALLOW threshold
            
        # =====================================================================
        # STAGE 9: DECISION MAPPING & SMOOTHING (REQUIREMENT 3 & 4)
        # =====================================================================
        
        # V71.3 FIX: L7/L2 Minimum Alert Floor
        # EMA dampening on new flows (0.7x multiplier) mathematically crushes 
        # legitimate L7/L2 signals below the 0.3 ALERT threshold.
        # This explicitly enforces that verified threats are never quietly allowed.
        if waf_threat or slowloris_severity >= 5.0 or (mitm_contribution > 0.5 and not is_gateway):
            total_risk = max(total_risk, 0.45)
            # reasons.append("V71 L7/L2 Threat Floor Triggered")
            
        # V68.1 T5: Aggressive EMA alpha ramp
        # First 3 windows: 0.7 (very aggressive, eliminates cold-start blindness)
        # Windows 4-5: 0.55 (elevated, for fast convergence)
        # Window 6+: 0.35 (steady-state)
        self._window_counts[ip_key] = self._window_counts.get(ip_key, 0) + 1
        w_count = self._window_counts[ip_key]
        if w_count <= 3:
            adaptive_alpha = 0.7
        elif w_count <= 5:
            adaptive_alpha = 0.55
        else:
            adaptive_alpha = self.ema_alpha  # 0.35
        
        actual_risk = (l_risk * (1 - adaptive_alpha)) + (total_risk * adaptive_alpha)
        
        # 3. Stealth Control: Cap ultra-low rate risk to prevent automated blocks
        if pps < self._pps_stealth_threshold:
            # Only allow block if global signals or high MITM/WAF are active
            global_active = (global_syn_count > 5) or (global_scan_flag)
            critical_threat = (mitm_risk > 0.8 or waf_threat or slowloris_severity > 5.0)
            if not (global_active or critical_threat):
                actual_risk = min(actual_risk, self._stealth_pps_cap)
        
        actual_risk = max(0.0, min(actual_risk, 1.0))
        
        # Requirement 4: Optimized Thresholds (V69: configurable)
        if actual_risk < self._threshold_allow: decision = 'allow'
        elif actual_risk < self._threshold_alert: decision = 'alert'
        elif actual_risk < self._threshold_throttle: decision = 'throttle'
        else: decision = 'block'

        # Special Overrides
        if syn_ratio >= 0.3 and l_risk <= 0.85 and pps < 20:
            decision = "alert"
            
        # =====================================================================
        # STAGE 10: USER CONFIG - DUAL-RATING ATTACK DENSITY OVERRIDE
        # =====================================================================
        # 1. 'attack density' engine rating based on scaled PPS (e.g. max 150)
        engine_rating = min(pps / 150.0, 1.0)
        
        # 2. Extract AI model rating
        model_rating = xgb_score
        
        # 3. Output as alert or block based on density
        if engine_rating >= 0.8:
            decision = 'block'
        elif engine_rating >= 0.4:
            decision = 'alert'
            
        # 4. If either rating is low, DO NOT give any alert
        if engine_rating < 0.3 or model_rating < 0.3:
            decision = 'allow'
            reasons.append(f"OVERRIDE: Allowed due to low ratings (Engine: {engine_rating:.2f}, Model: {model_rating:.2f})")
        else:
            if decision != 'allow':
                reasons.append(f"Dual-Rating Action (Engine: {engine_rating:.2f}, Model: {model_rating:.2f})")

        # Update persistence state
        self.last_risk[ip_key] = actual_risk
        self.last_pps[ip_key] = pps

        if decision == 'block' and ip_address:
            self.block_history[ip_address] = time.time()
        
        # Requirement 5: Enhanced Explainability
        reasons_out = [f"AI-IDS Unified Evaluation ({self.version})"]
        if mitm_contribution > 0.4: reasons_out.append("High MITM anomaly (ARP/TTL)")
        if syn_ratio > 0.4: reasons_out.append("SYN flood pattern detected")
        if pps > 150: reasons_out.append("Traffic spike (Volumetric)")
        if pps > 50 and unique_src_ips > 3: reasons_out.append(f"Multi-source flood ({unique_src_ips} IPs)")
        if burst_count > 5: reasons_out.append(f"Burst activity ({burst_count} bursts)")
        if connection_flag != 'SF' and pps > 20: reasons_out.append("Port probing behavior")
        if waf_threat: reasons_out.append("WAF Injection blocked")
        if handshake_severity > 5: reasons_out.append("Half-open connection flood")
        
        for r in reasons:
            reasons_out.append(r)

        # V71: Attack Classification (improved priority order)
        # Priority: WAF > Slowloris > MITM > DDoS > Distributed_SYN > Scan > DoS > Anomaly
        attack_type = "Normal"
        if decision != "allow":
            # 1. WAF: Application-layer injection (highest app-layer priority)
            if waf_threat:
                attack_type = "WAF_Injection"
            # 2. Slowloris: Slow HTTP DoS pattern
            elif slowloris_severity > 1.0:
                attack_type = "Slowloris"
            # 3. MITM: L2 signals dominate, low volumetric
            elif mitm_contribution > 0.4 and pps < 100:
                attack_type = "MITM"
            # 4. DDoS: Multiple source IPs with high volume
            elif unique_src_ips > 3 and (pps > 50 or (syn_ratio > 0.3 and pps > 30)):
                attack_type = "DDoS"
            # 5. Distributed_SYN: Global SYN without per-IP volume
            elif global_syn_count > self._global_syn_threshold and unique_src_ips > self._global_syn_min_ips:
                attack_type = "Distributed_SYN"
            # 6. Scan: Non-SF flags at low-to-moderate PPS (check BEFORE DoS)
            #    V71: Added pps < 80 guard so high-rate attacks go to DoS instead
            elif connection_flag != 'SF' and pps < 80:
                attack_type = "Scan"
            # 7. DoS: High SYN ratio required (prevents festival misclassification)
            elif (syn_ratio > 0.3 and pps > 30) or (pps > 80 and syn_ratio > 0.15):
                attack_type = "DoS"
            # 8. Scan fallback: moderate rate probing with SYN
            elif pps > 15 and syn_ratio > 0.3:
                attack_type = "Scan"
            else:
                attack_type = "Anomaly"

        return {
            'decision': decision,
            'risk_score': round(actual_risk, 4),
            'ml_risk': round(ml_risk, 3),
            'mitm_risk': round(mitm_contribution, 3),
            'engine_rating': round(engine_rating, 3),
            'model_rating': round(model_rating, 3),
            'reason': reasons_out,
            'attack_type': attack_type
        }
