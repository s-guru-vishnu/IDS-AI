"""
V72 Dynamic Baseline Test Suite
Validates that the new PPS baseline logic eliminates false positives
while maintaining robust DDoS detection.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'DDoS-engine'))
from decision_engine import DecisionEngine

def test_scenario(engine, name, **kwargs):
    result = engine.evaluate(
        xgb_score=kwargs.get('xgb', 0.1),
        if_anomaly=kwargs.get('if_anom', False),
        ae_mse=0.0, ae_baseline=1.0, spike_zscore=0.0,
        syn_ratio=kwargs.get('syn', 0.0),
        pps=kwargs.get('pps', 0.0),
        ip_address=kwargs.get('ip', '10.0.0.1'),
        dst_ip=kwargs.get('dst', '192.168.1.100'),
        byte_rate=kwargs.get('byte_rate', 1000),
        connection_flag=kwargs.get('flag', 'SF'),
        mitm_risk=kwargs.get('mitm', 0.0),
        unique_src_ips=kwargs.get('src_ips', 1),
        waf_threat=kwargs.get('waf', False),
    )
    print(f"  [{result['decision'].upper():>8}] {name}")
    print(f"           Risk={result.get('risk_score',0):.3f} Engine={result.get('engine_rating',0):.2f} "
          f"Model={result.get('model_rating',0):.2f} PPS_Ratio={result.get('pps_ratio', 0):.2f} "
          f"Baseline={result.get('pps_baseline', 0):.1f}")
    return result

print("=" * 70)
print("V72 DYNAMIC BASELINE VALIDATION TEST")
print("=" * 70)

# =============================================
# TEST 1: CDN / Streaming — MUST NOT BLOCK
# =============================================
print("\n--- TEST 1: CDN/Streaming High PPS (MUST ALLOW) ---")
cdn = DecisionEngine(eval_mode=False)
# Simulate 5 windows of stable 130 PPS (builds baseline)
for i in range(5):
    r = test_scenario(cdn, f"CDN Window {i+1}: 130 PPS, SYN=0.01, clean",
                      ip='203.0.113.50', pps=130, syn=0.01, flag='SF')
# Window 6: same traffic — should be ALLOW (baseline ~130)
r = test_scenario(cdn, f"CDN Window 6: 130 PPS (at baseline)", 
                  ip='203.0.113.50', pps=130, syn=0.01, flag='SF')
assert r['decision'] == 'allow', f"FAIL: CDN at baseline should ALLOW, got {r['decision']}"
print("  ✅ CDN at stable 130 PPS correctly ALLOWED")

# =============================================
# TEST 2: CDN Spike — should NOT auto-block
# =============================================
print("\n--- TEST 2: CDN Temporary Spike (MUST NOT BLOCK) ---")
# Sudden spike to 300 PPS but still clean SYN
r = test_scenario(cdn, f"CDN Spike: 300 PPS, SYN=0.02, clean",
                  ip='203.0.113.50', pps=300, syn=0.02, flag='SF')
assert r['decision'] != 'block', f"FAIL: Clean CDN spike should NOT block, got {r['decision']}"
print(f"  ✅ CDN spike to 300 PPS correctly NOT blocked (decision: {r['decision']})")

# =============================================
# TEST 3: Real DDoS Attack — MUST BLOCK
# =============================================
print("\n--- TEST 3: DDoS Attack (MUST BLOCK) ---")
attacker = DecisionEngine(eval_mode=False)
# First window: new IP appears with high SYN flood
r = test_scenario(attacker, "Attack Window 1: 150 PPS, SYN=0.6, non-SF",
                  ip='45.33.32.1', pps=150, syn=0.6, flag='S0', xgb=0.85)
# Second window: sustained attack
r = test_scenario(attacker, "Attack Window 2: 180 PPS, SYN=0.7, non-SF",
                  ip='45.33.32.1', pps=180, syn=0.7, flag='S0', xgb=0.9)
assert r['decision'] == 'block', f"FAIL: DDoS attack should BLOCK, got {r['decision']}"
print("  ✅ DDoS attack correctly BLOCKED")

# =============================================
# TEST 4: Low-rate SYN flood — should detect
# =============================================
print("\n--- TEST 4: Low-Rate SYN Flood (should alert/throttle) ---")
stealth = DecisionEngine(eval_mode=False)
last_detected = None
for i in range(4):
    r = test_scenario(stealth, f"Stealth Window {i+1}: 25 PPS, SYN=0.35",
                      ip='10.0.0.99', pps=25, syn=0.35, flag='S0', xgb=0.4)
    # Track the last non-cooldown result
    if r['decision'] != 'allow' or r.get('risk_score', 0) > 0.1:
        last_detected = r
assert last_detected is not None and last_detected['decision'] in ('alert', 'throttle', 'block'), \
    f"FAIL: Low-rate SYN flood should detect, got {last_detected}"
print(f"  ✅ Low-rate SYN flood correctly detected (decision: {last_detected['decision']})")

# =============================================
# TEST 5: Old behavior regression — PPS=120 alone should NOT block
# =============================================
print("\n--- TEST 5: Regression: PPS=120 alone MUST NOT BLOCK ---")
reg = DecisionEngine(eval_mode=False)
r = test_scenario(reg, "PPS=120, SYN=0.02, clean SF, low ML",
                  ip='172.16.0.50', pps=120, syn=0.02, flag='SF', xgb=0.1)
assert r['decision'] != 'block', \
    f"REGRESSION FAIL: PPS=120 with clean traffic should NOT block, got {r['decision']}"
print(f"  ✅ PPS=120 with clean traffic correctly NOT blocked (decision: {r['decision']})")

# =============================================
# TEST 6: MITM-only attack — should still detect
# =============================================
print("\n--- TEST 6: MITM-only Attack (should alert even at low PPS) ---")
mitm = DecisionEngine(eval_mode=False)
# First window with moderate MITM
r1 = test_scenario(mitm, "MITM: PPS=5, SYN=0, MITM_risk=0.7",
                  ip='192.168.1.5', pps=5, syn=0.0, mitm=0.7)
# Second window with high MITM (builds confidence)
r2 = test_scenario(mitm, "MITM: PPS=5, SYN=0, MITM_risk=0.85",
                  ip='192.168.1.5', pps=5, syn=0.0, mitm=0.85)
assert r2['decision'] != 'allow' or r2['risk_score'] > 0.15, \
    f"FAIL: MITM attack should be detected, got decision={r2['decision']}, risk={r2['risk_score']}"
print(f"  ✅ MITM-only attack detected (decision: {r2['decision']}, risk: {r2['risk_score']:.3f})")

# =============================================
# TEST 7: Sustained spike without signature → THROTTLE (not BLOCK)
# =============================================
print("\n--- TEST 7: Sustained Clean Spike → THROTTLE ---")
sustained = DecisionEngine(eval_mode=False)
# Build baseline at 20 PPS
for i in range(3):
    test_scenario(sustained, f"Baseline {i+1}: 20 PPS",
                  ip='10.1.1.1', pps=20, syn=0.01, flag='SF')
# Now spike to 200 PPS (10x baseline) but clean — sustained 4+ windows
for i in range(5):
    r = test_scenario(sustained, f"Spike Window {i+1}: 200 PPS, clean",
                      ip='10.1.1.1', pps=200, syn=0.03, flag='SF')
# After sustained spike without attack signature, should cap at throttle max
assert r['decision'] != 'block', \
    f"FAIL: Sustained clean spike should NOT block, got {r['decision']}"
print(f"  ✅ Sustained clean spike correctly capped (decision: {r['decision']})")

print("\n" + "=" * 70)
print("ALL TESTS PASSED ✅")
print("=" * 70)
