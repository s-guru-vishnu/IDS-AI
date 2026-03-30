"""
benchmark_pipeline.py — Performance Benchmark for V3 10-Layer Flow-Based Pipeline
===================================================================================
Tests flow buffer, 10-layer processing, and outputs strict JSON.
"""

import sys
import time

sys.path.insert(0, '.')
sys.path.insert(0, 'DDoS-engine')

from security_pipeline import SecurityPipeline

p = SecurityPipeline()

# =========================================
# Pre-populate flow buffer with packets
# =========================================
print("=" * 64)
print("FLOW BUFFER: Ingesting packets into flow-based buffers")
print("=" * 64)

now = time.time()

# Simulate 50 benign packets from 10.0.0.50
for i in range(50):
    p.ingest_packet(
        src_ip="10.0.0.50", dst_ip="10.0.0.1",
        src_port=12345, dst_port=443, protocol="TCP",
        size=100 + (i % 10), flags="A", timestamp=now + i * 0.2
    )

# Simulate 200 attack packets from 192.168.1.100 (SYN flood)
for i in range(200):
    p.ingest_packet(
        src_ip="192.168.1.100", dst_ip="10.0.0.1",
        src_port=50000 + (i % 100), dst_port=80, protocol="TCP",
        size=60, flags="S", timestamp=now + i * 0.005
    )

buf_stats = p.flow_buffer.get_stats()
print(f"  Active flows: {buf_stats['active_flows']}")
print(f"  Total packets: {buf_stats['total_packets_ingested']}")
print(f"  Triggers: {buf_stats['total_triggers']}")
print()

# =========================================
# TEST 1: Attack flow (with buffer context)
# =========================================
print("=" * 64)
print("TEST 1: DDoS ATTACK (buffer-enriched, 10 layers)")
print("=" * 64)

r1 = p.process_flow(
    src_ip="192.168.1.100", dst_ip="10.0.0.1",
    src_port=50001, dst_port=80,
    features={"packet_rate": 200.0, "byte_rate": 12000.0, "avg_packet_size": 60.0,
              "std_packet_size": 0.0, "tcp_ratio": 1.0, "udp_ratio": 0.0,
              "syn_flag_ratio": 0.95, "ack_flag_ratio": 0.0, "iat_mean": 0.005,
              "iat_std": 0.001, "burst_count": 5.0, "connection_duration": 1.0},
    xgb_score=0.92, if_anomaly=True,
    decision_engine_result={"decision": "block", "risk_score": 0.92,
                             "attack_type": "DDoS", "ml_risk": 0.92,
                             "reason": ["SYN flood: 200 pps, 95% SYN ratio"]},
    mitm_risk=0.0, pps=200.0, syn_ratio=0.95, protocol="TCP",
)
t = r1.timing
print(f"  Flow ID:     {r1.flow_id}")
print(f"  Attack:      {r1.attack_type} | Action: {r1.action} | Risk: {r1.risk_level}")
print(f"  Buffer:      {r1.buffer_stats.to_dict()}")
print(f"  10-Layer Timing:")
print(f"    L1  Buffer/Capture:    {t.capture_time_ms:.4f} ms")
print(f"    L2  Feature Extract:   {t.feature_time_ms:.4f} ms")
print(f"    L3  Behavioral:        {t.behavior_time_ms:.4f} ms")
print(f"    L4  ML Ensemble:       {t.ml_time_ms:.4f} ms")
print(f"    L5  AI Attack Defense: {t.ai_defense_time_ms:.4f} ms")
print(f"    L6  Threat Intel:      {t.intelligence_time_ms:.4f} ms")
print(f"    L7  Correlation:       {t.correlation_time_ms:.4f} ms")
print(f"    L8  Zero-Day:          {t.zero_day_time_ms:.4f} ms")
print(f"    L9  Decision:          {t.decision_time_ms:.4f} ms")
print(f"    L10 Response:          {t.response_time_ms:.4f} ms")
print(f"    TOTAL DETECT:          {t.total_detection_time_ms:.4f} ms")
print(f"    TOTAL RESPONSE:        {t.total_response_time_ms:.4f} ms")
print(f"  Optimizations: {r1.optimization_applied}")
print()

# =========================================
# TEST 2: Benign flow (fast-path + trusted)
# =========================================
print("=" * 64)
print("TEST 2: BENIGN FLOW (fast-path, buffer-enriched)")
print("=" * 64)

r2 = p.process_flow(
    src_ip="10.0.0.50", dst_ip="10.0.0.1",
    src_port=12345, dst_port=443,
    features={"packet_rate": 5.0, "byte_rate": 500.0, "avg_packet_size": 100.0,
              "std_packet_size": 3.0, "tcp_ratio": 1.0, "udp_ratio": 0.0,
              "syn_flag_ratio": 0.02, "ack_flag_ratio": 0.5, "iat_mean": 0.2,
              "iat_std": 0.05, "burst_count": 0.0, "connection_duration": 10.0},
    xgb_score=0.03, if_anomaly=False,
    decision_engine_result={"decision": "allow", "risk_score": 0.03,
                             "attack_type": "Normal", "ml_risk": 0.03,
                             "reason": []},
    mitm_risk=0.0, pps=5.0, syn_ratio=0.02, protocol="TCP",
)
t2 = r2.timing
print(f"  Flow ID:     {r2.flow_id}")
print(f"  Attack:      {r2.attack_type} | Action: {r2.action} | Risk: {r2.risk_level}")
print(f"  TOTAL RESP:  {t2.total_response_time_ms:.4f} ms")
print(f"  Optimizations: {r2.optimization_applied}")
print()

# =========================================
# TEST 3: Strict JSON Output
# =========================================
print("=" * 64)
print("TEST 3: STRICT JSON OUTPUT (attack flow)")
print("=" * 64)
print(r1.to_json())
print()

# =========================================
# BENCHMARK: 100 flows throughput
# =========================================
print("=" * 64)
print("BENCHMARK: 100 flows (50 benign + 50 attack)")
print("=" * 64)

start = time.perf_counter_ns()
for i in range(50):
    p.process_flow(
        src_ip=f"10.0.0.{i+1}", dst_ip="10.0.0.1",
        features={"packet_rate": 3.0, "byte_rate": 300.0, "avg_packet_size": 100.0,
                  "tcp_ratio": 1.0, "syn_flag_ratio": 0.01,
                  "iat_mean": 0.3, "iat_std": 0.1, "burst_count": 0.0},
        xgb_score=0.03, if_anomaly=False,
        decision_engine_result={"decision": "allow", "risk_score": 0.03,
                                 "attack_type": "Normal", "reason": []},
        mitm_risk=0.0, pps=3.0, syn_ratio=0.01,
    )
for i in range(50):
    p.process_flow(
        src_ip=f"192.168.1.{i+1}", dst_ip="10.0.0.1",
        features={"packet_rate": 200.0, "byte_rate": 20000.0, "avg_packet_size": 60.0,
                  "tcp_ratio": 0.8, "syn_flag_ratio": 0.4,
                  "iat_mean": 0.005, "iat_std": 0.001, "burst_count": 5.0},
        xgb_score=0.9, if_anomaly=True,
        decision_engine_result={"decision": "block", "risk_score": 0.9,
                                 "attack_type": "DDoS", "reason": ["flood"]},
        mitm_risk=0.0, pps=200.0, syn_ratio=0.4,
    )
elapsed_ns = time.perf_counter_ns() - start
elapsed_ms = elapsed_ns / 1_000_000

stats = p.get_pipeline_stats()
print(f"  Total flows: {stats['total_flows_processed']}")
print(f"  Fast-path: {stats['fast_path_flows']} ({stats['fast_path_ratio']})")
print(f"  100 flows in: {elapsed_ms:.2f} ms")
print(f"  Avg per flow: {elapsed_ms/100:.3f} ms")
print(f"  Pipeline avg timing: {stats['avg_total_response_ms']} ms")

ti_stats = stats["sub_engine_stats"]["threat_intelligence"]
fb_stats = stats["sub_engine_stats"]["flow_buffer"]
print(f"  ThreatIntel cache: {ti_stats['cache_hit_rate']}")
print(f"  Flow Buffer: {fb_stats['active_flows']} active flows, {fb_stats['total_packets_ingested']} pkts ingested")
print()

# =========================================
# 10-Layer Timing Breakdown
# =========================================
print("=" * 64)
print("10-LAYER TIMING (attack flow)")
print("=" * 64)
layers = [
    ("L1  Buffer/Capture", t.capture_time_ms),
    ("L2  Feature Extract", t.feature_time_ms),
    ("L3  Behavioral", t.behavior_time_ms),
    ("L4  ML Ensemble", t.ml_time_ms),
    ("L5  AI Defense", t.ai_defense_time_ms),
    ("L6  Threat Intel", t.intelligence_time_ms),
    ("L7  Correlation", t.correlation_time_ms),
    ("L8  Zero-Day", t.zero_day_time_ms),
    ("L9  Decision", t.decision_time_ms),
    ("L10 Response", t.response_time_ms),
]
total = sum(v for _, v in layers)
for name, val in layers:
    pct = (val / total * 100) if total > 0 else 0
    bar = "#" * int(pct / 2)
    print(f"  {name:<22} {val:>8.4f} ms  {pct:>5.1f}%  {bar}")
print(f"  {'TOTAL':<22} {total:>8.4f} ms  100.0%")
print()

target = 0.35
status = "PASS" if total < target else ("CLOSE" if total < 1.0 else "NEEDS WORK")
emoji = "+" if total < target else "~"
print(f"  TARGET: < {target} ms  |  ACTUAL: {total:.4f} ms  |  {status} {emoji}")
