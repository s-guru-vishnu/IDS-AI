"""
generate_dataset.py — Synthetic Flow-Based IDS Dataset Generator
=================================================================
Generates a realistic, labeled CSV dataset for testing the Cyber Defense
AI 10-layer pipeline. Covers all attack types, edge cases, and zero-day
patterns with realistic feature distributions.

Output: dataset/synthetic_flows.csv

Labels:
  BENIGN, DDoS, MITM, AI_ATTACK, STEALTH_ATTACK, HYBRID_ATTACK, UNKNOWN_ATTACK

Usage:
  py generate_dataset.py                     # Default: 10,000 flows
  py generate_dataset.py --count 50000       # Custom count
  py generate_dataset.py --output my_data.csv
"""

import os
import sys
import csv
import random
import math
import argparse
import ipaddress
from datetime import datetime
from typing import List, Dict, Tuple

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

DEFAULT_COUNT = 10000
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset")

# Class distribution (approximate percentages)
CLASS_DISTRIBUTION = {
    "BENIGN":         0.35,
    "DDoS":           0.15,
    "MITM":           0.08,
    "AI_ATTACK":      0.08,
    "STEALTH_ATTACK": 0.08,
    "HYBRID_ATTACK":  0.06,
    "UNKNOWN_ATTACK": 0.05,
    # Edge cases fill the remaining ~15%
    "EDGE_DDoS_low_slow":       0.02,
    "EDGE_mimicry":             0.02,
    "EDGE_threshold_aware":     0.02,
    "EDGE_jitter":              0.01,
    "EDGE_encrypted_like":      0.01,
    "EDGE_distributed_micro":   0.02,
    "EDGE_noise_injection":     0.02,
    "EDGE_time_shifted":        0.01,
    "EDGE_very_short":          0.01,
    "EDGE_very_long":           0.01,
}

# CSV Header
FIELDS = [
    "flow_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "duration",
    "packet_count",
    "byte_count",
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "std_packet_size",
    "inter_arrival_time",
    "iat_std",
    "entropy",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "syn_ratio",
    "ack_ratio",
    "fin_ratio",
    "rst_ratio",
    "burst_count",
    "unique_src_ports",
    "unique_dst_ports",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "label",
]


# ─────────────────────────────────────────────
# IP Address Generators
# ─────────────────────────────────────────────

def random_internal_ip() -> str:
    """Generate a random internal/private IP."""
    subnet = random.choice(["10.0", "192.168", "172.16"])
    if subnet == "10.0":
        return f"10.{random.randint(0,255)}.{random.randint(1,254)}.{random.randint(1,254)}"
    elif subnet == "192.168":
        return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    else:
        return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"


def random_external_ip() -> str:
    """Generate a random external/public IP."""
    while True:
        a = random.randint(1, 223)
        if a in (10, 127, 169, 172, 192):
            continue
        return f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def random_botnet_ips(count: int) -> List[str]:
    """Generate a set of distributed botnet source IPs."""
    ips = set()
    while len(ips) < count:
        ips.add(random_external_ip())
    return list(ips)


# ─────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────

def clamp(val, lo, hi):
    return max(lo, min(hi, val))


def gauss_clamp(mean, std, lo, hi):
    return clamp(random.gauss(mean, std), lo, hi)


def compute_entropy(avg_size: float, std_size: float) -> float:
    """Approximate Shannon entropy from packet size distribution."""
    if std_size < 1:
        return 0.0  # Uniform size = zero entropy
    # Higher std = more variation = higher entropy
    cv = std_size / max(avg_size, 1)
    return clamp(cv * 2.5, 0.0, 1.0)


def compute_flags(packet_count: int, syn_r: float, ack_r: float,
                  fin_r: float, rst_r: float) -> dict:
    """Compute flag counts from ratios."""
    n = max(packet_count, 1)
    return {
        "syn_count": int(n * syn_r),
        "ack_count": int(n * ack_r),
        "fin_count": int(n * fin_r),
        "rst_count": int(n * rst_r),
        "syn_ratio": round(syn_r, 4),
        "ack_ratio": round(ack_r, 4),
        "fin_ratio": round(fin_r, 4),
        "rst_ratio": round(rst_r, 4),
    }


# ─────────────────────────────────────────────
# Flow Generators (one per class)
# ─────────────────────────────────────────────

def gen_benign() -> dict:
    """Normal web browsing, API calls, file downloads."""
    profile = random.choice(["web", "api", "download", "streaming", "dns"])

    if profile == "web":
        duration = gauss_clamp(2.0, 1.5, 0.1, 30.0)
        packet_count = int(gauss_clamp(30, 20, 5, 200))
        avg_size = gauss_clamp(600, 300, 64, 1500)
        std_size = gauss_clamp(200, 100, 10, 500)
        syn_r, ack_r, fin_r, rst_r = 0.03, 0.45, 0.02, 0.0
        protocol = "TCP"
        dst_port = random.choice([80, 443, 443, 443, 8080])

    elif profile == "api":
        duration = gauss_clamp(0.5, 0.3, 0.05, 5.0)
        packet_count = int(gauss_clamp(10, 5, 3, 50))
        avg_size = gauss_clamp(300, 150, 64, 1000)
        std_size = gauss_clamp(100, 50, 5, 300)
        syn_r, ack_r, fin_r, rst_r = 0.05, 0.50, 0.05, 0.0
        protocol = "TCP"
        dst_port = random.choice([443, 8443, 3000, 5000, 8080])

    elif profile == "download":
        duration = gauss_clamp(10.0, 5.0, 1.0, 120.0)
        packet_count = int(gauss_clamp(200, 100, 30, 1000))
        avg_size = gauss_clamp(1400, 100, 1000, 1500)
        std_size = gauss_clamp(50, 30, 5, 200)
        syn_r, ack_r, fin_r, rst_r = 0.01, 0.60, 0.01, 0.0
        protocol = "TCP"
        dst_port = random.choice([80, 443, 21])

    elif profile == "streaming":
        duration = gauss_clamp(60.0, 30.0, 5.0, 300.0)
        packet_count = int(gauss_clamp(500, 200, 50, 2000))
        avg_size = gauss_clamp(1200, 200, 500, 1500)
        std_size = gauss_clamp(100, 50, 10, 300)
        syn_r, ack_r, fin_r, rst_r = 0.005, 0.55, 0.005, 0.0
        protocol = random.choice(["TCP", "UDP"])
        dst_port = random.choice([443, 1935, 554, 8554])

    else:  # dns
        duration = gauss_clamp(0.05, 0.03, 0.01, 0.5)
        packet_count = int(gauss_clamp(2, 1, 1, 6))
        avg_size = gauss_clamp(80, 30, 40, 512)
        std_size = gauss_clamp(20, 10, 0, 100)
        syn_r, ack_r, fin_r, rst_r = 0.0, 0.0, 0.0, 0.0
        protocol = "UDP"
        dst_port = 53

    src_ip = random_internal_ip()
    dst_ip = random_external_ip()
    src_port = random.randint(1024, 65535)

    pps = packet_count / max(duration, 0.001)
    bps = (packet_count * avg_size) / max(duration, 0.001)
    iat = duration / max(packet_count - 1, 1)

    return _build_row(
        src_ip, dst_ip, src_port, dst_port, protocol,
        duration, packet_count, avg_size, std_size,
        pps, bps, iat, gauss_clamp(iat * 0.3, iat * 0.1, 0, iat),
        syn_r, ack_r, fin_r, rst_r, 0,
        1, 1, "BENIGN",
    )


def gen_ddos() -> dict:
    """DDoS attack: high rate, SYN flood, distributed."""
    variant = random.choice(["syn_flood", "udp_flood", "http_flood", "amplification"])

    if variant == "syn_flood":
        duration = gauss_clamp(5.0, 3.0, 0.5, 30.0)
        packet_count = int(gauss_clamp(2000, 1000, 200, 10000))
        avg_size = gauss_clamp(60, 10, 40, 100)
        std_size = gauss_clamp(5, 3, 0, 20)
        syn_r, ack_r, fin_r, rst_r = gauss_clamp(0.85, 0.1, 0.5, 1.0), 0.05, 0.0, 0.0
        protocol = "TCP"
        dst_port = random.choice([80, 443, 22, 3389])

    elif variant == "udp_flood":
        duration = gauss_clamp(3.0, 2.0, 0.5, 20.0)
        packet_count = int(gauss_clamp(5000, 2000, 500, 20000))
        avg_size = gauss_clamp(512, 200, 64, 1500)
        std_size = gauss_clamp(50, 30, 0, 200)
        syn_r, ack_r, fin_r, rst_r = 0.0, 0.0, 0.0, 0.0
        protocol = "UDP"
        dst_port = random.choice([53, 123, 161, 1900])

    elif variant == "http_flood":
        duration = gauss_clamp(10.0, 5.0, 1.0, 60.0)
        packet_count = int(gauss_clamp(1000, 500, 100, 5000))
        avg_size = gauss_clamp(400, 150, 100, 1500)
        std_size = gauss_clamp(100, 50, 10, 500)
        syn_r, ack_r, fin_r, rst_r = 0.15, 0.40, 0.02, 0.01
        protocol = "TCP"
        dst_port = random.choice([80, 443, 8080])

    else:  # amplification
        duration = gauss_clamp(5.0, 3.0, 0.5, 20.0)
        packet_count = int(gauss_clamp(3000, 1500, 300, 15000))
        avg_size = gauss_clamp(1400, 100, 500, 1500)
        std_size = gauss_clamp(30, 20, 0, 100)
        syn_r, ack_r, fin_r, rst_r = 0.0, 0.0, 0.0, 0.0
        protocol = "UDP"
        dst_port = random.choice([53, 123, 1900, 11211])

    src_ip = random_external_ip()
    dst_ip = random_internal_ip()
    src_port = random.randint(1024, 65535)

    pps = packet_count / max(duration, 0.001)
    bps = (packet_count * avg_size) / max(duration, 0.001)
    iat = duration / max(packet_count - 1, 1)

    burst = int(gauss_clamp(5, 3, 1, 15))
    unique_src = random.randint(1, 5) if variant != "amplification" else 1
    unique_dst = 1

    return _build_row(
        src_ip, dst_ip, src_port, dst_port, protocol,
        duration, packet_count, avg_size, std_size,
        pps, bps, iat, gauss_clamp(iat * 0.1, iat * 0.05, 0, iat),
        syn_r, ack_r, fin_r, rst_r, burst,
        unique_src, unique_dst, "DDoS",
    )


def gen_mitm() -> dict:
    """MITM: abnormal timing, packet manipulation, irregular sequences."""
    variant = random.choice(["arp_spoof", "dns_poison", "ssl_strip", "session_hijack"])

    duration = gauss_clamp(15.0, 10.0, 1.0, 120.0)
    packet_count = int(gauss_clamp(100, 50, 20, 500))
    avg_size = gauss_clamp(400, 200, 64, 1500)
    std_size = gauss_clamp(250, 100, 50, 600)  # High variance = manipulation

    if variant == "arp_spoof":
        protocol = "ARP"
        dst_port = 0
        syn_r, ack_r, fin_r, rst_r = 0.0, 0.0, 0.0, 0.0
        avg_size = gauss_clamp(42, 5, 28, 60)
        std_size = gauss_clamp(3, 2, 0, 10)
    elif variant == "dns_poison":
        protocol = "UDP"
        dst_port = 53
        syn_r, ack_r, fin_r, rst_r = 0.0, 0.0, 0.0, 0.0
    elif variant == "ssl_strip":
        protocol = "TCP"
        dst_port = 80
        syn_r, ack_r, fin_r, rst_r = 0.08, 0.35, 0.05, 0.08
    else:
        protocol = "TCP"
        dst_port = random.choice([80, 443])
        syn_r, ack_r, fin_r, rst_r = 0.10, 0.30, 0.03, 0.15  # High RST = hijack

    src_ip = random_external_ip()
    dst_ip = random_internal_ip()
    src_port = random.randint(1024, 65535)

    pps = packet_count / max(duration, 0.001)
    bps = (packet_count * avg_size) / max(duration, 0.001)
    # MITM has irregular IAT (high jitter)
    iat = duration / max(packet_count - 1, 1)
    iat_jitter = iat * gauss_clamp(0.8, 0.3, 0.3, 2.0)

    return _build_row(
        src_ip, dst_ip, src_port, dst_port, protocol,
        duration, packet_count, avg_size, std_size,
        pps, bps, iat, iat_jitter,
        syn_r, ack_r, fin_r, rst_r, 0,
        1, 1, "MITM",
    )


def gen_ai_attack() -> dict:
    """AI attack: adversarial feature manipulation to appear normal."""
    # Start with benign-like features, then slightly perturb
    base = gen_benign()

    # Adversarial perturbation: make malicious traffic look benign
    # Slightly higher packet rate than normal but within 1 std
    base["packet_rate"] = float(base["packet_rate"]) * gauss_clamp(1.3, 0.2, 1.05, 1.8)
    base["byte_rate"] = float(base["byte_rate"]) * gauss_clamp(1.2, 0.15, 1.0, 1.5)

    # Slightly manipulated entropy (trying to evade detection)
    base["entropy"] = gauss_clamp(0.5, 0.15, 0.2, 0.8)

    # Inject SYN anomaly that's barely detectable
    base["syn_ratio"] = gauss_clamp(0.12, 0.05, 0.05, 0.25)
    base["syn_count"] = int(int(base["packet_count"]) * float(base["syn_ratio"]))

    # Very slight IAT irregularity
    base["inter_arrival_time"] = float(base["inter_arrival_time"]) * gauss_clamp(0.9, 0.1, 0.5, 1.1)

    base["label"] = "AI_ATTACK"
    return base


def gen_stealth() -> dict:
    """Stealth attack: low-and-slow, distributed micro-traffic."""
    variant = random.choice(["low_slow", "micro_traffic", "covert_channel"])

    if variant == "low_slow":
        duration = gauss_clamp(300.0, 150.0, 30.0, 3600.0)
        packet_count = int(gauss_clamp(50, 30, 5, 200))
        avg_size = gauss_clamp(200, 100, 64, 500)
        std_size = gauss_clamp(50, 30, 5, 150)
        dst_port = random.choice([80, 443, 22])

    elif variant == "micro_traffic":
        duration = gauss_clamp(60.0, 40.0, 5.0, 600.0)
        packet_count = int(gauss_clamp(15, 10, 3, 50))
        avg_size = gauss_clamp(100, 50, 40, 300)
        std_size = gauss_clamp(20, 10, 0, 80)
        dst_port = random.choice([443, 8443, 53])

    else:  # covert_channel
        duration = gauss_clamp(120.0, 60.0, 10.0, 600.0)
        packet_count = int(gauss_clamp(30, 15, 5, 100))
        avg_size = gauss_clamp(64, 10, 40, 100)  # Small, fixed size
        std_size = gauss_clamp(2, 1, 0, 5)
        dst_port = random.choice([53, 443, 123])

    protocol = random.choice(["TCP", "UDP"])
    syn_r = gauss_clamp(0.05, 0.03, 0.0, 0.15)
    ack_r = gauss_clamp(0.4, 0.15, 0.1, 0.7) if protocol == "TCP" else 0.0
    fin_r = gauss_clamp(0.02, 0.01, 0.0, 0.05)
    rst_r = 0.0

    src_ip = random_external_ip()
    dst_ip = random_internal_ip()
    src_port = random.randint(1024, 65535)

    pps = packet_count / max(duration, 0.001)
    bps = (packet_count * avg_size) / max(duration, 0.001)
    iat = duration / max(packet_count - 1, 1)

    return _build_row(
        src_ip, dst_ip, src_port, dst_port, protocol,
        duration, packet_count, avg_size, std_size,
        pps, bps, iat, gauss_clamp(iat * 0.5, iat * 0.2, 0, iat * 2),
        syn_r, ack_r, fin_r, rst_r, 0,
        1, 1, "STEALTH_ATTACK",
    )


def gen_hybrid() -> dict:
    """Hybrid attack: DDoS + MITM combined, multi-stage."""
    # Phase 1 characteristics (DDoS-like)
    duration = gauss_clamp(20.0, 10.0, 3.0, 60.0)
    packet_count = int(gauss_clamp(800, 400, 100, 3000))
    avg_size = gauss_clamp(300, 150, 64, 1200)
    std_size = gauss_clamp(250, 100, 50, 600)  # High variance from mixed phases

    # Combined flag profile (DDoS SYN + MITM RST anomaly)
    syn_r = gauss_clamp(0.40, 0.15, 0.15, 0.70)
    ack_r = gauss_clamp(0.25, 0.10, 0.05, 0.45)
    fin_r = gauss_clamp(0.03, 0.02, 0.0, 0.10)
    rst_r = gauss_clamp(0.10, 0.05, 0.02, 0.25)  # Elevated RST

    protocol = "TCP"
    dst_port = random.choice([80, 443, 22, 3389])
    src_ip = random_external_ip()
    dst_ip = random_internal_ip()
    src_port = random.randint(1024, 65535)

    pps = packet_count / max(duration, 0.001)
    bps = (packet_count * avg_size) / max(duration, 0.001)
    iat = duration / max(packet_count - 1, 1)
    iat_jitter = iat * gauss_clamp(1.0, 0.5, 0.2, 3.0)  # High jitter

    burst = int(gauss_clamp(4, 2, 1, 10))

    return _build_row(
        src_ip, dst_ip, src_port, dst_port, protocol,
        duration, packet_count, avg_size, std_size,
        pps, bps, iat, iat_jitter,
        syn_r, ack_r, fin_r, rst_r, burst,
        random.randint(2, 8), 1, "HYBRID_ATTACK",
    )


def gen_unknown() -> dict:
    """Zero-day / unknown attack: patterns that deviate from ALL known distributions."""
    # Use unusual combinations that don't match any known class
    variant = random.choice(["bizarre_flags", "unusual_size", "timing_anomaly", "protocol_anomaly"])

    if variant == "bizarre_flags":
        # Unusual flag combinations
        duration = gauss_clamp(5.0, 3.0, 0.5, 30.0)
        packet_count = int(gauss_clamp(100, 50, 10, 500))
        avg_size = gauss_clamp(400, 200, 64, 1500)
        std_size = gauss_clamp(150, 80, 10, 400)
        syn_r = gauss_clamp(0.30, 0.10, 0.10, 0.50)
        ack_r = gauss_clamp(0.10, 0.05, 0.0, 0.20)  # Low ACK = weird
        fin_r = gauss_clamp(0.20, 0.10, 0.05, 0.40)  # High FIN = weird
        rst_r = gauss_clamp(0.15, 0.08, 0.03, 0.30)  # High RST = weird
        protocol = "TCP"

    elif variant == "unusual_size":
        # Packet sizes that don't match any normal distribution
        duration = gauss_clamp(3.0, 2.0, 0.3, 15.0)
        packet_count = int(gauss_clamp(60, 30, 10, 200))
        avg_size = gauss_clamp(937, 50, 800, 1100)  # Unusual avg
        std_size = gauss_clamp(3, 2, 0, 8)  # Very uniform = suspicious
        syn_r, ack_r, fin_r, rst_r = 0.08, 0.35, 0.02, 0.02
        protocol = "TCP"

    elif variant == "timing_anomaly":
        # Very precise / robotic timing
        duration = gauss_clamp(10.0, 5.0, 1.0, 30.0)
        packet_count = int(gauss_clamp(150, 70, 20, 500))
        avg_size = gauss_clamp(500, 150, 100, 1000)
        std_size = gauss_clamp(80, 40, 5, 200)
        syn_r, ack_r, fin_r, rst_r = 0.05, 0.40, 0.02, 0.01
        protocol = random.choice(["TCP", "UDP"])

    else:  # protocol_anomaly
        # ICMP with high packet counts (unusual)
        duration = gauss_clamp(5.0, 3.0, 0.5, 20.0)
        packet_count = int(gauss_clamp(300, 150, 50, 1000))
        avg_size = gauss_clamp(64, 10, 32, 128)
        std_size = gauss_clamp(5, 3, 0, 15)
        syn_r, ack_r, fin_r, rst_r = 0.0, 0.0, 0.0, 0.0
        protocol = "ICMP"

    dst_port = random.choice([0, 80, 443, 8080, 4444, 31337]) if protocol != "ICMP" else 0
    src_ip = random_external_ip()
    dst_ip = random_internal_ip()
    src_port = random.randint(0, 65535)

    pps = packet_count / max(duration, 0.001)
    bps = (packet_count * avg_size) / max(duration, 0.001)
    iat = duration / max(packet_count - 1, 1)
    # Zero-day has very low IAT std (robotic)
    iat_std = iat * gauss_clamp(0.02, 0.01, 0.001, 0.05) if variant == "timing_anomaly" else gauss_clamp(iat * 0.4, iat * 0.2, 0, iat)

    return _build_row(
        src_ip, dst_ip, src_port, dst_port, protocol,
        duration, packet_count, avg_size, std_size,
        pps, bps, iat, iat_std,
        syn_r, ack_r, fin_r, rst_r, random.randint(0, 3),
        1, 1, "UNKNOWN_ATTACK",
    )


# ─────────────────────────────────────────────
# Edge Case Generators
# ─────────────────────────────────────────────

def gen_edge_ddos_low_slow() -> dict:
    """Low-and-slow DDoS: almost normal traffic rate."""
    duration = gauss_clamp(120.0, 60.0, 20.0, 600.0)
    packet_count = int(gauss_clamp(100, 50, 20, 300))
    avg_size = gauss_clamp(200, 80, 64, 500)
    std_size = gauss_clamp(30, 15, 5, 80)
    syn_r = gauss_clamp(0.18, 0.05, 0.10, 0.30)  # Just above normal
    ack_r = gauss_clamp(0.35, 0.10, 0.15, 0.55)
    fin_r, rst_r = 0.01, 0.0
    protocol = "TCP"
    dst_port = random.choice([80, 443])

    src_ip = random_external_ip()
    dst_ip = random_internal_ip()
    pps = packet_count / max(duration, 0.001)  # Very low PPS
    bps = (packet_count * avg_size) / max(duration, 0.001)
    iat = duration / max(packet_count - 1, 1)

    return _build_row(
        src_ip, dst_ip, random.randint(1024, 65535), dst_port, protocol,
        duration, packet_count, avg_size, std_size,
        pps, bps, iat, gauss_clamp(iat * 0.4, iat * 0.2, 0, iat * 2),
        syn_r, ack_r, fin_r, rst_r, 0,
        1, 1, "DDoS",
    )


def gen_edge_mimicry() -> dict:
    """Human-like mimicry traffic: looks exactly like browsing."""
    row = gen_benign()
    # Add very subtle attack indicators
    row["packet_rate"] = float(row["packet_rate"]) * 1.05
    row["syn_ratio"] = gauss_clamp(0.06, 0.02, 0.03, 0.10)
    row["syn_count"] = int(int(row["packet_count"]) * float(row["syn_ratio"]))
    row["label"] = "STEALTH_ATTACK"
    return row


def gen_edge_threshold_aware() -> dict:
    """Traffic just below detection thresholds."""
    # Packet rate just below typical alert threshold of 80 pps
    pps = gauss_clamp(75, 5, 60, 79.9)
    duration = gauss_clamp(5.0, 2.0, 1.0, 15.0)
    packet_count = int(pps * duration)
    avg_size = gauss_clamp(100, 30, 60, 200)
    std_size = gauss_clamp(10, 5, 0, 30)
    # SYN ratio just below typical threshold of 0.15
    syn_r = gauss_clamp(0.13, 0.02, 0.10, 0.149)
    ack_r, fin_r, rst_r = 0.40, 0.02, 0.0
    protocol = "TCP"

    src_ip = random_external_ip()
    dst_ip = random_internal_ip()
    bps = (packet_count * avg_size) / max(duration, 0.001)
    iat = duration / max(packet_count - 1, 1)

    return _build_row(
        src_ip, dst_ip, random.randint(1024, 65535), 80, protocol,
        duration, packet_count, avg_size, std_size,
        pps, bps, iat, gauss_clamp(iat * 0.3, iat * 0.1, 0, iat),
        syn_r, ack_r, fin_r, rst_r, 1,
        1, 1, "DDoS",
    )


def gen_edge_jitter() -> dict:
    """Randomized jitter patterns to evade timing analysis."""
    duration = gauss_clamp(10.0, 5.0, 1.0, 30.0)
    packet_count = int(gauss_clamp(80, 40, 15, 300))
    avg_size = gauss_clamp(300, 100, 64, 800)
    std_size = gauss_clamp(100, 50, 10, 300)
    syn_r = gauss_clamp(0.20, 0.08, 0.08, 0.40)
    ack_r, fin_r, rst_r = 0.30, 0.02, 0.01
    protocol = "TCP"

    pps = packet_count / max(duration, 0.001)
    bps = (packet_count * avg_size) / max(duration, 0.001)
    iat = duration / max(packet_count - 1, 1)
    # Very high IAT std = randomized jitter
    iat_std = iat * gauss_clamp(2.0, 0.5, 1.0, 4.0)

    return _build_row(
        random_external_ip(), random_internal_ip(),
        random.randint(1024, 65535), random.choice([80, 443]), protocol,
        duration, packet_count, avg_size, std_size,
        pps, bps, iat, iat_std,
        syn_r, ack_r, fin_r, rst_r, random.randint(2, 6),
        1, 1, "STEALTH_ATTACK",
    )


def gen_edge_encrypted_like() -> dict:
    """Encrypted-like: uniform packet sizes (looks like VPN/TLS)."""
    duration = gauss_clamp(30.0, 15.0, 2.0, 120.0)
    packet_count = int(gauss_clamp(200, 100, 30, 800))
    avg_size = random.choice([1024, 1280, 1400, 1460])  # Fixed MTU-like
    std_size = gauss_clamp(2, 1, 0, 5)  # Nearly zero variance
    syn_r = gauss_clamp(0.15, 0.05, 0.05, 0.30)
    ack_r, fin_r, rst_r = 0.40, 0.02, 0.01
    protocol = "TCP"

    pps = packet_count / max(duration, 0.001)
    bps = (packet_count * avg_size) / max(duration, 0.001)
    iat = duration / max(packet_count - 1, 1)

    return _build_row(
        random_external_ip(), random_internal_ip(),
        random.randint(1024, 65535), 443, protocol,
        duration, packet_count, avg_size, std_size,
        pps, bps, iat, gauss_clamp(iat * 0.1, iat * 0.05, 0, iat),
        syn_r, ack_r, fin_r, rst_r, 0,
        1, 1, "AI_ATTACK",
    )


def gen_edge_distributed_micro() -> dict:
    """Distributed micro-attack: many IPs, very low per-IP rate."""
    duration = gauss_clamp(30.0, 15.0, 5.0, 120.0)
    packet_count = int(gauss_clamp(10, 5, 2, 30))
    avg_size = gauss_clamp(100, 40, 40, 300)
    std_size = gauss_clamp(20, 10, 0, 60)
    syn_r = gauss_clamp(0.30, 0.10, 0.10, 0.60)
    ack_r, fin_r, rst_r = 0.20, 0.01, 0.0
    protocol = "TCP"

    pps = packet_count / max(duration, 0.001)
    bps = (packet_count * avg_size) / max(duration, 0.001)
    iat = duration / max(packet_count - 1, 1)

    return _build_row(
        random_external_ip(), random_internal_ip(),
        random.randint(1024, 65535), random.choice([80, 443]), protocol,
        duration, packet_count, avg_size, std_size,
        pps, bps, iat, gauss_clamp(iat * 0.6, iat * 0.3, 0, iat * 3),
        syn_r, ack_r, fin_r, rst_r, 0,
        1, 1, "DDoS",
    )


def gen_edge_noise_injection() -> dict:
    """Mix of benign + attack patterns in same flow."""
    # 50/50 mix of benign and attack characteristics
    duration = gauss_clamp(15.0, 8.0, 2.0, 60.0)
    packet_count = int(gauss_clamp(150, 80, 20, 500))
    avg_size = gauss_clamp(500, 250, 64, 1400)
    std_size = gauss_clamp(300, 100, 50, 600)  # Very high variance = noise
    syn_r = gauss_clamp(0.15, 0.08, 0.03, 0.35)
    ack_r = gauss_clamp(0.30, 0.10, 0.10, 0.50)
    fin_r = gauss_clamp(0.04, 0.02, 0.0, 0.10)
    rst_r = gauss_clamp(0.05, 0.03, 0.0, 0.15)
    protocol = "TCP"

    pps = packet_count / max(duration, 0.001)
    bps = (packet_count * avg_size) / max(duration, 0.001)
    iat = duration / max(packet_count - 1, 1)

    return _build_row(
        random_external_ip(), random_internal_ip(),
        random.randint(1024, 65535), random.choice([80, 443, 8080]), protocol,
        duration, packet_count, avg_size, std_size,
        pps, bps, iat, gauss_clamp(iat * 0.8, iat * 0.3, 0, iat * 2),
        syn_r, ack_r, fin_r, rst_r, random.randint(1, 4),
        random.randint(1, 3), 1, "HYBRID_ATTACK",
    )


def gen_edge_time_shifted() -> dict:
    """Time-shifted: delayed burst after quiet period."""
    duration = gauss_clamp(30.0, 15.0, 5.0, 120.0)
    packet_count = int(gauss_clamp(300, 150, 50, 1000))
    avg_size = gauss_clamp(200, 80, 64, 600)
    std_size = gauss_clamp(60, 30, 5, 200)
    syn_r = gauss_clamp(0.40, 0.15, 0.15, 0.70)
    ack_r, fin_r, rst_r = 0.20, 0.02, 0.02
    protocol = "TCP"

    pps = packet_count / max(duration, 0.001)
    bps = (packet_count * avg_size) / max(duration, 0.001)
    iat = duration / max(packet_count - 1, 1)
    # Very high burst count = time-shifted
    burst = int(gauss_clamp(8, 3, 3, 15))

    return _build_row(
        random_external_ip(), random_internal_ip(),
        random.randint(1024, 65535), random.choice([80, 443]), protocol,
        duration, packet_count, avg_size, std_size,
        pps, bps, iat, gauss_clamp(iat * 1.5, iat * 0.5, 0, iat * 4),
        syn_r, ack_r, fin_r, rst_r, burst,
        1, 1, "DDoS",
    )


def gen_edge_very_short() -> dict:
    """Very short flows: 1-2 packets."""
    packet_count = random.choice([1, 2])
    duration = gauss_clamp(0.01, 0.005, 0.001, 0.1)
    avg_size = gauss_clamp(60, 20, 40, 200)
    std_size = 0.0 if packet_count == 1 else gauss_clamp(10, 5, 0, 40)
    syn_r = 1.0 if packet_count == 1 else 0.5
    ack_r, fin_r, rst_r = 0.0, 0.0, 0.0
    protocol = "TCP"

    pps = packet_count / max(duration, 0.001)
    bps = (packet_count * avg_size) / max(duration, 0.001)
    iat = duration if packet_count > 1 else 0.0

    # Port scan indicator
    label = random.choice(["STEALTH_ATTACK", "BENIGN"])

    return _build_row(
        random_external_ip(), random_internal_ip(),
        random.randint(1024, 65535), random.randint(1, 65535), protocol,
        duration, packet_count, avg_size, std_size,
        pps, bps, iat, 0.0,
        syn_r, ack_r, fin_r, rst_r, 0,
        1, 1, label,
    )


def gen_edge_very_long() -> dict:
    """Very long persistent connection."""
    duration = gauss_clamp(3600.0, 1200.0, 600.0, 7200.0)
    packet_count = int(gauss_clamp(2000, 1000, 100, 10000))
    avg_size = gauss_clamp(500, 200, 64, 1500)
    std_size = gauss_clamp(200, 100, 10, 500)
    syn_r = gauss_clamp(0.003, 0.002, 0.0, 0.01)
    ack_r = gauss_clamp(0.55, 0.10, 0.30, 0.75)
    fin_r = gauss_clamp(0.003, 0.002, 0.0, 0.01)
    rst_r = 0.0
    protocol = "TCP"

    pps = packet_count / max(duration, 0.001)
    bps = (packet_count * avg_size) / max(duration, 0.001)
    iat = duration / max(packet_count - 1, 1)

    # Long connections could be C2 or legitimate
    label = random.choice(["STEALTH_ATTACK", "BENIGN"])

    return _build_row(
        random_external_ip(), random_internal_ip(),
        random.randint(1024, 65535), random.choice([443, 22, 3389]), protocol,
        duration, packet_count, avg_size, std_size,
        pps, bps, iat, gauss_clamp(iat * 0.3, iat * 0.1, 0, iat),
        syn_r, ack_r, fin_r, rst_r, 0,
        1, 1, label,
    )


# ─────────────────────────────────────────────
# Row Builder
# ─────────────────────────────────────────────

def _build_row(
    src_ip, dst_ip, src_port, dst_port, protocol,
    duration, packet_count, avg_size, std_size,
    pps, bps, iat, iat_std,
    syn_r, ack_r, fin_r, rst_r, burst_count,
    unique_src_ports, unique_dst_ports, label,
) -> dict:
    """Build a dataset row with all computed fields."""
    n = max(int(packet_count), 1)
    byte_count = int(n * avg_size)
    entropy = compute_entropy(avg_size, std_size)

    # Protocol ratios
    tcp_r = 1.0 if protocol == "TCP" else 0.0
    udp_r = 1.0 if protocol == "UDP" else 0.0
    icmp_r = 1.0 if protocol == "ICMP" else 0.0
    if protocol == "ARP":
        tcp_r, udp_r, icmp_r = 0.0, 0.0, 0.0

    flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}/{protocol}"

    return {
        "flow_id": flow_id,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(src_port),
        "dst_port": int(dst_port),
        "protocol": protocol,
        "duration": round(float(duration), 4),
        "packet_count": int(n),
        "byte_count": int(byte_count),
        "packet_rate": round(float(pps), 4),
        "byte_rate": round(float(bps), 2),
        "avg_packet_size": round(float(avg_size), 2),
        "std_packet_size": round(float(std_size), 2),
        "inter_arrival_time": round(float(iat), 6),
        "iat_std": round(float(iat_std), 6),
        "entropy": round(float(entropy), 4),
        "syn_count": int(n * syn_r),
        "ack_count": int(n * ack_r),
        "fin_count": int(n * fin_r),
        "rst_count": int(n * rst_r),
        "syn_ratio": round(float(syn_r), 4),
        "ack_ratio": round(float(ack_r), 4),
        "fin_ratio": round(float(fin_r), 4),
        "rst_ratio": round(float(rst_r), 4),
        "burst_count": int(burst_count),
        "unique_src_ports": int(unique_src_ports),
        "unique_dst_ports": int(unique_dst_ports),
        "tcp_ratio": tcp_r,
        "udp_ratio": udp_r,
        "icmp_ratio": icmp_r,
        "label": label,
    }


# ─────────────────────────────────────────────
# Generator Registry
# ─────────────────────────────────────────────

GENERATORS = {
    "BENIGN":                   gen_benign,
    "DDoS":                     gen_ddos,
    "MITM":                     gen_mitm,
    "AI_ATTACK":                gen_ai_attack,
    "STEALTH_ATTACK":           gen_stealth,
    "HYBRID_ATTACK":            gen_hybrid,
    "UNKNOWN_ATTACK":           gen_unknown,
    "EDGE_DDoS_low_slow":       gen_edge_ddos_low_slow,
    "EDGE_mimicry":             gen_edge_mimicry,
    "EDGE_threshold_aware":     gen_edge_threshold_aware,
    "EDGE_jitter":              gen_edge_jitter,
    "EDGE_encrypted_like":      gen_edge_encrypted_like,
    "EDGE_distributed_micro":   gen_edge_distributed_micro,
    "EDGE_noise_injection":     gen_edge_noise_injection,
    "EDGE_time_shifted":        gen_edge_time_shifted,
    "EDGE_very_short":          gen_edge_very_short,
    "EDGE_very_long":           gen_edge_very_long,
}


# ─────────────────────────────────────────────
# Main Generator
# ─────────────────────────────────────────────

def generate_dataset(total_count: int, output_path: str) -> str:
    """Generate the full synthetic dataset."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    # Calculate per-class counts
    class_counts = {}
    allocated = 0
    for cls, ratio in CLASS_DISTRIBUTION.items():
        count = int(total_count * ratio)
        class_counts[cls] = count
        allocated += count

    # Distribute remainder to BENIGN
    class_counts["BENIGN"] += (total_count - allocated)

    print(f"Generating {total_count} synthetic flows...")
    print(f"  Classes: {len(class_counts)}")
    for cls, count in sorted(class_counts.items(), key=lambda x: -x[1]):
        pct = count / total_count * 100
        print(f"    {cls:<28} {count:>6}  ({pct:.1f}%)")

    # Generate all rows
    rows = []
    for cls, count in class_counts.items():
        gen_fn = GENERATORS[cls]
        for _ in range(count):
            rows.append(gen_fn())

    # Shuffle to avoid ordering bias
    random.shuffle(rows)

    # Deduplicate by flow_id (regenerate duplicates)
    seen_ids = set()
    unique_rows = []
    for row in rows:
        fid = row["flow_id"]
        attempts = 0
        while fid in seen_ids and attempts < 5:
            # Regenerate with different ports
            row["src_port"] = random.randint(1024, 65535)
            row["flow_id"] = f"{row['src_ip']}:{row['src_port']}-{row['dst_ip']}:{row['dst_port']}/{row['protocol']}"
            fid = row["flow_id"]
            attempts += 1
        seen_ids.add(fid)
        unique_rows.append(row)

    # Write CSV
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(unique_rows)

    # Print summary
    label_counts = {}
    for row in unique_rows:
        label_counts[row["label"]] = label_counts.get(row["label"], 0) + 1

    print(f"\nDataset saved: {output_path}")
    print(f"  Total rows: {len(unique_rows)}")
    print(f"  Unique flow IDs: {len(seen_ids)}")
    print(f"\n  Label Distribution (final):")
    for label, count in sorted(label_counts.items(), key=lambda x: -x[1]):
        pct = count / len(unique_rows) * 100
        bar = "#" * int(pct)
        print(f"    {label:<20} {count:>6}  ({pct:>5.1f}%)  {bar}")

    # Edge case percentage
    edge_count = sum(
        class_counts.get(k, 0) for k in class_counts
        if k.startswith("EDGE_")
    )
    print(f"\n  Edge cases: {edge_count} ({edge_count/total_count*100:.1f}%)")

    return output_path


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic IDS flow dataset")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT,
                        help=f"Number of flows to generate (default: {DEFAULT_COUNT})")
    parser.add_argument("--output", type=str, default=None,
                        help="Output CSV path (default: dataset/synthetic_flows.csv)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for reproducibility")
    args = parser.parse_args()

    random.seed(args.seed)

    output = args.output or os.path.join(OUTPUT_DIR, "synthetic_flows.csv")

    print("=" * 60)
    print("Synthetic Flow-Based IDS Dataset Generator")
    print(f"  Seed: {args.seed}")
    print(f"  Count: {args.count}")
    print(f"  Output: {output}")
    print("=" * 60)

    generate_dataset(args.count, output)

    print("\nDone!")
