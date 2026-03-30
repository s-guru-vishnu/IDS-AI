"""
MITM Detection Module — Enterprise Configuration
================================================
Central configuration for all detection thresholds, adaptive baselines,
response staging, packet capture analysis, and self-diagnostic parameters.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional


# ─────────────────────────────────────────────
# Logging & Health Reporting
# ─────────────────────────────────────────────
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-22s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
import os
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(_root, "stimulater", "mitm_detector.log")
ALERT_LOG_FILE = os.path.join(_root, "stimulater", "mitm_alerts.json")
HEALTH_LOG_FILE = os.path.join(_root, "stimulater", "mitm_health.json")


@dataclass
class NetworkConfig:
    """Network interface and packet handling metrics."""
    interface: Optional[str] = None  # None = Auto-detect
    gateway_ips: List[str] = field(default_factory=list)
    sniff_filter: str = "arp or icmp or tcp or udp"  # Full capture for port monitoring
    sniff_batch_size: int = 100
    promiscuous_mode: bool = True
    
    # Multi-interface awareness
    monitor_all_interfaces: bool = False
    gateway_watchdog_interval: float = 15.0


@dataclass
class EmaConfig:
    """Exponential Moving Average (EMA) Parameters."""
    # Weight of the newest data point (0.0 to 1.0)
    # Higher = faster adaptation, lower = smoother baseline
    rate_alpha: float = 0.2
    latency_alpha: float = 0.15
    ttl_alpha: float = 0.1


@dataclass
class ArpMonitorConfig:
    """ARP monitoring and stealth detection."""
    # Sliding window for flood detection
    arp_flood_threshold: int = 25
    arp_flood_window_seconds: float = 5.0
    
    # Startup Learning Phase (seconds)
    # Ignore anomalies during this period to build baseline
    learning_phase_duration: float = 45.0

    # Stealth Detection: Low-frequency spoofing
    # Score penalty for replies seen without requests over a long window
    stealth_reply_window_seconds: float = 60.0
    
    # Duplicate detection (short window)
    duplicate_reply_window_seconds: float = 1.5
    duplicate_reply_threshold: int = 2


@dataclass
class BehaviourAnalyzerConfig:
    """Adaptive network behaviour tracking."""
    rate_window_seconds: float = 15.0
    rate_spike_multiplier: float = 2.5
    min_packet_threshold: int = 20
    
    # TTL Distribution anomaly detection
    # If TTL for an IP shifts by more than this, it may be a different machine
    ttl_drift_threshold: int = 4
    
    # MAC Churn
    max_macs_per_ip: int = 3
    
    max_tracked_ips: int = 1000
    ip_expiry_seconds: float = 1200.0


@dataclass
class DnsHeuristicConfig:
    """Basic DNS anomaly detection (detects rogue gateway redirects)."""
    enabled: bool = True
    # If RTT to DNS server jump coincident with ARP change
    dns_latency_correlation_threshold: float = 40.0


@dataclass
class LatencyMonitorConfig:
    """Percentile-based latency monitoring."""
    probe_interval_seconds: float = 8.0
    pings_per_measurement: int = 5
    ping_timeout_seconds: float = 1.5
    
    # Percentile-based drift (more robust than simple mean)
    # Detect if current latency is > Nth percentile of history
    percentile_threshold: float = 90.0
    sustained_drift_count: int = 3
    
    max_valid_rtt_ms: float = 300.0


@dataclass
class PacketCaptureConfig:
    """Packet capture and port monitoring thresholds."""
    # Analysis window
    analysis_window_seconds: float = 5.0

    # DDoS detection
    ddos_pps_threshold: float = 100.0
    ddos_sustained_windows: int = 2

    # Port scan detection
    port_scan_threshold: int = 10
    port_scan_window_seconds: float = 10.0

    # Port flood detection
    port_flood_threshold: int = 30
    port_flood_window_seconds: float = 5.0

    # Suspicious external IP
    external_ip_packet_threshold: int = 30
    private_prefixes: List[str] = field(default_factory=lambda: [
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.", "127.",
    ])

    # Sensitive ports
    sensitive_ports: Set[int] = field(default_factory=lambda: {
        21, 22, 23, 445, 3389, 3306, 5432, 1433, 6379, 27017,
    })

    # Reporting
    top_talkers_count: int = 5
    report_interval_seconds: float = 5.0
    enable_console_report: bool = True

    # Capacity
    max_tracked_ips: int = 2000
    ip_expiry_seconds: float = 600.0


@dataclass
class RiskScoreConfig:
    """Multi-factor risk scoring and correlation."""
    # Score Weights — ARP / Network
    weight_unverified_gateway_change: float = 65.0
    weight_verified_gateway_change: float = 5.0
    weight_arp_flood: float = 30.0
    weight_stealth_spoof: float = 35.0
    weight_behaviour_anomaly: float = 15.0
    weight_latency_drift: float = 25.0
    weight_duplicate_arp_reply: float = 20.0
    weight_gratuitous_arp: float = 15.0
    weight_unsolicited_arp_reply: float = 10.0

    # Score Weights — Packet Capture / Port Monitoring
    weight_port_scan: float = 35.0
    weight_port_flood: float = 25.0
    weight_ddos_indicator: float = 40.0
    weight_sensitive_port: float = 20.0
    weight_suspicious_external: float = 15.0

    # Score Weights — Advanced / Multi-layer Monitors
    weight_wifi_impersonation: float = 75.0
    weight_tls_tampering: float = 65.0
    weight_dns_hijack: float = 70.0
    weight_route_redirect: float = 75.0
    weight_ipv6_ndp_attack: float = 65.0
    
    # Correlation Multipliers (Synergy)
    # If ARP change AND Latency drift both happen, multiply the incremental score
    correlation_multiplier: float = 1.8

    # Thresholds
    threshold_low: float = 35.0
    threshold_medium: float = 50.0
    threshold_high: float = 70.0
    threshold_critical: float = 85.0

    # Decay
    decay_factor: float = 0.85 
    decay_interval_seconds: float = 30.0
    
    max_score: float = 100.0
    alert_cooldown_seconds: float = 300.0


@dataclass
class ResponseConfig:
    """Staged response parameters."""
    auto_response_enabled: bool = True
    auto_block_enabled: bool = True
    auto_arp_correction_enabled: bool = False
    
    # Response Modes: 
    # 0 = MONITOR_ONLY
    # 1 = STAGED (Warn -> Quarantine -> Block)
    # 2 = AGGRESSIVE (Block immediately on high risk)
    response_mode: int = 1
    
    # Connectivity Safety Check
    # Before blocking, verify we can still reach these (e.g., 8.8.8.8)
    # If we can't, rollback the block immediately.
    safety_check_ips: List[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    
    block_score_threshold: float = 75.0
    quarantine_duration_seconds: float = 600.0
    max_concurrent_blocks: int = 10
    
    # Firewall templates
    block_command_template: str = ""
    unblock_command_template: str = ""
    block_mac_command_template: Optional[str] = None
    unblock_mac_command_template: Optional[str] = None
    protected_ips: List[str] = field(default_factory=list)


@dataclass
class GatewayVerifierConfig:
    """Active verification settings."""
    probe_count: int = 3
    probe_timeout_seconds: float = 2.0
    min_confirmations: int = 2
    verification_cooldown_seconds: float = 300.0
    verification_grace_period_seconds: float = 2.0


@dataclass
class HealthMonitorConfig:
    """Self-diagnostic settings."""
    check_interval_seconds: float = 30.0
    max_memory_mb: int = 500
    max_cpu_percent: float = 15.0


@dataclass
class MitmConfig:
    """Master Configuration."""
    network: NetworkConfig = field(default_factory=NetworkConfig)
    ema: EmaConfig = field(default_factory=EmaConfig)
    arp_monitor: ArpMonitorConfig = field(default_factory=ArpMonitorConfig)
    behaviour_analyzer: BehaviourAnalyzerConfig = field(default_factory=BehaviourAnalyzerConfig)
    dns: DnsHeuristicConfig = field(default_factory=DnsHeuristicConfig)
    latency_monitor: LatencyMonitorConfig = field(default_factory=LatencyMonitorConfig)
    packet_capture: PacketCaptureConfig = field(default_factory=PacketCaptureConfig)
    risk_score: RiskScoreConfig = field(default_factory=RiskScoreConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    gateway_verifier: GatewayVerifierConfig = field(default_factory=GatewayVerifierConfig)
    health: HealthMonitorConfig = field(default_factory=HealthMonitorConfig)
    
    # Advanced Modules Flag
    advanced_modules_enabled: bool = True

    # Whitelists
    trusted_macs: Set[str] = field(default_factory=set)
    trusted_ips: Set[str] = field(default_factory=set)
