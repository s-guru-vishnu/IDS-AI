"""
MITM Detector — Main Orchestrator
===================================
Central orchestrator that ties all detection modules together and
manages the packet capture pipeline, background threads, and
inter-module communication.

Architecture:
  ┌────────────────────────────────────────────────────────┐
  │                    MitmDetector                        │
  │  ┌──────────┐  ┌────────────────┐  ┌───────────────┐  │
  │  │ Scapy    │→ │  ArpMonitor    │→ │ RiskScoring   │  │
  │  │ Sniffer  │→ │  Behaviour     │→ │ Engine        │  │
  │  │ (Thread) │  │  Analyzer      │  │               │  │
  │  └──────────┘  └────────────────┘  └───────┬───────┘  │
  │                                            │          │
  │  ┌──────────────┐  ┌─────────────┐         ▼          │
  │  │ Latency      │→ │ Gateway     │  ┌─────────────┐   │
  │  │ Monitor      │  │ Verifier    │  │ Response    │   │
  │  │ (Thread)     │  │             │  │ Engine      │   │
  │  └──────────────┘  └─────────────┘  └─────────────┘   │
  └────────────────────────────────────────────────────────┘

Thread Design:
  - Main thread: Scapy packet sniffing (blocking)
  - Thread 1: LatencyMonitor background probes
  - Thread 2: Periodic analysis (behaviour, score decay, cleanup)
  - Thread N: Response engine auto-unblock timers (daemon)
"""

import os
import sys
import time
import json
import socket
import logging
import platform
import threading
import subprocess
from typing import Optional, List, Callable

# Scapy imports
try:
    from scapy.all import sniff, conf, get_if_list, get_if_hwaddr
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.inet import IP, ICMP
except ImportError:
    print("ERROR: Scapy is required. Install with: pip install scapy")
    sys.exit(1)

# Module imports
from mitm_config import MitmConfig
from arp_monitor import ArpMonitor, ArpEvent
from gateway_verifier import GatewayVerifier
from behaviour_analyzer import BehaviourAnalyzer
from latency_monitor import LatencyMonitor
from risk_scoring import RiskScoringEngine
from response_engine import ResponseEngine
from packet_capture import PacketCaptureEngine

# Advanced Monitors
from wifi_monitor import WifiMonitor, WifiEvent
from tls_monitor import TlsMonitor, TlsEvent
from dns_monitor import DnsMonitor, DnsEvent
from icmp_monitor import IcmpMonitor, IcmpEvent
from ipv6_ndp_monitor import Ipv6NdpMonitor, Ipv6Event

# MongoDB Integration
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from mongo_logger import setup_mongo_logging
except ImportError:
    setup_mongo_logging = None

logger = logging.getLogger("mitm.detector")


class MitmDetector:
    """
    Production MITM detection and response system.

    Orchestrates all detection layers, manages threads, and
    routes events through the risk scoring pipeline to the
    response engine.

    Usage:
        config = MitmConfig()
        detector = MitmDetector(config)
        detector.start()  # Blocks until stop() or Ctrl+C
    """

    def __init__(self, config: MitmConfig = None):
        self._config = config or MitmConfig()
        self._running = False
        self._lock = threading.Lock()

        # ── Setup Logging ──
        self._setup_logging()

        # ── Auto-detect Network Info ──
        self._interface = self._config.network.interface or self._detect_interface()
        self._own_ip = self._get_own_ip()
        self._own_mac = self._get_own_mac()
        self._gateway_ips = self._config.network.gateway_ips or self._detect_gateways()

        logger.info("═" * 60)
        logger.info("MITM Detector Initializing")
        logger.info("═" * 60)
        logger.info("Interface:  %s", self._interface)
        logger.info("Own IP:     %s", self._own_ip)
        logger.info("Own MAC:    %s", self._own_mac)
        logger.info("Gateway(s): %s", self._gateway_ips)
        logger.info("═" * 60)

        # ── Initialize Modules ──
        self._arp_monitor = ArpMonitor(
            config=self._config.arp_monitor,
            trusted_macs=set(self._config.trusted_macs or []),
        )

        self._gateway_verifier = GatewayVerifier(
            config=self._config.gateway_verifier,
            interface=self._interface,
        )

        self._behaviour_analyzer = BehaviourAnalyzer(
            config=self._config.behaviour_analyzer,
            ema_cfg=self._config.ema,
        )

        self._latency_monitor = LatencyMonitor(
            config=self._config.latency_monitor,
            gateway_ips=self._gateway_ips,
        )

        self._risk_engine = RiskScoringEngine(
            config=self._config.risk_score,
            alert_callback=self._on_risk_alert,
        )

        self._response_engine = ResponseEngine(
            config=self._config.response,
            own_ip=self._own_ip,
            gateway_ips=self._gateway_ips,
            db=getattr(self, "_db", None)
        )

        self._packet_capture = PacketCaptureEngine(
            config=self._config.packet_capture,
            own_ip=self._own_ip,
        )

        # ── Initialize Advanced Monitors ──
        if self._config.advanced_modules_enabled:
            self._wifi_monitor = WifiMonitor(check_interval=30.0)
            self._tls_monitor = TlsMonitor()
            self._dns_monitor = DnsMonitor()
            self._icmp_monitor = IcmpMonitor(gateway_ips=self._gateway_ips)
            self._ipv6_monitor = Ipv6NdpMonitor()
            logger.info("Advanced monitors initialized (WiFi, TLS, DNS, ICMP, IPv6 NDP)")

        # Protect own IP and gateway IPs
        for gw in self._gateway_ips:
            self._response_engine.add_protected_ip(gw)
        self._response_engine.add_protected_ip(self._own_ip)

        # ── Set Initial Gateway MACs ──
        self._initialize_gateway_macs()

        logger.info("PacketCaptureEngine integrated — port monitoring active")

        # ── Startup Phase ──
        self._learning_until = time.time() + self._config.arp_monitor.learning_phase_duration
        self._is_learning = True

        # ── Statistics ──
        self._packets_processed = 0
        self._arp_packets = 0
        self._events_detected = 0
        self._alerts_raised = 0
        self._start_time: Optional[float] = None
        self._health_stats = {
            "last_watchdog_check": 0.0,
            "gateway_reachable": True,
            "packet_capture_healthy": True
        }

        # ── Background Threads ──
        self._analysis_thread: Optional[threading.Thread] = None
        self._watchdog_thread: Optional[threading.Thread] = None

        logger.info("All modules initialized successfully")
        if self._config.arp_monitor.learning_phase_duration > 0:
            logger.info("Learning phase active for %.0fs", self._config.arp_monitor.learning_phase_duration)

    def _setup_logging(self):
        """Configure the logging system."""
        from mitm_config import LOG_LEVEL, LOG_FORMAT, LOG_DATE_FORMAT, LOG_FILE

        # Root logger for the mitm namespace
        root_logger = logging.getLogger("mitm")
        root_logger.setLevel(LOG_LEVEL)

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(LOG_LEVEL)
        console_formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

        # File handler
        try:
            file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(console_formatter)
            root_logger.addHandler(file_handler)
        except PermissionError:
            print(f"WARNING: Cannot write to log file {LOG_FILE}")
            
        # MongoDB handler
        if setup_mongo_logging:
            _, self._db = setup_mongo_logging(logger_name="mitm", collection_name="logs")

    def _detect_interface(self) -> str:
        """Auto-detect the best network interface for sniffing."""
        try:
            # Use Scapy's default interface
            iface = conf.iface
            if iface:
                logger.info("Auto-detected interface: %s", iface)
                return str(iface)
        except Exception:
            pass

        # Fallback: list interfaces and pick first non-loopback
        try:
            interfaces = get_if_list()
            for iface in interfaces:
                if "loopback" not in iface.lower() and "lo" != iface:
                    return iface
        except Exception:
            pass

        return "eth0"  # Final fallback

    def _get_own_ip(self) -> str:
        """Get the IP address of the local host."""
        try:
            # Create a UDP socket to determine which IP the OS would use
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _get_own_mac(self) -> str:
        """Get the MAC address of the active interface."""
        try:
            return get_if_hwaddr(self._interface)
        except Exception:
            return "00:00:00:00:00:00"

    def _detect_gateways(self) -> List[str]:
        """
        Auto-detect gateway IP addresses using Scapy's route table
        and fallback shell commands.
        """
        gateways = []

        try:
            # 1. Primary Method: Use Scapy's built-in route detection
            # This is generally the most reliable across platforms
            from scapy.all import conf
            gw = conf.route.route("0.0.0.0")[2]
            if gw and gw != "0.0.0.0":
                gateways.append(gw)
                logger.debug("Detected gateway from Scapy routes: %s", gw)

        except Exception as e:
            logger.debug("Scapy gateway detection failed: %s", e)

        # 2. Fallback: OS-specific commands
        if not gateways:
            try:
                system = platform.system().lower()

                if system == "windows":
                    # Parse ipconfig output (handles different encodings)
                    result = subprocess.run(
                        ["ipconfig"], capture_output=True, timeout=5
                    )
                    # Try common encodings
                    import re
                    content = ""
                    for enc in ["utf-8", "cp1252", "cp437", "utf-16"]:
                        try:
                            content = result.stdout.decode(enc)
                            if "Windows IP Configuration" in content:
                                break
                        except Exception:
                            continue
                    
                    matches = re.findall(
                        r"Default Gateway[\s.]*:\s*([\d.]+)", content
                    )
                    gateways.extend(matches)

                else:
                    # Parse ip route output (Linux/Mac)
                    result = subprocess.run(
                        ["ip", "route", "show", "default"],
                        capture_output=True,
                        text=True, errors="ignore",
                        timeout=5,
                    )
                    import re
                    matches = re.findall(r"via\s+([\d.]+)", result.stdout)
                    gateways.extend(matches)

                    if not gateways:
                        # Try netstat for macOS
                        result = subprocess.run(
                            ["netstat", "-rn"],
                            capture_output=True,
                            text=True, errors="ignore",
                            timeout=5,
                        )
                        for line in result.stdout.splitlines():
                            if line.startswith("default") or line.startswith("0.0.0.0"):
                                parts = line.split()
                                if len(parts) >= 2:
                                    gw = parts[1]
                                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", gw):
                                        gateways.append(gw)

            except Exception as e:
                logger.warning("Gateway detection fallback failed: %s", e)

        # Deduplicate
        gateways = list(set(gateways))

        if not gateways:
            logger.warning("Could not detect gateway — using 192.168.1.1 as default")
            gateways = ["192.168.1.1"]

        return gateways

    def _initialize_gateway_macs(self):
        """
        Learn initial gateway MACs from the system ARP cache.
        These form the trusted baseline for change detection.
        """
        for gw_ip in self._gateway_ips:
            mac = self._get_mac_from_arp_cache(gw_ip)
            if mac:
                self._gateway_verifier.set_initial_gateway(gw_ip, mac)
                self._arp_monitor.mark_verified(gw_ip, mac)
                logger.info("Initial gateway MAC: %s → %s", gw_ip, mac)
            else:
                logger.warning(
                    "Could not find MAC for gateway %s in ARP cache — "
                    "will learn from first observed ARP reply",
                    gw_ip,
                )

    def _get_mac_from_arp_cache(self, ip: str) -> Optional[str]:
        """Read MAC for an IP from the system ARP cache."""
        try:
            system = platform.system().lower()

            if system == "windows":
                result = subprocess.run(
                    ["arp", "-a", ip], capture_output=True, text=True, errors="ignore", timeout=5
                )
            else:
                result = subprocess.run(
                    ["arp", "-n", ip], capture_output=True, text=True, errors="ignore", timeout=5
                )

            import re
            # Match MAC address patterns (xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx)
            match = re.search(
                r"([\da-fA-F]{2}[:-]){5}[\da-fA-F]{2}", result.stdout
            )
            if match:
                return match.group(0).lower().replace("-", ":")

        except Exception as e:
            logger.debug("ARP cache lookup failed for %s: %s", ip, e)

        return None

    # ─────────────────────────────────────────────
    # Packet Processing Pipeline
    # ─────────────────────────────────────────────

    def _process_packet(self, packet):
        """
        Main packet processing callback — called by Scapy sniffer for each packet.
        This is the hot path — must be as efficient as possible.
        """
        if not self._running:
            return

        self._packets_processed += 1

        # ── Periodic Learning Phase Check (Every 500 packets to save time.time() calls) ──
        if self._is_learning and (self._packets_processed % 500 == 0):
            if time.time() > self._learning_until:
                self._is_learning = False
                logger.info("Learning phase complete — system in ACTIVE monitoring mode")

        try:
            # ── Efficient Layer Extraction ──
            ip_layer = packet.getlayer(IP)
            if ip_layer:
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                # Use faster Ether layer access if possible
                eth_layer = packet.getlayer(Ether)
                src_mac = eth_layer.src if eth_layer else "00:00:00:00:00:00"
                ttl = ip_layer.ttl
                self._behaviour_analyzer.record_packet(src_ip, src_mac, ttl)

                # ── Feed to Packet Capture Engine ──
                protocol = "OTHER"
                src_port = 0
                dst_port = 0

                tcp_layer = packet.getlayer('TCP')
                udp_layer = packet.getlayer('UDP')

                if tcp_layer:
                    protocol = "TCP"
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                elif udp_layer:
                    protocol = "UDP"
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport

                self._packet_capture.record_packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    src_port=src_port,
                    dst_port=dst_port,
                )

            # ── ARP Processing ──
            arp_layer = packet.getlayer(ARP)
            if arp_layer:
                self._arp_packets += 1
                event = self._arp_monitor.process_packet(packet)

                if event:
                    self._events_detected += 1
                    if not self._is_learning:
                        self._handle_arp_event(event)
                    else:
                        logger.debug("Learning phase: Suppressing ARP event from %s", event.source_ip)

            # ── Route to Advanced Monitors ──
            if self._config.advanced_modules_enabled and not self._is_learning:
                self._route_advanced_modules(packet)

        except Exception as e:
            # Avoid logging on every packet error to prevent flood, but record critical ones
            if self._packets_processed % 100 == 0:
                logger.error("Packet processing error: %s", e)

    def _handle_arp_event(self, event: ArpEvent):
        """
        Route an ARP event to the appropriate handler and risk scorer.

        Different event types carry different risk weights and may
        trigger additional verification steps.
        """
        cfg = self._config.risk_score

        if event.event_type == "mac_change":
            # ── MAC Change: Highest priority — may need active verification ──
            if event.source_ip in self._gateway_ips:
                # Gateway MAC changed — this is the most critical scenario
                # Trigger active verification before full scoring
                logger.warning(
                    "Gateway MAC change detected for %s — initiating verification",
                    event.source_ip,
                )
                self._verify_and_score_gateway(event)
            else:
                # Non-gateway MAC change — score directly but with lower weight
                self._risk_engine.add_score(
                    event.source_ip,
                    "mac_change",
                    cfg.weight_unverified_gateway_change * 0.5,  # Half weight for non-gateway
                    event.details,
                    mac=event.source_mac,
                )

        elif event.event_type == "flood":
            self._risk_engine.add_score(
                event.source_ip,
                "arp_flood",
                cfg.weight_arp_flood,
                event.details,
                mac=event.source_mac,
            )

        elif event.event_type == "duplicate_reply":
            self._risk_engine.add_score(
                event.source_ip,
                "duplicate_arp_reply",
                cfg.weight_duplicate_arp_reply,
                event.details,
                mac=event.source_mac,
            )

        elif event.event_type == "gratuitous":
            self._risk_engine.add_score(
                event.source_ip,
                "gratuitous_arp",
                cfg.weight_gratuitous_arp,
                event.details,
                mac=event.source_mac,
            )

        elif event.event_type == "unsolicited":
            self._risk_engine.add_score(
                event.source_ip,
                "unsolicited_arp_reply",
                cfg.weight_unsolicited_arp_reply,
                event.details,
                mac=event.source_mac,
            )

    def _route_advanced_modules(self, packet):
        """Route packets to advanced protocol monitors."""
        cfg = self._config.risk_score

        tls_ev = self._tls_monitor.process_packet(packet)
        if tls_ev:
            self._handle_advanced_event(tls_ev, "tls_tampering", cfg.weight_tls_tampering)

        dns_ev = self._dns_monitor.process_packet(packet)
        if dns_ev:
            self._handle_advanced_event(dns_ev, "dns_hijack", cfg.weight_dns_hijack)

        icmp_ev = self._icmp_monitor.process_packet(packet)
        if icmp_ev:
            self._handle_advanced_event(icmp_ev, "route_redirect", cfg.weight_route_redirect)

        ipv6_ev = self._ipv6_monitor.process_packet(packet)
        if ipv6_ev:
            self._handle_advanced_event(
                ipv6_ev, "ipv6_ndp_attack", cfg.weight_ipv6_ndp_attack,
                mac=getattr(ipv6_ev, 'source_mac', None)
            )

    def _handle_advanced_event(self, event, component_name, weight, mac=None):
        """Score an event from an advanced monitor."""
        self._risk_engine.add_score(
            event.source_ip,
            component_name,
            weight,
            event.details,
            mac=mac,
        )

    def _verify_and_score_gateway(self, event: ArpEvent):
        """
        Verify a gateway MAC change using active ARP probes.

        This is done in a separate thread to avoid blocking the sniffer.
        """
        def _verify():
            try:
                result = self._gateway_verifier.verify_gateway(
                    event.source_ip, event.source_mac
                )

                if result.is_legitimate:
                    # Legitimate change — update trusted MAC, low score
                    logger.info(
                        "Gateway %s MAC change VERIFIED as legitimate: %s",
                        event.source_ip,
                        event.source_mac,
                    )
                    self._arp_monitor.mark_verified(
                        event.source_ip, event.source_mac
                    )
                    # Small score for awareness (but not alerting level)
                    self._risk_engine.add_score(
                        event.source_ip,
                        "gateway_mac_change_verified",
                        5.0,  # Low weight — verified legitimate
                        f"Gateway MAC change verified: {event.details}",
                        mac=event.source_mac,
                    )
                else:
                    # Verification FAILED — high confidence attack!
                    logger.critical(
                        "Gateway %s MAC change FAILED verification! %s",
                        event.source_ip,
                        result.details,
                    )
                    self._risk_engine.add_score(
                        event.source_ip,
                        "gateway_mac_change_unverified",
                        self._config.risk_score.weight_unverified_gateway_change,
                        f"UNVERIFIED gateway MAC change: {result.details}",
                        mac=event.source_mac,
                    )

            except Exception as e:
                logger.error("Gateway verification error: %s", e)
                # Score with medium weight on verification failure
                self._risk_engine.add_score(
                    event.source_ip,
                    "gateway_mac_change_error",
                    self._config.risk_score.weight_unverified_gateway_change * 0.7,
                    f"Gateway MAC change — verification failed: {e}",
                )

        thread = threading.Thread(
            target=_verify, name="GatewayVerify", daemon=True
        )
        thread.start()

    def _on_risk_alert(
        self, ip: str, score: float, threat_level: str, details: list, mac: Optional[str] = None
    ):
        """
        Callback from RiskScoringEngine when score crosses threshold.
        Routes to the ResponseEngine for automated actions.
        """
        self._alerts_raised += 1
        self._response_engine.handle_alert(ip, score, threat_level, details, mac=mac)

    # ─────────────────────────────────────────────
    # Background Analysis Thread
    # ─────────────────────────────────────────────

    def _analysis_loop(self):
        """
        Periodic analysis loop running in background thread.

        Performs:
          1. Behaviour anomaly analysis
          2. Risk score decay
          3. Latency event processing
          4. ARP table cleanup
          5. Statistics reporting
        """
        analysis_interval = self._config.behaviour_analyzer.rate_window_seconds
        decay_interval = self._config.risk_score.decay_interval_seconds
        last_decay = time.time()
        last_stats = time.time()
        last_cleanup = time.time()

        while self._running:
            try:
                now = time.time()

                # ── Behaviour Analysis ──
                behaviour_events = self._behaviour_analyzer.analyze()
                for event in behaviour_events:
                    self._risk_engine.add_score(
                        event.source_ip,
                        "behaviour_anomaly",
                        self._config.risk_score.weight_behaviour_anomaly,
                        event.details,
                        mac=event.source_mac,
                    )

                # ── Latency Events ──
                latency_events = self._latency_monitor.drain_events()
                for event in latency_events:
                    # Latency drift applies to gateway IPs
                    self._risk_engine.add_score(
                        event.gateway_ip,
                        "latency_drift",
                        self._config.risk_score.weight_latency_drift,
                        event.details,
                    )

                # ── Packet Capture Analysis ──
                pc_events = self._packet_capture.analyze()
                cfg_rs = self._config.risk_score
                for pc_event in pc_events:
                    weight_map = {
                        "port_scan":           cfg_rs.weight_port_scan,
                        "port_flood":          cfg_rs.weight_port_flood,
                        "ddos_indicator":      cfg_rs.weight_ddos_indicator,
                        "sensitive_port":      cfg_rs.weight_sensitive_port,
                        "suspicious_external": cfg_rs.weight_suspicious_external,
                    }
                    weight = weight_map.get(pc_event.event_type, 10.0)
                    target_ip = pc_event.source_ip if pc_event.source_ip != "0.0.0.0" else (
                        self._gateway_ips[0] if self._gateway_ips else "0.0.0.0"
                    )
                    self._risk_engine.add_score(
                        target_ip,
                        pc_event.event_type,
                        weight,
                        pc_event.details,
                    )

                # ── WiFi Events (Advanced Module) ──
                if self._config.advanced_modules_enabled:
                    wifi_events = self._wifi_monitor.drain_events()
                    for event in wifi_events:
                        gw_ip = self._gateway_ips[0] if self._gateway_ips else "0.0.0.0"
                        self._risk_engine.add_score(
                            gw_ip,
                            "wifi_impersonation",
                            cfg_rs.weight_wifi_impersonation,
                            event.details,
                            mac=event.bssid,
                        )

                # ── Score Decay ──
                if (now - last_decay) >= decay_interval:
                    self._risk_engine.decay_scores()
                    last_decay = now

                # ── ARP Table Cleanup ──
                if (now - last_cleanup) >= 60.0:
                    self._arp_monitor.cleanup_stale(ttl=3600.0) # 1 hour TTL
                    last_cleanup = now

                # ── Periodic Stats ──
                if (now - last_stats) >= 60.0:
                    self._log_stats()
                    last_stats = now

            except Exception as e:
                logger.error("Analysis loop error: %s", e)

            # Sleep with clean shutdown support
            for _ in range(int(analysis_interval * 10)):
                if not self._running:
                    return
                time.sleep(0.1)

    def _watchdog_loop(self):
        """
        Periodically verifies gateway reachability and MAC integrity.
        Provides a self-validation layer for detection confidence.
        """
        interval = self._config.network.gateway_watchdog_interval
        
        while self._running:
            try:
                now = time.time()
                self._health_stats["last_watchdog_check"] = now

                for gw_ip in self._gateway_ips:
                    # 1. Passive check: check if we have seen traffic from this IP recently
                    # (Not implemented here, but could be)

                    # 2. Active check: Verify MAC still matches our baseline
                    cached_mac = self._arp_monitor.get_arp_table().get(gw_ip)
                    if cached_mac:
                        verification = self._gateway_verifier.verify_gateway(gw_ip, cached_mac.mac)
                        
                        if not verification.is_legitimate:
                            logger.critical("WATCHDOG: Gateway %s MAC integrity FAILED", gw_ip)
                            self._health_stats["gateway_reachable"] = False
                            # We don't raise it as a new event here because srp probes 
                            # would have already triggered handle_arp_event if they mismatched
                        else:
                            self._health_stats["gateway_reachable"] = True
                    
                    # 3. Connectivity check: Can we reach the internet?
                    # This is handled by ResponseEngine but good for health stats too
                
            except Exception as e:
                logger.error("Watchdog error: %s", e)

            # Sleep with clean shutdown support
            for _ in range(int(interval * 10)):
                if not self._running: return
                time.sleep(0.1)

    def _log_stats(self):
        """Log current detection statistics."""
        uptime = time.time() - (self._start_time or time.time())
        pc_stats = self._packet_capture.get_stats()
        logger.info(
            "Stats: uptime=%.0fs, pkts=%d (capture: %d), alerts=%d, gw_ok=%s, learning=%s",
            uptime,
            self._packets_processed,
            pc_stats["lifetime_packets"],
            self._alerts_raised,
            self._health_stats["gateway_reachable"],
            self._is_learning
        )

        # Log packet capture alert counts
        if any(v > 0 for v in pc_stats["lifetime_alerts"].values()):
            logger.info(
                "Packet Capture alerts: %s", pc_stats["lifetime_alerts"]
            )

        # Log current risk scores
        high_risk = self._risk_engine.get_high_risk_ips()
        if high_risk:
            for record in high_risk:
                logger.warning(
                    "Active threat: %s (score=%.1f, level=%s)",
                    record.ip,
                    record.total_score,
                    record.threat_level,
                )

    # ─────────────────────────────────────────────
    # Start / Stop
    # ─────────────────────────────────────────────

    def start_background_tasks(self):
        """
        Start the MITM background analysis threads.
        This does NOT start packet capture (sniffing is handled externally).
        """
        if self._running:
            logger.warning("Detector is already running")
            return

        self._running = True
        self._start_time = time.time()

        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║           MITM DETECTION ENGINE — ACTIVE                   ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║  Interface:  {self._interface:<47}║")
        print(f"║  Own IP:     {self._own_ip:<47}║")
        print(f"║  Gateway(s): {', '.join(self._gateway_ips):<47}║")
        print(f"║  Filter:     {self._config.network.sniff_filter:<47}║")
        print("╚══════════════════════════════════════════════════════════════╝\n")

        # ── Start Latency Monitor Thread ──
        self._latency_monitor.start()

        if self._config.advanced_modules_enabled:
            self._wifi_monitor.start()

        # ── Start Analysis Thread ──
        self._analysis_thread = threading.Thread(
            target=self._analysis_loop, name="AnalysisLoop", daemon=True
        )
        self._analysis_thread.start()

        # ── Start Watchdog Thread ──
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop, name="Watchdog", daemon=True
        )
        self._watchdog_thread.start()

        logger.info("MITM background tasks started successfully.")

    def stop(self):
        """Stop the detection system gracefully."""
        if not self._running:
            return

        logger.info("Stopping MITM Detector...")
        self._running = False

        # Stop threads
        self._latency_monitor.stop()
        if self._config.advanced_modules_enabled:
            self._wifi_monitor.stop()

        # Wait for threads
        for t in [self._analysis_thread, self._watchdog_thread]:
            if t and t.is_alive():
                t.join(timeout=2)

        # Final stats
        self._log_stats()

        # Export final scores
        scores_json = self._risk_engine.export_scores_json()
        if scores_json != "{}":
            logger.info("Final risk scores:\n%s", scores_json)
            try:
                with open("mitm_final_scores.json", "w") as f:
                    f.write(scores_json)
            except Exception:
                pass

        print("\n✅ MITM Detector stopped cleanly.")

    # ─────────────────────────────────────────────
    # IDS Integration API
    # ─────────────────────────────────────────────

    def register_ids_consumer(self, callback: Callable):
        """
        Register an external IDS consumer for risk score notifications.

        The callback will be called as:
            callback(ip: str, score: float)

        whenever an IP crosses the HIGH risk threshold.
        """
        self._risk_engine.register_consumer(callback)
        logger.info("Registered IDS consumer: %s", callback.__name__)

    def get_risk_scores(self):
        """Get all current risk scores (for IDS dashboard)."""
        return self._risk_engine.get_all_scores()

    def get_active_blocks(self):
        """Get all currently blocked IPs."""
        return self._response_engine.get_active_blocks()

    def get_arp_table(self):
        """Get the current ARP table."""
        return self._arp_monitor.get_arp_table()

    def get_stats(self):
        """Get current detection statistics."""
        pc_stats = self._packet_capture.get_stats()
        return {
            "packets_processed": self._packets_processed,
            "arp_packets": self._arp_packets,
            "events_detected": self._events_detected,
            "alerts_raised": self._alerts_raised,
            "start_time": self._start_time,
            "uptime": time.time() - (self._start_time or time.time()),
            "packet_capture": pc_stats,
        }

    def get_traffic_snapshot(self):
        """Get latest traffic snapshot from packet capture engine."""
        return self._packet_capture.get_latest_snapshot()
