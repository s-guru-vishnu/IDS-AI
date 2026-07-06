import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd
import numpy as np
import re
import csv
import json
import time
import threading
import hashlib
import urllib.parse
from collections import defaultdict, deque
from datetime import datetime
import socket
from scapy.all import get_if_addr, conf

import os
# ================= CONFIGURATION =================
WINDOW_SIZE = 10  
HIST_MAXLEN = 100  
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(_root, "stimulater", "security_alerts.csv")
JSON_SUMMARY = os.path.join(_root, "stimulater", "nids_summary.json")
WAF_PORTS = {80, 8080, 443}

# Detect Local IP
try:
    MY_IP = get_if_addr(conf.iface)
except:
    try:
        MY_IP = socket.gethostbyname(socket.gethostname())
    except:
        MY_IP = "127.0.0.1"

# Regex Patterns for WAF
SQLI_REGEX = re.compile(r"(union select|or 1=1|select|drop table)", re.IGNORECASE)
XSS_REGEX = re.compile(r"(<script>|alert\(|onerror)", re.IGNORECASE)

# ================= UTILS =================
def normalize_payload(payload):
    try:
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode('utf-8', errors='ignore')
        decoded = urllib.parse.unquote(str(payload))
        return decoded.lower().strip().replace('\x00', '')
    except Exception:
        return str(payload).lower()

def hash_payload(payload):
    """Produces SHA256 of normalized payload for signature tracking."""
    return hashlib.sha256(payload.encode()).hexdigest()

# ================= MODULES =================
class AdaptiveThresholder:
    def __init__(self, maxlen=HIST_MAXLEN):
        self.history = defaultdict(lambda: deque(maxlen=maxlen))

    def update_and_check(self, src_ip, current_count):
        hist = self.history[src_ip]
        if len(hist) < 2:  # Reduced for demo/simulation purposes
            hist.append(current_count)
            return 0
        series = pd.Series(list(hist))
        mean, std = series.mean(), series.std()
        threshold = mean + (2 * (std if std > 1 else 1.0))
        severity = 0
        if current_count > threshold:
            deviation = (current_count - mean) / (std if std > 0 else 1)
            severity = min(10, int(3 + (deviation / 2)))
        hist.append(current_count)
        return severity

class HandshakeMonitor:
    def __init__(self, maxlen=HIST_MAXLEN):
        # Rolling averages for the handshake ratio
        self.stats = defaultdict(lambda: {'syn_ack_sent': 0, 'ack_received': 0})
        self.ratio_history = defaultdict(lambda: deque(maxlen=maxlen))

    def track(self, packet):
        if not packet.haslayer(TCP): return
        flags, src, dst = packet[TCP].flags, packet[IP].src, packet[IP].dst
        if src == MY_IP and flags & 0x12 == 0x12:
            self.stats[dst]['syn_ack_sent'] += 1
        elif dst == MY_IP and flags & 0x10 == 0x10 and not (flags & 0x02):
            self.stats[src]['ack_received'] += 1

    def detect_syn_flood(self, ip):
        data = self.stats[ip]
        sent, received = data['syn_ack_sent'], data['ack_received']
        if sent > 20:
            ratio = received / sent if sent > 0 else 1
            self.ratio_history[ip].append(ratio)
            # Check if rolling average of completion is low
            avg_completion = pd.Series(list(self.ratio_history[ip])).mean()
            if avg_completion < 0.2:
                return min(9, 6 + int((1 - avg_completion) * 3))
        return 0

# ================= NIDS ENGINE =================
class AdvancedNIDSEngine:
    def __init__(self):
        self.tcp_thresholder = AdaptiveThresholder()
        self.udp_thresholder = AdaptiveThresholder()
        self.handshake = HandshakeMonitor()
        self.lock = threading.Lock()
        self.my_ip = MY_IP
        
        self.window_stats = defaultdict(lambda: {
            'tcp_count': 0, 'udp_count': 0, 
            'waf_hits': 0, 'payload_hash': "", 'snippet': ""
        })
        
        # Database initialization
        try:
            from pymongo import MongoClient
            from dotenv import load_dotenv
            load_dotenv()
            mongo_uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
            self.mongo_client = MongoClient(mongo_uri)
            self.db = self.mongo_client["AI-IDS"]
            self.collection = self.db["security_alerts"]
            self.use_mongo = True
        except ImportError:
            self.use_mongo = False
        except Exception as e:
            print(f"Failed to connect to MongoDB: {e}")
            self.use_mongo = False

    def packet_callback(self, packet):
        if not IP in packet: return
        src_ip = packet[IP].src
        
        # 🤝 Handshake & Protocols
        if packet.haslayer(TCP):
            self.handshake.track(packet)
            with self.lock: self.window_stats[src_ip]['tcp_count'] += 1
        elif packet.haslayer(UDP):
            with self.lock: self.window_stats[src_ip]['udp_count'] += 1

        # 📄 Payload & WAF
        if packet.haslayer(scapy.Raw):
            raw_data = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            norm = normalize_payload(raw_data)
            if SQLI_REGEX.search(norm) or XSS_REGEX.search(norm):
                with self.lock:
                    self.window_stats[src_ip]['waf_hits'] += 1
                    self.window_stats[src_ip]['payload_hash'] = hash_payload(norm)
                    self.window_stats[src_ip]['snippet'] = norm[:50]

    def log_alert(self, ip, attack, severity, snippet="", p_hash=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if getattr(self, "use_mongo", False):
            try:
                self.collection.insert_one({
                    "Timestamp": timestamp,
                    "Source_IP": ip,
                    "Attack_Type": attack,
                    "Severity_Score": severity,
                    "Payload_Snippet": snippet,
                    "Payload_Hash": p_hash
                })
            except Exception as e:
                print(f"MongoDB Insert Error: {e}")
        else:
            with open(LOG_FILE, 'a', newline='') as f:
                csv.writer(f).writerow([timestamp, ip, attack, severity, snippet, p_hash])
                
        print(f"[{timestamp}] 🚨 SEVERITY {severity}: {attack} from {ip}!")

    def monitor_loop(self):
        if not getattr(self, "use_mongo", False):
            try:
                with open(LOG_FILE, 'x', newline='') as f:
                    csv.writer(f).writerow(['Timestamp', 'Source_IP', 'Attack_Type', 'Severity_Score', 'Payload_Snippet', 'Payload_Hash'])
            except FileExistsError: pass

        while True:
            time.sleep(WINDOW_SIZE)
            with self.lock:
                current_window = dict(self.window_stats)
                self.window_stats.clear()
                # We don't clear handshake stats, they use rolling avg ratio

            summary_data = []

            for ip, stats in current_window.items():
                if ip == self.my_ip:
                    continue
                attack_vectors = []
                final_severity = 0

                # 1. TCP Volumetric
                tcp_sev = self.tcp_thresholder.update_and_check(ip, stats['tcp_count'])
                if tcp_sev > 0:
                    attack_vectors.append("TCP_FLOOD")
                    final_severity = max(final_severity, tcp_sev)

                # 2. UDP Volumetric (Diversity)
                udp_sev = self.udp_thresholder.update_and_check(ip, stats['udp_count'])
                if udp_sev > 0:
                    attack_vectors.append("UDP_FLOOD")
                    final_severity = max(final_severity, udp_sev)

                # 3. Half-Open (Rolling Avg)
                syn_sev = self.handshake.detect_syn_flood(ip)
                if syn_sev > 0:
                    attack_vectors.append("HALF_OPEN_ATTACK")
                    final_severity = max(final_severity, syn_sev)

                # 4. WAF (Normalization + Hashing)
                if stats['waf_hits'] > 0:
                    attack_vectors.append("WAF_INJECTION")
                    final_severity = max(final_severity, 8)

                # 🧠 MULTI-VECTOR CORRELATION
                if len(attack_vectors) > 1:
                    attack_type = "CORRELATED_ATTACK (" + "|".join(attack_vectors) + ")"
                    self.log_alert(ip, attack_type, 10, stats['snippet'], stats['payload_hash'])
                elif attack_vectors:
                    self.log_alert(ip, attack_vectors[0], final_severity, stats['snippet'], stats['payload_hash'])

                if attack_vectors:
                    summary_data.append({"ip": ip, "vectors": attack_vectors, "severity": final_severity})

            # JSON Export for Dashboard/Grafana-ready output
            with open(JSON_SUMMARY, 'w') as jf:
                json.dump({"timestamp": str(datetime.now()), "alerts": summary_data}, jf)

    def run(self):
        print(f"🛡️ Advanced NIDS V3 starting... Multi-Vector Correlation: ON")
        print(f"Server IP: {MY_IP} | Tracking Protocols: TCP, UDP | Exporting: CSV, JSON")
        threading.Thread(target=self.monitor_loop, daemon=True).start()
        # Start Sniff (Performance optimized with iface=None for multi-adapter support)
        try:
            # We filter for tcp or udp and listen on ALL interfaces to catch loopback traffic
            scapy.sniff(iface=None, prn=self.packet_callback, store=0, filter="tcp or udp")
        except Exception as e: print(f"❌ Error: {e}")

if __name__ == "__main__":
    AdvancedNIDSEngine().run()
