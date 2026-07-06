import time
import os
import copy
import logging
import threading
import pandas as pd
import scapy.all as scapy
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import sys
root_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(root_dir)
sys.path.append(os.path.join(root_dir, 'model'))
sys.path.append(os.path.join(root_dir, 'DDoS-engine'))
sys.path.append(os.path.join(root_dir, 'MITM-engine'))

from feature_extractor import FeatureExtractor
from decision_engine import DecisionEngine
from mitm_config import MitmConfig
from mitm_detector import MitmDetector
from logger import setup_logger
from advanced_nids import AdvancedNIDSEngine
from package_analyser import TrafficAnalyser
from ip_blocker import IPBlocker
import joblib
import json
from groq_explainer import explain_alert
from security_pipeline import SecurityPipeline

# MongoDB Logging
from mongo_logger import setup_mongo_logging

def load_model_safe(path):
    if os.path.exists(path):
        try:
            return joblib.load(path)
        except Exception as e:
            print(f"Failed to load model from {path}: {e}")
            return None
    return None

# Disable scapy's verbose output
scapy.conf.verb = 0

logger = setup_logger("batch_pipeline")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Enable Global MongoDB Logging
setup_mongo_logging(logger_name=None, collection_name="system_logs")

class Batch10sPipeline:
    def __init__(self, interface=None):
        self.interface = interface
        self.batch_duration = 10.0
        self.packet_buffer = []
        self.buffer_lock = threading.Lock()
        
        # 1. Initialize ML components & Decision Engine
        self.decision_engine = DecisionEngine(eval_mode=False)
        self.models_dir = os.path.join(os.path.dirname(__file__), "model")
        self.xgb_model = self._load_model("xgboost.pkl")
        self.if_model = self._load_model("isolation_forest.pkl")
        
        # 2. MITM Config
        mitm_config = MitmConfig()
        if interface:
            mitm_config.network.interface = interface
        self.mitm_detector = MitmDetector(mitm_config)
        self.mitm_risk_buffer = {} # ip -> risk_score

        # 3. Work Directory Engines (DDoS & Visual Reporting)
        self.advanced_ddos_engine = AdvancedNIDSEngine()
        self.traffic_analyser = TrafficAnalyser(debug=False)

        # 3.5. Cyber Defense AI — 10-Layer Flow-Based Security Pipeline V3
        self.security_pipeline = SecurityPipeline()

        # 4. IP Blocker (OS-level firewall integration)
        self.ip_blocker = None  # Initialized after DB setup in _init_db()

        # We'll rely on the standalone feature extraction logic for standard processing
        # Provide a dummy queue because FeatureExtractor expects it, but we'll use a direct call.
        from queue import Queue
        self.dummy_q1 = Queue()
        self.dummy_q2 = Queue()
        self.extractor = FeatureExtractor(self.dummy_q1, self.dummy_q2, window_size_sec=self.batch_duration)
        
        self.csv_log_file = os.path.join(os.path.dirname(__file__), "stimulater", "batch_10s_logs.csv")
        self.local_ip = self._get_local_ip()
        self._init_db()

    def _init_db(self):
        try:
            from pymongo import MongoClient
            from dotenv import load_dotenv
            load_dotenv()
            mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
            self.mongo_client = MongoClient(mongo_uri)
            self.db = self.mongo_client["IDS"]
            self.collection = self.db["batch_logs"]
            self.blocked_collection = self.db["blocked_alerts"]
            self.pipeline_collection = self.db["pipeline_results"]
            self.use_mongo = True
        except ImportError:
            print("pymongo not installed, falling back to CSV.")
            self.use_mongo = False
        except Exception as e:
            print(f"Failed to connect to MongoDB: {e}. Falling back to CSV.")
            self.use_mongo = False

        # Initialize IP Blocker with MongoDB and trusted IPs
        trusted_ips_path = os.path.join(
            os.path.dirname(__file__), "DDoS-engine", "trusted_ips.json"
        )
        self.ip_blocker = IPBlocker(
            mongo_db=self.db if self.use_mongo else None,
            block_duration=600,  # 10 minutes
            trusted_ips_file=trusted_ips_path,
        )
            
        if not self.use_mongo:
            if not os.path.exists(self.csv_log_file):
                with open(self.csv_log_file, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Timestamp", "Source_IP", "Dest_IP", "PPS", "MITM_Risk", "ML_Risk", "Final_Risk", "Decision", "Attack_Type", "Reasons"])

    def _load_model(self, name):
        bundle = load_model_safe(os.path.join(self.models_dir, name))
        return bundle if bundle else None

    def _get_local_ip(self):
        """Auto-detect the local primary network IP."""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Use Google DNS to determine primary routing interface
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def start(self):
        local_ip = self._get_local_ip()
        print(f"\n=============================================")
        print(f"🚀 Starting Unified 10-Second Batch AI-IDS Pipeline")
        print(f"🛡️  DEFENDER SYSTEM IP: {local_ip}")
        print(f"Interface: {self.interface or 'All'}")
        print(f"Logging to: {self.csv_log_file}")
        print(f"DDoS Output: 📊 Visual Terminal Summaries | 📂 security_alerts.csv")
        print(f"=============================================\n")

        # Start background MITM Tasks (ARP pinging etc.)
        self.mitm_detector.start_background_tasks()

        # Start the Advanced NIDS monitors from the work/ folder
        threading.Thread(target=self.advanced_ddos_engine.monitor_loop, daemon=True).start()

        # Start the batch timer string
        threading.Thread(target=self._batch_timer_loop, daemon=True).start()

        # Start Sniffing
        print("Listening for packets... (Reports appear every 10 seconds)\n")
        try:
            scapy.sniff(iface=self.interface, prn=self._sniff_callback, store=0)
        except KeyboardInterrupt:
            print("\nShutting down 10-second pipeline.")

    def _sniff_callback(self, packet):
        # Pass to the DDoS engine and Traffic Analyzer first
        self.traffic_analyser.process_packet(packet)
        self.advanced_ddos_engine.packet_callback(packet)
        
        # Extremely fast callback: lock, append, release
        with self.buffer_lock:
            self.packet_buffer.append(packet)

    def _batch_timer_loop(self):
        while True:
            time.sleep(self.batch_duration)
            self._process_batch()

    def _process_batch(self):
        with self.buffer_lock:
            # take a snapshot of packets and clear buffer
            batch_packets = self.packet_buffer[:]
            self.packet_buffer.clear()

        batch_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if not batch_packets:
            print(f"[{batch_time}]  — {self.batch_duration}s Window: 0 Packets (Clean)")
            return
            
        # 1. First, print the visual DDoS traffic report from package_analyser
        report = self.traffic_analyser.get_report()
        self.traffic_analyser.print_visual_report(report)

        # 2. Execute MITM and ML concurrently on the buffer
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_mitm = executor.submit(self._run_mitm_engine, batch_packets)
            future_ml = executor.submit(self._run_ml_ddos_engine, batch_packets)
            
            # Wait for both to complete
            mitm_results = future_mitm.result()
            ml_results = future_ml.result()

        # 3. Print combined MITM & DDoS result
        self._evaluate_and_log(batch_time, ml_results, mitm_results)

    def _run_mitm_engine(self, packets):
        """Thread 1: Feed packets to MITM Engine."""
        # Because mitm_detector usually uses an async/event model, we will simulate
        # feeding it the batch and reading out its current IP scores.
        for pkt in packets:
            self.mitm_detector._process_packet(pkt)
        
        # Read the internal threat scores for the current IPs from the Risk Engine
        mitm_scores = {}
        all_scores = self.mitm_detector.get_risk_scores()
        for ip, record in all_scores.items():
            # Normalized score for decision engine (0.0 to 1.0)
            mitm_scores[ip] = max(0.0, min(record.total_score / 100.0, 1.0))
        return mitm_scores

    def _run_ml_ddos_engine(self, packets):
        """Thread 2: Extract features per IP and run ML inference."""
        # Convert to FeatureExtractor format
        valid_pkts = []
        for pkt in packets:
            if scapy.IP in pkt:
                info = {
                    'src_ip': pkt[scapy.IP].src,
                    'dst_ip': pkt[scapy.IP].dst,
                    'size': len(pkt),
                    'timestamp': float(pkt.time),
                    'protocol': "TCP" if scapy.TCP in pkt else ("UDP" if scapy.UDP in pkt else "ICMP")
                }
                if scapy.TCP in pkt:
                    info['flags'] = pkt[scapy.TCP].flags
                    info['src_port'] = pkt[scapy.TCP].sport
                    info['dst_port'] = pkt[scapy.TCP].dport
                elif scapy.UDP in pkt:
                    info['src_port'] = pkt[scapy.UDP].sport
                    info['dst_port'] = pkt[scapy.UDP].dport
                valid_pkts.append(info)
                
        if not valid_pkts:
            return pd.DataFrame()

        df_raw = pd.DataFrame(valid_pkts)
        
        # Group by Source IP
        ip_groups = df_raw.groupby('src_ip')
        all_features = []
        
        for src_ip, df_group in ip_groups:
            feats = self.extractor._extract_features(df_group)
            if feats:
                all_features.append(feats)
                
        if not all_features:
            return pd.DataFrame()
            
        df_features = pd.DataFrame(all_features)
        
        # ML Inference
        if self.xgb_model and len(self.xgb_model) > 1:
            train_cols = self.xgb_model[1]
            X = df_features.reindex(columns=train_cols, fill_value=0)
            try:
                probs = self.xgb_model[0].predict_proba(X)
                df_features['xgb_prob'] = probs[:, 1]
            except:
                df_features['xgb_prob'] = 0.05
        else:
            df_features['xgb_prob'] = 0.05

        if self.if_model and len(self.if_model) > 1:
            train_cols = self.if_model[1]
            X = df_features.reindex(columns=train_cols, fill_value=0)
            try:
                df_features['if_anomaly'] = self.if_model[0].predict(X)
            except:
                df_features['if_anomaly'] = 1
        else:
            df_features['if_anomaly'] = 1
            
        return df_features

    def _evaluate_and_log(self, batch_time, df_features, mitm_scores):
        table_output = []
        logs_to_write = []

        # We need sum of all packets to find global SYN count
        global_syn_count = 0
        if 'syn_flag_ratio' in df_features.columns and 'packet_count' in df_features.columns:
            global_syn_count = int((df_features['syn_flag_ratio'] * df_features['packet_count']).sum())
            
        global_pps = df_features['packet_rate'].sum() if 'packet_rate' in df_features.columns else 0
        # Get unique IPs from both sources
        all_active_ips = set(df_features['src_ip'].unique()) if not df_features.empty else set()
        all_active_ips.update(mitm_scores.keys())

        unique_ips = len(all_active_ips)

        for src_ip in all_active_ips:
            if src_ip == self.local_ip:
                continue
            # Try to get row from df_features
            rows = df_features[df_features['src_ip'] == src_ip] if not df_features.empty else pd.DataFrame()
            
            if not rows.empty:
                row = rows.iloc[0]
                dst_ip = row['dst_ip']
                pps = row['packet_rate']
                syn_ratio = row.get('syn_flag_ratio', 0.0)
                byte_rate = row.get('byte_rate', 0)
                xgb_score = row.get('xgb_prob', 0) * 100.0
                if_anomaly = (row.get('if_anomaly', 1) == -1)
                conn_flag = row.get('session_pattern', 'SF').split('-')[-1] if '-' in row.get('session_pattern', '') else 'SF'
            else:
                # MITM only or incomplete data
                dst_ip = "Unknown"
                pps = 0.0
                syn_ratio = 0.0
                byte_rate = 0
                xgb_score = 0
                if_anomaly = False
                conn_flag = "SF"

            mitm_risk = mitm_scores.get(src_ip, 0.0)
            
            # Decision Engine (State track + fusion)
            result = self.decision_engine.evaluate(
                xgb_score=xgb_score / 100.0,
                if_anomaly=if_anomaly,
                ae_mse=0.0,
                ae_baseline=1.0,
                spike_zscore=0.0,
                syn_ratio=syn_ratio,
                pps=pps,
                byte_rate=byte_rate,
                connection_flag=conn_flag,
                ip_address=src_ip,
                dst_ip=dst_ip,
                mitm_risk=mitm_risk,
                unique_src_ips=1,
                global_pps=global_pps,
                global_syn_count=global_syn_count
            )

            decision = result.get('decision', 'allow')
            final_risk = result.get('risk_score', 0.0)
            ml_risk = result.get('ml_risk', 0.0)
            engine_rating = result.get('engine_rating', 0.0)
            model_rating = result.get('model_rating', 0.0)
            attack_type = result.get('attack_type', 'Normal')
            reasons = " | ".join(result.get('reason', []))

            # ═════════════════════════════════════════════════════════
            # 🛡️ CYBER DEFENSE AI — 10-Layer Flow-Based Security Pipeline V3
            # ═════════════════════════════════════════════════════════
            features_dict = {}
            if not rows.empty:
                for col in rows.columns:
                    try:
                        features_dict[col] = float(row.get(col, 0))
                    except (TypeError, ValueError):
                        pass

            # Extract src_port and dst_port for 5-tuple flow key
            pkt_src_port = 0
            pkt_dst_port = 0
            pkt_protocol = "TCP"
            if not rows.empty:
                pkt_dst_port = int(row.get('dst_port', 0)) if 'dst_port' in row.index else 0
                pkt_src_port = int(row.get('src_port', 0)) if 'src_port' in row.index else 0
                pkt_protocol = str(row.get('protocol', 'TCP')) if 'protocol' in row.index else 'TCP'

            pipeline_result = self.security_pipeline.process_flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                features=features_dict,
                xgb_score=xgb_score / 100.0,
                if_anomaly=if_anomaly,
                decision_engine_result=result,
                mitm_risk=mitm_risk,
                pps=pps,
                syn_ratio=syn_ratio,
                protocol=pkt_protocol,
                src_port=pkt_src_port,
                dst_port=pkt_dst_port,
                was_recently_blocked=(self.ip_blocker.is_blocked(src_ip) if self.ip_blocker else False),
            )

            # Use pipeline output for final decision
            pipeline_action = pipeline_result.action
            pipeline_attack = pipeline_result.attack_type
            pipeline_risk = pipeline_result.timing.total_detection_time_ms

            log_row = [batch_time, src_ip, dst_ip, round(pps, 1), round(mitm_risk, 2), round(ml_risk, 2), round(final_risk, 2), pipeline_action, pipeline_attack, reasons]
            logs_to_write.append(log_row)

            # Log strict JSON pipeline output to MongoDB
            if getattr(self, "use_mongo", False):
                try:
                    pipeline_doc = pipeline_result.to_extended_dict()
                    pipeline_doc["Timestamp"] = batch_time
                    pipeline_doc["batch_id"] = batch_time
                    self.pipeline_collection.insert_one(pipeline_doc)
                except Exception as e:
                    pass  # Non-blocking

            # 🔒 FIREWALL BLOCK / ISOLATE
            effective_decision = pipeline_action.lower()
            if effective_decision in ("block", "isolate"):
                if self.ip_blocker and not self.ip_blocker.is_blocked(src_ip):
                    block_duration = 1200 if effective_decision == "isolate" else 600
                    self.ip_blocker.block_ip(ip=src_ip, reason=pipeline_attack, severity=final_risk, duration=block_duration)
                
                # 🛡️ DEDICATED BLOCKED DATA LOGGING
                if getattr(self, "use_mongo", False):
                    self.blocked_collection.insert_one({
                        "Timestamp": batch_time,
                        "Source_IP": src_ip,
                        "Dest_IP": dst_ip,
                        "PPS": pps,
                        "MITM_Risk": mitm_risk,
                        "ML_Risk": ml_risk,
                        "Final_Risk": final_risk,
                        "Decision": pipeline_action,
                        "Attack_Type": pipeline_attack,
                        "Reasons": reasons,
                        "anomaly_score": pipeline_result.anomaly_score,
                        "is_zero_day": pipeline_result.is_zero_day,
                        "confidence": pipeline_result.confidence,
                        "risk_level": pipeline_result.risk_level,
                        "pipeline_timing_ms": pipeline_result.timing.total_response_time_ms,
                    })

            # Unified Terminal Report (with pipeline timing)
            if effective_decision != "allow" or mitm_risk > 0.1:
                icon = "🚨" if effective_decision in ("block", "isolate") else ("⚠️" if effective_decision == "throttle" else "🔔")
                timing_str = f"{pipeline_result.timing.total_response_time_ms:.2f}ms"
                zd_flag = " 🔴ZD" if pipeline_result.is_zero_day else ""
                table_output.append(
                    f"  {icon} {src_ip:<15} -> {dst_ip:<15} | PPS: {pps:<6.1f} | "
                    f"Risk: {pipeline_result.risk_level:<8} | Action: {pipeline_action:<8} | "
                    f"Type: {pipeline_attack:<16} | ⏱️{timing_str}{zd_flag}"
                )
                # 🧠 XAI: Non-blocking Groq explanation for every meaningful alert
                explain_alert(
                    src_ip=src_ip, dst_ip=dst_ip, pps=pps,
                    mitm_risk=mitm_risk, ml_risk=ml_risk,
                    final_risk=final_risk, decision=effective_decision,
                    attack_type=pipeline_attack,
                    reasons=result.get('reason', []),
                    mongo_collection=self.collection if getattr(self, "use_mongo", False) else None,
                    query={"Source_IP": src_ip, "Timestamp": batch_time},
                    secondary_collection=self.blocked_collection if (effective_decision in ("block", "isolate") and getattr(self, "use_mongo", False)) else None
                )

        # Write to Database or CSV
        if logs_to_write:
            if getattr(self, "use_mongo", False):
                try:
                    docs = []
                    for row in logs_to_write:
                        docs.append({
                            "Timestamp": row[0],
                            "Source_IP": row[1],
                            "Dest_IP": row[2],
                            "PPS": row[3],
                            "MITM_Risk": row[4],
                            "ML_Risk": row[5],
                            "Final_Risk": row[6],
                            "Decision": row[7],
                            "Attack_Type": row[8],
                            "Reasons": row[9]
                        })
                    self.collection.insert_many(docs)
                except Exception as e:
                    print(f"MongoDB Insert Error: {e}")
            else:
                with open(self.csv_log_file, "a", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerows(logs_to_write)

        # Print Terminal Output
        if table_output:
            stats = self.security_pipeline.get_pipeline_stats()
            avg_ms = stats.get('avg_total_response_ms', 0)
            print(f"  ╔══ 10-SECOND THREAT REPORT ══╗  Pipeline: {stats['total_flows_processed']} flows | Avg: {avg_ms:.3f}ms")
            for line in table_output:
                print(line)
            print(f"  ╚══════════════════════════════╝")
        else:
            print(f"  ✅ No threats detected in {unique_ips} active IPs.")

if __name__ == "__main__":
    pipeline = Batch10sPipeline()
    pipeline.start()
