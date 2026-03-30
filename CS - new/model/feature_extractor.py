import pandas as pd
import numpy as np
from queue import Queue, Empty
import time
import threading
from typing import Optional, Dict, Any
import sys, os
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(root_dir, 'DDoS-engine'))
from logger import setup_logger

logger = setup_logger(__name__)

class FeatureExtractor:
    def __init__(self, packet_queue: Queue, feature_queue: Queue, window_size_sec=1.0):
        self.packet_queue = packet_queue
        self.feature_queue = feature_queue
        self.window_size_sec = window_size_sec
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.connection_states = {} # Tracks first timestamp for (src_ip, dst_ip)

    def _extract_features(self, df):
        if df.empty:
            return None
        
        features: Dict[str, Any] = {}
        features['packet_count'] = len(df)
        features['total_bytes'] = int(df['size'].sum())
        features['packet_rate'] = features['packet_count'] / self.window_size_sec
        features['byte_rate'] = features['total_bytes'] / self.window_size_sec
        
        # (Moved identity metadata to end to preserve CSV column order)
        
        # (UA/Session moved to end)
        
        features['avg_packet_size'] = float(df['size'].mean())
        features['std_packet_size'] = float(df['size'].std()) if len(df) > 1 else 0.0
        features['min_packet_size'] = float(df['size'].min())
        features['max_packet_size'] = float(df['size'].max())
        
        proto_counts = df['protocol'].value_counts(normalize=True)
        features['tcp_ratio'] = float(proto_counts.get('TCP', 0.0))
        features['udp_ratio'] = float(proto_counts.get('UDP', 0.0))
        features['icmp_ratio'] = float(proto_counts.get('ICMP', 0.0))
        
        tcp_count = len(df[df['protocol'] == 'TCP'])
        if 'flags' in df.columns and tcp_count > 0:
            flags_str = df['flags'].astype(str)
            features['syn_flag_ratio'] = float(flags_str.str.contains('S').sum() / tcp_count)
            features['ack_flag_ratio'] = float(flags_str.str.contains('A').sum() / tcp_count)
            features['fin_flag_ratio'] = float(flags_str.str.contains('F').sum() / tcp_count)
            features['rst_flag_ratio'] = float(flags_str.str.contains('R').sum() / tcp_count)
        else:
            features['syn_flag_ratio'] = 0.0
            features['ack_flag_ratio'] = 0.0
            features['fin_flag_ratio'] = 0.0
            features['rst_flag_ratio'] = 0.0
            
        features['unique_src_ips'] = int(df['src_ip'].nunique())
        features['unique_dst_ips'] = int(df['dst_ip'].nunique())
        src_ips_list = list(df['src_ip'].unique()) # Temp list
        dst_ips_list = list(df['dst_ip'].unique()) # Temp list
        
        if 'src_port' in df.columns:
            features['unique_src_ports'] = int(df['src_port'].nunique())
            features['unique_dst_ports'] = int(df['dst_port'].nunique())
        else:
            features['unique_src_ports'] = 0
            features['unique_dst_ports'] = 0

        features['pkts_per_src_ip'] = features['packet_count'] / features['unique_src_ips'] if features['unique_src_ips'] > 0 else 0.0
        
        # Timing features
        # df may not be sorted exactly by timestamp if multi-threaded queue, so sort just in case
        df_sorted = df.sort_values(by='timestamp')
        if len(df_sorted) > 1:
            iats = df_sorted['timestamp'].diff().dropna()
            features['iat_mean'] = float(iats.mean())
            features['iat_std'] = float(iats.std())
            features['burst_count'] = int((iats < (self.window_size_sec / 100.0)).sum())
        else:
            features['iat_mean'] = 0.0
            features['iat_std'] = 0.0
            features['burst_count'] = 0
        
        # V69: Vectorized Connection Duration (was df.iterrows — 5-10x faster)
        if not df.empty and 'src_ip' in df.columns and 'dst_ip' in df.columns:
            df_conn = df[['src_ip', 'dst_ip', 'timestamp']].copy()
            df_conn['conn_key'] = df_conn['src_ip'].astype(str) + '-' + df_conn['dst_ip'].astype(str)
            
            # Get first-seen timestamp for each connection from state
            first_ts = df_conn.groupby('conn_key')['timestamp'].first()
            for key, ts in first_ts.items():
                if key not in self.connection_states:
                    self.connection_states[key] = ts
            
            # Vectorized duration calculation
            df_conn['first_seen'] = df_conn['conn_key'].map(self.connection_states)
            df_conn['duration'] = df_conn['timestamp'] - df_conn['first_seen']
            features['connection_duration'] = float(df_conn['duration'].mean()) if not df_conn['duration'].empty else 0.0
        else:
            features['connection_duration'] = 0.0
        
        # V69: LRU-style eviction (keep most recent 5000 instead of hard clear at 10K)
        if len(self.connection_states) > 5000:
            # Keep only the 2500 most recently added entries
            keys = list(self.connection_states.keys())
            for k in keys[:len(keys) - 2500]:
                del self.connection_states[k]
            
        # Standard Schema Order:
        # 1-24: Core features (packet_count ... connection_duration)
        # 25: timestamp (placeholder, filled in process_loop)
        # 26: src_ip
        # 27: dst_ip
        # 28: user_agent
        # 29: session_pattern
        # 30: label (filled in training/audit)

        features['timestamp'] = time.time() # Default
        
        features['src_ip'] = df['src_ip'].mode().iloc[0] if not df['src_ip'].empty else None
        features['dst_ip'] = df['dst_ip'].mode().iloc[0] if not df['dst_ip'].empty else None
        
        if 'user_agent' in df.columns:
            ua_series = df['user_agent'].dropna()
            features['user_agent'] = ua_series.iloc[0] if not ua_series.empty else None
        else:
            features['user_agent'] = None
        
        proto_mode = df['protocol'].mode()
        mode_proto = proto_mode.iloc[0] if not proto_mode.empty else "UNKNOWN"

        mode_port = 0
        if 'dst_port' in df.columns:
            port_mode = df['dst_port'].mode()
            mode_port = port_mode.iloc[0] if not port_mode.empty else 0

        mode_flags = ""
        if 'flags' in df.columns:
            flags_mode = df['flags'].mode()
            mode_flags = flags_mode.iloc[0] if not flags_mode.empty else ""

        features['session_pattern'] = f"{mode_proto}-{mode_port}-{mode_flags}"

        # EXTREMELY CRITICAL: Schema Alignment for V19 (30 Columns)
        # Ensure EXACT order of keys to prevent CSV column shift
        ordered_keys = [
            'packet_count', 'total_bytes', 'packet_rate', 'byte_rate',
            'avg_packet_size', 'std_packet_size', 'min_packet_size', 'max_packet_size',
            'tcp_ratio', 'udp_ratio', 'icmp_ratio', 'syn_flag_ratio', 'ack_flag_ratio',
            'fin_flag_ratio', 'rst_flag_ratio', 'unique_src_ips', 'unique_dst_ips',
            'unique_src_ports', 'unique_dst_ports', 'pkts_per_src_ip', 'iat_mean',
            'iat_std', 'burst_count', 'connection_duration', 'timestamp',
            'src_ip', 'dst_ip', 'user_agent', 'session_pattern'
        ]
        
        # Build ordered dict
        final_features = {}
        for k in ordered_keys:
            final_features[k] = features.get(k, 0 if k not in ['src_ip', 'dst_ip', 'user_agent', 'session_pattern'] else '')
            
        return final_features

    def _process_loop(self):
        buffer = []
        last_window_time = time.time()
        
        logger.info(f"Starting advanced feature extraction loop (window: {self.window_size_sec}s)...")
        while not self.stop_event.is_set():
            try:
                pkt = self.packet_queue.get(timeout=0.1)
                buffer.append(pkt)
            except Empty:
                pass
                
            current_time = time.time()
            if current_time - last_window_time >= self.window_size_sec:
                if buffer:
                    df = pd.DataFrame(buffer)
                    features = self._extract_features(df)
                    if features:
                        self.feature_queue.put(features)
                    buffer = [] # Reset buffer for next window
                last_window_time = current_time

    def start(self):
        self.stop_event.clear()
        t = threading.Thread(target=self._process_loop, daemon=True)
        self.thread = t
        t.start()

    def stop(self):
        self.stop_event.set()
        t = self.thread
        if t is not None:
            t.join(timeout=2.0)
