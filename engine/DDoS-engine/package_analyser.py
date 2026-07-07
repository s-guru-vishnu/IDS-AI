from scapy.all import IP, TCP, UDP, get_if_addr, conf
from collections import defaultdict
import time
import threading
import socket

class TrafficAnalyser:
    def __init__(self, debug=False):
        self.debug = debug
        try:
            self.my_ip = get_if_addr(conf.iface)
        except:
            self.my_ip = socket.gethostbyname(socket.gethostname())

        self.lock = threading.Lock()
        self.start_time = time.time()
        
        # Stats
        self.packet_count = 0
        self.incoming_count = 0
        self.outgoing_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.ip_count = defaultdict(int)
        self.incoming_ip_count = defaultdict(int)
        self.port_scan = defaultdict(set)
        self.port_count = defaultdict(int)

    def process_packet(self, packet):
        if not IP in packet:
            return

        src = packet[IP].src
        dst = packet[IP].dst
        proto = "OTHER"

        is_tcp = TCP in packet
        is_udp = UDP in packet
        
        if is_tcp: proto = "TCP"
        elif is_udp: proto = "UDP"

        with self.lock:
            self.packet_count += 1
            self.ip_count[src] += 1

            if dst == self.my_ip:
                self.incoming_count += 1
                self.incoming_ip_count[src] += 1
                direction = "⬅️ IN"
                dport = packet[TCP].dport if is_tcp else (packet[UDP].dport if is_udp else None)
                if dport:
                    self.port_scan[src].add(dport)
                    self.port_count[src] += 1
            elif src == self.my_ip:
                self.outgoing_count += 1
                direction = "➡️ OUT"
            else:
                direction = "🔄 OTHER"

        if self.debug:
            print(f"{direction} | {src} → {dst} | {proto}")

    def get_report(self):
        """Returns a snapshot of the current stats and resets them."""
        with self.lock:
            duration = time.time() - self.start_time
            report = {
                'duration': duration,
                'total': self.packet_count,
                'incoming': self.incoming_count,
                'outgoing': self.outgoing_count,
                'tcp': self.tcp_count,
                'udp': self.udp_count,
                'top_ips': sorted(self.ip_count.items(), key=lambda x: x[1], reverse=True)[:5],
                'incoming_ips': sorted(self.incoming_ip_count.items(), key=lambda x: x[1], reverse=True)[:5],
                'port_scan': dict(self.port_scan)
            }
            
            # Reset
            self.packet_count = 0
            self.incoming_count = 0
            self.outgoing_count = 0
            self.tcp_count = 0
            self.udp_count = 0
            self.ip_count.clear()
            self.incoming_ip_count.clear()
            self.port_scan.clear()
            self.port_count.clear()
            self.start_time = time.time()
            
            return report

    def print_visual_report(self, report):
        pps = report['total'] / report['duration'] if report['duration'] > 0 else 0
        print("\n📊 " + "="*30)
        print(f"TRAFFIC REPORT ({time.strftime('%H:%M:%S')})")
        print(f"PPS: {pps:.2f} | IN: {report['incoming']} | OUT: {report['outgoing']}")
        
        if report['top_ips']:
            print("\n🔝 Top Talkers:")
            for ip, count in report['top_ips']:
                print(f"  {ip}: {count} pkts")
        
        if report['incoming_ips']:
            print("\n🎯 Top Incoming Sources:")
            for ip, count in report['incoming_ips']:
                print(f"  {ip}: {count} pkts")
        print("="*32 + "\n")