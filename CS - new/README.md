# 🛡️ Hybrid AI-IDS (Intrusion Detection System)

**Version 71.4** — A high-performance, unified 10-second batch processing pipeline for detecting and mitigating Layer-2 (MITM), Layer-4 (DDoS/SYN Floods), and Layer-7 (WAF/Slowloris) network attacks in real-time.

---

## 🏗️ The Architecture
The project has been aggressively optimized into a hyper-clean, 4-folder architecture.

### 1. `model/`
Holds the core Machine Learning assets.
- `xgboost.pkl` & `isolation_forest.pkl`: The trained AI classification models.
- `feature_extractor.py`: The data-parsing engine that extracts 29 critical telemetry features from raw network packets.
- `train_improved_ids.py`: Script to handle dataset imbalances and retrain the models with SMOTE.

### 2. `DDoS-engine/`
The active system orchestrator and volumetric analysis tier.
- `decision_engine.py`: The proprietary threat fusion logic that marries AI Risk Scores with Volumetric Thresholds to output a final *Allow/Alert/Block* decision.
- `advanced_nids.py` & `package_analyser.py`: The visual traffic monitoring and connection state tracking modules.
- `thresholds.json`: User-configurable detection sensitivities.

### 3. `MITM-engine/`
The standalone Layer-2 threat detection engine.
- Contains the `mitm_detector.py` orchestrator.
- Monitors and defends against ARP Spoofing, DNS Hijacking, routing latency drifts, and Gateway impersonation.

### 4. `stimulater/`
The interactive network combat and dataset generation engine.
- **`packet_simulator.py`**: A massive interactive terminal tool. It can blast the pipeline with 14 different complex traffic permutations (Festival Traffic, Distributed DoS, Stealth Scans, WAF injections, Slowloris, etc.).
- The tool automatically logs every packet it generates into flawlessly formatted `.csv` datasets for later AI training and analysis.

---

## 🚀 Installation

Ensure you have Python 3.10+ installed.

1. Create a virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
2. Install the necessary dependencies:
   ```powershell
   pip install pandas numpy scikit-learn xgboost scapy joblib
   ```
   *(Note: Npcap must be installed on Windows for `scapy` packet sniffing to function).*

---

## ⚔️ How to Run

You will need **two separate terminals** running concurrently (both with the `venv` activated).

### Terminal 1: Start the Defense Pipeline
This boots up the AI models, loads the MITM monitors, and begins analyzing network traffic in 10-second batches.
```powershell
python main.py
```

### Terminal 2: Start the Attack Simulator
Use this interactive tool to fire 14 different complex network attacks at your machine to watch the Pipeline detect and block them.
```powershell
python stimulater\packet_simulator.py
```
