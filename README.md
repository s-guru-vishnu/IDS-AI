<div align="center">

<a href="https://thecybermatrix.space">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=11,5,5&height=240&section=header&text=The%20Cyber%20Matrix&fontSize=58&fontAlignY=38&desc=AI%20Powered%20Real-Time%20IDS&descAlignY=63&descAlign=50&fontColor=ffffff" alt="The Cyber Matrix Header" />
</a>

<br>

[![Typing SVG](https://readme-typing-svg.herokuapp.com?font=Fira+Code&weight=600&size=24&duration=3500&pause=1000&color=FFFFFF&center=true&vCenter=true&width=800&lines=Real-Time+Hybrid+Intrusion+Detection+System;XGBoost+%2B+Isolation+Forest;Layer-2+MITM+%7C+Layer-4+%26+7+DDoS+Protection;AI-Powered+Threat+Analysis+Dashboard;Built+with+React+%2B+Flask+%2B+AWS+%2B+Docker)](https://thecybermatrix.space)


<img src="https://plain-apac-prod-public.komododecks.com/202607/07/Bx81QQz76eFklx79qJh5/image.png" width="100" alt="Cyber Matrix Logo">

<br>
<br>


![GitHub Repo stars](https://img.shields.io/github/stars/s-guru-vishnu/IDS-AI?style=for-the-badge&logo=github)
![GitHub Forks](https://img.shields.io/github/forks/s-guru-vishnu/IDS-AI?style=for-the-badge&logo=github)
![GitHub Last Commit](https://img.shields.io/github/last-commit/s-guru-vishnu/IDS-AI?style=for-the-badge)

<br>

</div>

<br>

# About

- **Situation**: Traditional network intrusion detection systems rely on static signatures that miss zero-day threats or generate high false-positive rates, while multi-layer attacks force security teams to juggle fragmented tools.
- **Task**: Architect an all-in-one, real-time defense ecosystem capable of monitoring, classifying, and mitigating network threats across Layer-2 (MITM), Layer-4 (DDoS), and Layer-7 (WAF/Slowloris) with minimal latency.
- **Action**: Engineered a high-performance **10-second batch processing pipeline** that fuses supervised (**XGBoost**) and unsupervised (**Isolation Forest**) machine learning models with volumetric traffic buffers, automated IP blocking, and a live React cloud dashboard.
- **Result**: Achieved **99.81% detection accuracy** with `<18ms` inference latency, automating active threat mitigation and providing SOC analysts with instant, plain-English AI incident explanations.

<br>

# Live Demo

| Platform | Link |
|----------|------|
| **Frontend** | https://thecybermatrix.space |
| **Backend** | https://cybermatrix-api.onrender.com |

<br>

# ⚙️ Technology Stack

<table>
  <tr>
    <td align="center" width="20%"><b>Frontend</b></td>
    <td>
      <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react&logoColor=black" alt="React" />
      <img src="https://img.shields.io/badge/Vite-8-646CFF?style=flat&logo=vite&logoColor=white" alt="Vite" />
      <img src="https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=flat&logo=tailwindcss&logoColor=white" alt="Tailwind CSS" />
    </td>
  </tr>

  <tr>
    <td align="center"><b>Backend & API</b></td>
    <td>
      <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python" />
      <img src="https://img.shields.io/badge/Flask-000000?style=flat&logo=flask&logoColor=white" alt="Flask" />
      <img src="https://img.shields.io/badge/Flask--CORS-000000?style=flat&logo=flask&logoColor=white" alt="Flask CORS" />
    </td>
  </tr>

  <tr>
    <td align="center"><b>Database</b></td>
    <td>
      <img src="https://img.shields.io/badge/MongoDB_Atlas-47A248?style=flat&logo=mongodb&logoColor=white" alt="MongoDB Atlas" />
      <img src="https://img.shields.io/badge/PyMongo-47A248?style=flat&logo=mongodb&logoColor=white" alt="PyMongo" />
    </td>
  </tr>

  <tr>
    <td align="center"><b>AI/ML & Security</b></td>
    <td>
      <img src="https://img.shields.io/badge/XGBoost-FF6600?style=flat" alt="XGBoost" />
      <img src="https://img.shields.io/badge/Scikit--Learn-F7931E?style=flat&logo=scikitlearn&logoColor=white" alt="Scikit-Learn" />
      <img src="https://img.shields.io/badge/Isolation_Forest-4B8BBE?style=flat" alt="Isolation Forest" />
      <img src="https://img.shields.io/badge/Pandas-150458?style=flat&logo=pandas&logoColor=white" alt="Pandas" />
      <img src="https://img.shields.io/badge/NumPy-013243?style=flat&logo=numpy&logoColor=white" alt="NumPy" />
      <img src="https://img.shields.io/badge/Scapy-00599C?style=flat" alt="Scapy" />
      <img src="https://img.shields.io/badge/Npcap-2E8B57?style=flat" alt="Npcap" />
    </td>
  </tr>

  <tr>
    <td align="center"><b>Cloud & DevOps</b></td>
    <td>
      <img src="https://img.shields.io/badge/AWS_EC2-FF9900?style=flat&logo=amazonaws&logoColor=white" alt="AWS EC2" />
      <img src="https://img.shields.io/badge/Render-46E3B7?style=flat&logo=render&logoColor=black" alt="Render" />
      <img src="https://img.shields.io/badge/Vercel-000000?style=flat&logo=vercel&logoColor=white" alt="Vercel" />
      <img src="https://img.shields.io/badge/Linux_Systemd-FCC624?style=flat&logo=linux&logoColor=black" alt="Systemd" />
    </td>
  </tr>
</table>

<br>

# System Architecture

```
                                 [ Network Traffic / Packets ]
                                               │
                                     (Scapy Sniffer Engine)
                                               │
                ┌───────────────────────────────┴───────────────────────────────┐
                ▼                                                               ▼
     [ Layer-2 MITM Engine ]                                          [ Layer-4 / 7 DDoS Engine ]
  • ARP & DNS Monitoring                                         • Flow Buffer & Package Analyser
  • Gateway & Latency Checks                                     • Volumetric Thresholds (thresholds.json)
               │                                                               │
               └───────────────────────────────┬───────────────────────────────┘
                                               ▼
                                   [ AI Feature Extractor ]
                                   (29 Telemetry Features)
                                               │
                                               ▼
                              [ AI Models & Decision Engine ]
                        • XGBoost Classifier & Isolation Forest
                        • Threat Fusion Logic (Allow / Alert / Block)
                                               │
                 ┌─────────────────────────────┴─────────────────────────────┐
                 ▼                                                           ▼
       [ Active Mitigation ]                                     [ MongoDB Atlas Cloud DB ]
    • IP Blocker & Firewall Rules                                • IDS.batch_logs / Security Alerts
                                                                             │
                                                                             ▼
                                                                  [ Flask REST API Server ]
                                                                 (server.py / Render Cloud)
                                                                             │
                                                                             ▼
                                                                [ React / Vite Web Dashboard ]
                                                               (Vercel / TheCyberMatrix.space)
```

<br>

# Project Structure

```
IDS-AI/
│
├── frontend/                   # React + Vite Web Dashboard
│   ├── public/                 # Static assets (Logo, Favicon)
│   ├── src/
│   │   ├── components/         # Reusable UI components (Navbar, etc.)
│   │   └── pages/              # Dashboard views (Overview, LiveLogs, BlockedIPs, AttackTypes)
│   ├── package.json
│   └── vercel.json             # Vercel deployment config
│
├── backend/                    # Flask REST API Server
│   ├── server.py               # API endpoints connecting MongoDB to Frontend
│   ├── Dockerfile
│   └── requirements.txt
│
├── engine/                     # Core Defense & Sniffing Engine
│   ├── main.py                 # Pipeline orchestrator (10s batch processing)
│   ├── security_pipeline.py    # Unified threat analysis workflow
│   ├── config.py & heartbeat.py
│   ├── groq_explainer.py       # AI LLM threat explanation module
│   │
│   ├── model/                  # Machine Learning Assets
│   │   ├── feature_extractor.py # 29-feature network packet parser

│   │   ├── train_improved_ids.py # SMOTE training script
│   │   ├── xgboost.pkl         # Trained XGBoost classifier
│   │   └── isolation_forest.pkl# Anomaly detection model
│   │
│   ├── DDoS-engine/            # Volumetric & Layer-4/7 Defense Tier
│   │   ├── decision_engine.py  # Threat fusion & mitigation logic
│   │   ├── advanced_nids.py    # Traffic monitoring & state tracking
│   │   ├── ip_blocker.py       # Active IP blocking module
│   │   └── thresholds.json     # Detection sensitivity rules
│   │
│   ├── MITM-engine/            # Layer-2 Threat Detection Tier
│   │   ├── mitm_detector.py    # Standalone MITM orchestrator
│   │   ├── arp_monitor.py      # ARP spoofing detection
│   │   ├── dns_monitor.py      # DNS hijacking detection
│   │   └── gateway_verifier.py # Gateway impersonation defense
│   │
│   └── stimulater/             # Interactive Attack Simulator
│       └── packet_simulator.py # Generates 14 attack permutations & CSV logs
│
├── scripts/ & configs/         # Utility scripts & system configuration
├── docker-compose.yml          # Container orchestration
├── render.yaml                 # Render cloud blueprint
└── requirements.txt            # Root Python dependencies
```

<br>

# Machine Learning Model

Dataset

```
CICIDS2017 & Custom Synthesized Attack Data (SMOTE Balanced)
```

Algorithms

- XGBoost Classifier (`xgboost.pkl`) — Supervised multi-class threat classification from 29 network features.
- Isolation Forest (`isolation_forest.pkl`) — Unsupervised anomaly detection for zero-day threats.

Accuracy

```
99.81%
```

Evaluation

| Metric | Score |
|---------|---------|
| Accuracy | 99.81% |
| Precision | 99.74% |
| Recall | 99.69% |
| F1 Score | 99.71% |
| Inference Latency | < 18ms per batch |

<br>

# Deployment

Hosted on

- AWS EC2 (Ubuntu Linux Daemon)
- Render (Backend API Cloud Service)
- Vercel (Frontend SPA Dashboard)
- MongoDB Atlas (Cloud Database)

Deployment Process

```
GitHub

↓

Vercel / Render Auto-Build & Deploy

↓

AWS EC2 Daemon (ids-engine.service)

↓

MongoDB Atlas Cloud Synchronization

↓

Live Production Security Suite
```

<br>

# Performance

| Test / Metric | Result |
|--------|----------|
| Lighthouse Performance Score | 98 / 100 |
| PageSpeed Insights | 95 / 100 |
| REST API Average Response Time | 42ms |
| ML Model Inference Time | 18ms |
| Pipeline Batch Processing Window | 10 Seconds |

<br>

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=11,5,5&height=100&section=footer" alt="Footer" />

**From [s-guru-vishnu](https://github.com/s-guru-vishnu)**

</div>
