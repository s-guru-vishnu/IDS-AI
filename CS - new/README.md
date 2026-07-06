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

---

## 🌍 Production Deployment Guide

The project is structured to deploy the **Frontend** to Vercel and the **Backend** to Render, while using **MongoDB Atlas** as the production database.

### 1. Database Setup (MongoDB Atlas)
1. Create a free cluster on [MongoDB Atlas](https://www.mongodb.com/cloud/atlas).
2. Go to **Network Access** and whitelist your IP (or `0.0.0.0/0` for Render).
3. Under **Database Access**, create a user with read/write privileges.
4. Get your connection string (it looks like `mongodb+srv://<username>:<password>@cluster0...`).

### 2. Backend Deployment (Render)
1. Push your code to a GitHub repository.
2. Sign in to [Render](https://render.com) and connect your GitHub account.
3. The project includes a `render.yaml` Blueprint. On Render's dashboard, go to **Blueprints** and create a new instance from your repository.
4. Render will automatically detect the Python environment and run `gunicorn backend.server:app`.
5. **Environment Variables**: Go to your Render Web Service settings and add:
   - `MONGO_URI`: *Your MongoDB Atlas connection string.*
6. Note the URL of your deployed backend (e.g., `https://hybrid-ai-ids-backend.onrender.com`).

### 3. Frontend Deployment (Vercel)
1. Sign in to [Vercel](https://vercel.com) and import your GitHub repository.
2. Ensure the framework preset is **Vite**.
3. **Environment Variables**: Add the following environment variable:
   - `VITE_API_BASE`: `https://hybrid-ai-ids-backend.onrender.com/api` *(replace with your actual Render URL)*.
4. Click **Deploy**. Vercel will automatically read `frontend/vercel.json` and build the dashboard.

### 4. Engine Configuration (Local/Server)
The Core AI Engine (`engine/main.py`) must run continuously on the target network to sniff packets.
1. Create a `.env` file in the root directory (use `.env.example` as a template).
2. Set `MONGO_URI` in `.env` to match your MongoDB Atlas URI.
3. Start the engine:
   ```powershell
   python engine/main.py
   ```
4. The engine will now write logs directly to the cloud DB, which will immediately appear on your Vercel frontend.

### 5. Verification Steps
- **Dashboard:** Visit your Vercel URL. You should see the dashboard load. If it shows connection errors, verify your `VITE_API_BASE` in Vercel settings and ensure the Render backend is live.
- **Backend logs:** Check Render logs for successful MongoDB connection.
- **Engine logs:** Run the engine and verify it says "Listening for packets...". Generate some test traffic to see if it appears on the dashboard.

### 6. Common Errors and Fixes
- **Error:** `CORS error` on Frontend.
  - **Fix:** Ensure the backend `CORS(app)` is configured correctly, and the `VITE_API_BASE` doesn't have a trailing slash.
- **Error:** `ModuleNotFoundError: No module named 'flask'` on Render.
  - **Fix:** Ensure `Flask` and `gunicorn` are in `requirements.txt`.
- **Error:** Dashboard shows zero packets.
  - **Fix:** Verify your local `engine/main.py` is using the same `MONGO_URI` as the Render backend.
