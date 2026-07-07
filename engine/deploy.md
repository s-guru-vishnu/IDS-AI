# 🚀 IDS Engine — AWS EC2 Deployment Guide

## Prerequisites
- AWS EC2 instance (Ubuntu 24.04 LTS)
- Minimum: t3.small (2 vCPU, 2GB RAM)
- Security Group: **outbound only** (no inbound ports needed)
- MongoDB Atlas cluster configured
- SSH key pair for access

---

## Step 1: Launch EC2 Instance

1. Go to AWS Console → EC2 → Launch Instance
2. **AMI:** Ubuntu Server 24.04 LTS
3. **Instance type:** t3.small (or larger)
4. **Security Group:**
   - ✅ Outbound: Allow all (HTTPS to MongoDB Atlas + Render backend)
   - ✅ Inbound: SSH (port 22) from your IP only
   - ❌ No other inbound ports needed — the engine only makes outbound connections
5. Launch and download the SSH key

---

## Step 2: SSH into the Instance

```bash
chmod 400 your-key.pem
ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>
```

---

## Step 3: Install System Dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3.12 python3.12-venv python3-pip git libpcap-dev tcpdump
```

---

## Step 4: Clone the Repository

```bash
sudo mkdir -p /opt/ids-engine
sudo chown ubuntu:ubuntu /opt/ids-engine
cd /opt/ids-engine

git clone https://github.com/s-guru-vishnu/IDS-AI.git .
```

---

## Step 5: Set Up Python Virtual Environment

```bash
cd "/opt/ids-engine/CS - new/engine"

python3.12 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

---

## Step 6: Configure Environment Variables

```bash
cp .env.example .env
nano .env
```

Set these values:
```
MONGO_URI=mongodb+srv://safro:safro@cluster0.hhgbnvw.mongodb.net
BACKEND_URL=https://cybermatrix-api.onrender.com
ENGINE_NAME=ids-engine-ec2-01
ENVIRONMENT=production
GROQ_API_KEY=<your_groq_key_or_leave_empty>
LOG_LEVEL=INFO
NETWORK_INTERFACE=
HEARTBEAT_INTERVAL=30
```

---

## Step 7: Test the Engine Manually

```bash
cd "/opt/ids-engine/CS - new/engine"
source venv/bin/activate
sudo venv/bin/python -u main.py
```

You should see:
```
🚀 Starting Unified 10-Second Batch AI-IDS Pipeline
🛡️  DEFENDER SYSTEM IP: <your_ec2_ip>
Listening for packets...
```

Press `Ctrl+C` to stop.

---

## Step 8: Install as Systemd Service

```bash
# Copy the service file
sudo cp ids-engine.service /etc/systemd/system/ids-engine.service

# Edit the service file to update paths if needed
sudo nano /etc/systemd/system/ids-engine.service
```

Update `WorkingDirectory` and `ExecStart` to match your actual path:
```ini
WorkingDirectory=/opt/ids-engine/CS - new/engine
ExecStart=/opt/ids-engine/CS - new/engine/venv/bin/python -u main.py
EnvironmentFile=/opt/ids-engine/CS - new/engine/.env
```

Then enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ids-engine
sudo systemctl start ids-engine
```

---

## Step 9: Verify the Service

```bash
# Check status
sudo systemctl status ids-engine

# View live logs
sudo journalctl -u ids-engine -f

# Check engine log files
tail -f "/opt/ids-engine/CS - new/engine/logs/system.log"
```

---

## Step 10: Firewall Hardening

```bash
# Allow only SSH inbound, allow all outbound
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable
sudo ufw status
```

---

## Step 11: Verification Checklist

| Check | Command | Expected |
|---|---|---|
| Service running | `sudo systemctl is-active ids-engine` | `active` |
| Models loaded | `sudo journalctl -u ids-engine \| grep "model"` | No errors |
| Packets captured | `sudo journalctl -u ids-engine \| grep "Packet"` | Count > 0 |
| MongoDB connected | `sudo journalctl -u ids-engine \| grep "MongoDB"` | Connected |
| Auto-restart | `sudo systemctl restart ids-engine` | Restarts cleanly |
| Survives reboot | `sudo reboot` → SSH back → check | `active` |

---

## Docker Alternative (Optional)

If you prefer Docker over systemd:

```bash
cd "/opt/ids-engine/CS - new/engine"

# Build
docker build -t ids-engine .

# Run (requires host networking + raw socket access)
docker run -d \
  --name ids-engine \
  --restart always \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --net=host \
  --env-file .env \
  ids-engine
```

---

## Troubleshooting

| Error | Fix |
|---|---|
| `PermissionError: packet capture` | Run with `sudo` or add `CAP_NET_RAW` |
| `ModuleNotFoundError` | Activate venv: `source venv/bin/activate` |
| `MongoDB connection failed` | Check `MONGO_URI` in `.env` and Atlas whitelist |
| `Backend unreachable` | Check `BACKEND_URL` and outbound firewall rules |
| `No packets captured` | Check `NETWORK_INTERFACE` or set to empty for all |
