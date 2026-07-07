"""
AI-IDS Backend API Server
Flask REST API serving data from MongoDB (AI-IDS database) for the Dashboard
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime, timedelta
import os
import re
import json
import secrets
import socket
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)

# Production CORS — explicit origin allowlist
# Add new domains to CORS_ORIGINS env var (comma-separated) on Render
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").split(",")
CORS_ORIGINS = [o.strip() for o in CORS_ORIGINS if o.strip()]

# Default allowed origins (always included)
DEFAULT_ORIGINS = [
    "https://cybermatrix-delta.vercel.app",
    "https://thecybermatrix.space",
    "https://www.thecybermatrix.space",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
    "http://localhost:3000",
]
ALLOWED_ORIGINS = list(set(DEFAULT_ORIGINS + CORS_ORIGINS))

CORS(app,
     origins=ALLOWED_ORIGINS,
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"],
     supports_credentials=True)

# MongoDB Connection
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client["IDS"]
db_ai_ids = client["AI-IDS"]

# Main IDS log collection (written by main.py -> IDS.batch_logs)
logs_col = db["batch_logs"]

# Traffic type collections
traffic_collections = {
    "dos_traffic": db_ai_ids["dos_traffic"],
    "scan_traffic": db_ai_ids["scan_traffic"],
    "waf_injection": db_ai_ids["waf_injection"],
    "normal_traffic": db_ai_ids["normal_traffic"],
    "festival_traffic": db_ai_ids["festival_traffic"],
    "mitm_traffic": db_ai_ids["mitm_traffic"],
    "tcp_volumetric_flood": db_ai_ids["tcp_volumetric_flood"],
    "stretch_slow_traffic": db_ai_ids["stretch_slow_traffic"],
}

# Alert collections
mitm_alerts_col = db_ai_ids["mitm_alerts"]
security_alerts_col = db_ai_ids["security_alerts"]
system_settings_col = db_ai_ids["system_settings"]
users_col = db_ai_ids["users"]

# Initialize default system settings and migrate admin to users collection
def init_settings():
    # 1. Global Config (System settings only)
    config = system_settings_col.find_one({"_id": "global_config"})
    if not config:
        print("Initializing default system settings...")
        system_settings_col.insert_one({
            "_id": "global_config",
            "preferences": {
                "theme": "dark",
                "refresh_interval_ms": 5000
            },
            "engine_config": {
                "auto_block_enabled": True,
                "critical_risk_threshold": 0.90,
                "high_risk_threshold": 0.70
            },
            "updated_at": datetime.utcnow().isoformat()
        })
    
    # 2. Migration: Move admin from global_config to users collection if needed
    if config and "auth" in config:
        print("Migrating admin user to the new users collection...")
        admin_data = config["auth"]
        if not users_col.find_one({"username": admin_data["username"]}):
            users_col.insert_one({
                "username": admin_data["username"],
                "password_hash": admin_data["password_hash"],
                "session_token": admin_data.get("session_token"),
                "role": "admin",
                "created_at": datetime.utcnow().isoformat()
            })
        # Remove auth block from global config to keep it clean
        system_settings_col.update_one({"_id": "global_config"}, {"$unset": {"auth": ""}})

    # 3. Ensure at least one admin exists if migration didn't happen
    if users_col.count_documents({}) == 0:
        print("No users found. Creating default admin...")
        users_col.insert_one({
            "username": "admin",
            "password_hash": generate_password_hash("admin123"),
            "session_token": None,
            "role": "admin",
            "created_at": datetime.utcnow().isoformat()
        })

init_settings()


def safe_float(val, default=0.0):
    """Safely convert a value to float."""
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def safe_round(val, digits=4):
    """Safely round a value."""
    try:
        return round(float(val), digits)
    except (TypeError, ValueError):
        return 0.0



# ─────────────────────────────────────────────
# AUTHENTICATION & SETTINGS
# ─────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username", "")
    password = data.get("password", "")
    
    user = users_col.find_one({"username": username})
    if user and check_password_hash(user["password_hash"], password):
        token = secrets.token_hex(32)
        users_col.update_one({"username": username}, {"$set": {"session_token": token}})
        
        config = system_settings_col.find_one({"_id": "global_config"})
        return jsonify({
            "success": True, 
            "token": token, 
            "username": username,
            "preferences": config.get("preferences", {})
        })
            
    return jsonify({"success": False, "error": "Invalid username or password"}), 401

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username", "")
    password = data.get("password", "")
    full_name = data.get("fullName", "")
    email = data.get("email", "")
    phone = data.get("phone", "")
    
    if not username or not password:
        return jsonify({"success": False, "error": "Username and password required"}), 400
        
    if users_col.find_one({"username": username}):
        return jsonify({"success": False, "error": "Username already exists"}), 409
        
    if email and users_col.find_one({"email": email}):
        return jsonify({"success": False, "error": "Email already registered"}), 409
        
    token = secrets.token_hex(32)
    users_col.insert_one({
        "username": username,
        "password_hash": generate_password_hash(password),
        "full_name": full_name,
        "email": email,
        "phone": phone,
        "session_token": token,
        "role": "user",
        "created_at": datetime.utcnow().isoformat()
    })
    
    config = system_settings_col.find_one({"_id": "global_config"})
    return jsonify({
        "success": True, 
        "token": token, 
        "username": username,
        "preferences": config.get("preferences", {})
    })

@app.route("/api/verify-session", methods=["POST"])
def verify_session():
    token = request.json.get("token")
    if not token:
        return jsonify({"valid": False})
        
    user = users_col.find_one({"session_token": token})
    if user:
        return jsonify({"valid": True, "username": user["username"]})
    return jsonify({"valid": False})

@app.route("/api/settings", methods=["GET"])
def get_settings():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = users_col.find_one({"session_token": token})
    if not user:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
        
    config = system_settings_col.find_one({"_id": "global_config"})
    
    # Dynamically detect REAL local IP (non-loopback)
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)) # Probe Google to see which interface is active
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return request.remote_addr # Fallback to requestaddr
            
    ip_addr = get_local_ip()
    mac_node = uuid.getnode()
    mac_addr = ':'.join(['{:02x}'.format((mac_node >> i) & 0xff) for i in range(40, -8, -8)]) # Correct formatting

    if config:
        return jsonify({
            "success": True,
            "username": user["username"],
            "full_name": user.get("full_name", ""),
            "email": user.get("email", ""),
            "phone": user.get("phone", ""),
            "ip_address": ip_addr,
            "mac_address": mac_addr,
            "preferences": config.get("preferences", {}),
            "engine_config": config.get("engine_config", {}),
            "updated_at": config.get("updated_at")
        })
    return jsonify({"success": False, "error": "Settings not found"}), 404

@app.route("/api/settings", methods=["PUT"])
def update_settings():
    data = request.json
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    
    user = users_col.find_one({"session_token": token})
    if not user:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
        
    update_fields = {"updated_at": datetime.utcnow().isoformat()}
    user_updates = {}
    
    if "username" in data:
        user_updates["username"] = data["username"]
        
    if "new_password" in data and data["new_password"]:
        if not check_password_hash(user["password_hash"], data.get("current_password", "")):
            return jsonify({"success": False, "error": "Incorrect current password"}), 401
        user_updates["password_hash"] = generate_password_hash(data["new_password"])
        
    if "email" in data:
        existing = users_col.find_one({"email": data["email"]})
        if existing and existing["username"] != user["username"]:
            return jsonify({"success": False, "error": "Email already in use by another user"}), 409
        user_updates["email"] = data["email"]
        
    if "phone" in data:
        user_updates["phone"] = data["phone"]

    if user_updates:
        users_col.update_one({"session_token": token}, {"$set": user_updates})
        
    if "preferences" in data:
        for k, v in data["preferences"].items():
            update_fields[f"preferences.{k}"] = v
            
    if "engine_config" in data:
        for k, v in data["engine_config"].items():
            update_fields[f"engine_config.{k}"] = v
            
    if len(update_fields) > 1: # More than just updated_at
        system_settings_col.update_one({"_id": "global_config"}, {"$set": update_fields})
        
    return jsonify({"success": True})

# ─────────────────────────────────────────────
# 1. OVERVIEW — Dashboard Stats
# ─────────────────────────────────────────────
@app.route("/api/overview", methods=["GET"])
def overview():
    try:
        total_logs = logs_col.count_documents({})
        blocked_count = logs_col.count_documents({"Decision": "BLOCK"})
        alert_count = logs_col.count_documents({"Decision": "ALERT"})
        throttle_count = logs_col.count_documents({"Decision": "THROTTLE"})
        allow_count = logs_col.count_documents({"Decision": "ALLOW"})

        # Attack type breakdown (exclude Normal and nulls)
        attack_pipeline = [
            {"$match": {
                "Attack_Type": {"$exists": True, "$ne": None, "$nin": ["Normal", "", "none"]}
            }},
            {"$group": {"_id": "$Attack_Type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        attack_breakdown = list(logs_col.aggregate(attack_pipeline))
        attack_types = {str(item["_id"]): item["count"] for item in attack_breakdown if item["_id"]}

        # Risk distribution (only numeric fields)
        risk_pipeline = [
            {"$match": {"Final_Risk": {"$type": "number"}, "PPS": {"$type": "number"}}},
            {"$group": {
                "_id": None,
                "avg_risk": {"$avg": "$Final_Risk"},
                "max_risk": {"$max": "$Final_Risk"},
                "avg_pps": {"$avg": "$PPS"},
                "max_pps": {"$max": "$PPS"}
            }}
        ]
        risk_stats = list(logs_col.aggregate(risk_pipeline))
        risk_info = risk_stats[0] if risk_stats else {"avg_risk": 0, "max_risk": 0, "avg_pps": 0, "max_pps": 0}
        risk_info.pop("_id", None)

        # Recent threats (last 20 non-ALLOW)
        recent_threats = list(logs_col.find(
            {"Decision": {"$nin": ["ALLOW", None]}},
            {"_id": 0}
        ).sort("Timestamp", -1).limit(20))

        # Ensure numeric fields in recent_threats
        for t in recent_threats:
            t["Final_Risk"] = safe_float(t.get("Final_Risk"))
            t["PPS"] = safe_float(t.get("PPS"))
            t["ML_Risk"] = safe_float(t.get("ML_Risk"))
            t["MITM_Risk"] = safe_float(t.get("MITM_Risk"))

        # Unique source IPs involved in threats
        unique_threat_ips = len(logs_col.distinct("Source_IP", {"Decision": {"$nin": ["ALLOW", None]}}))

        # MITM alert count
        mitm_alert_count = mitm_alerts_col.count_documents({})

        # Security alert count
        security_alert_count = security_alerts_col.count_documents({})

        # Traffic collection counts
        traffic_counts = {}
        for name, col in traffic_collections.items():
            traffic_counts[name] = col.count_documents({})

        # ── 1. Time Series Chart Data (Sample recent 50 for live feel) ──
        internal_prefixes = ("192.", "10.", "172.", "127.")
        recent_logs_chart = list(logs_col.find({}, {"Protocol": 1, "Source_IP": 1, "Timestamp": 1, "Length": 1}).sort("Timestamp", -1).limit(50))
        
        chart_data = []
        for log in reversed(recent_logs_chart):
            t_str = log.get("Timestamp", "").split(" ")[-1] if log.get("Timestamp") else ""
            proto = str(log.get("Protocol", "TCP")).upper()
            src = str(log.get("Source_IP", ""))
            is_incoming = not src.startswith(internal_prefixes)
            
            chart_data.append({
                "time": t_str[:8], 
                "tcp": 1 if "TCP" in proto else 0,
                "udp": 1 if "UDP" in proto else 0,
                "incoming": 1 if is_incoming else 0,
                "outgoing": 0 if is_incoming else 1,
                "size": log.get("Length", 0)
            })

        # ── 2. Attack Summary (Dynamic) ──
        db_to_display = {
            "Normal": "Normal IP Traffic",
            "BENIGN": "Normal IP Traffic",
            "Scan": "Port Scan",
            "WAF_Injection": "WAF Injection",
            "Slowloris": "Slowloris",
            "Stretch": "Slowloris",
            "MITM": "MITM",
            "DoS": "DDoS",  # Merged into DDoS
            "DDoS": "DDoS",
            "UNKNOWN_ATTACK": None,  # Hide from overview
            "STEALTH_ATTACK": "Stealth Attack",
            "HYBRID_ATTACK": "Hybrid Attack",
            "HIGH_VOLUME_ATTACK": "High Volume Attack",
            "KNOWN_ATTACKER": "Known Attacker",
            "ZERO_DAY": "Zero-Day Attack",
            "Anomaly": "Mixed Attacks",
            "Chaos": "Mixed Attacks",
            "AI_ATTACK": "AI Attack",
            "AI_Attack": "AI Attack"
        }
        
        # We perform a new aggregation including ALL attack types
        summary_pipeline = [
            {"$match": {"Attack_Type": {"$exists": True, "$ne": None, "$ne": ""}}},
            {"$group": {"_id": "$Attack_Type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        summary_results = list(logs_col.aggregate(summary_pipeline))
        
        # Merge counts using display names
        merged_summary = {}
        for item in summary_results:
            raw_type = str(item["_id"])
            display_name = db_to_display.get(raw_type, raw_type)
            if display_name is not None:
                merged_summary[display_name] = merged_summary.get(display_name, 0) + item["count"]
            
        attack_summary = [{"name": name, "packets": count} for name, count in merged_summary.items()]

        # ── 3. Short Tables (Status Summaries) ──
        # Merge AI-IDS alerts (signatures/simulator) with ML Engine blocks
        sec_alerts = list(security_alerts_col.find({}, {"_id": 0}).sort("Timestamp", -1).limit(6))
        ml_blocks = list(logs_col.find({"Decision": "BLOCK"}, {"_id": 0}).sort("Timestamp", -1).limit(6))
        
        # Normalize fields so the frontend table maps correctly
        for sa in sec_alerts:
            if "Risk_Score" in sa: sa["Final_Risk"] = sa.pop("Risk_Score")
            elif "Severity" in sa: sa["Final_Risk"] = 0.9 if sa["Severity"] == "High" else 0.5
            else: sa["Final_Risk"] = 0.8
            sa["Decision"] = "BLOCK"
            if "Source_IP" not in sa and "Src_IP" in sa: sa["Source_IP"] = sa["Src_IP"]
            if "Dest_IP" not in sa and "Dst_IP" in sa: sa["Dest_IP"] = sa["Dst_IP"]
            
        combined_alerts = sec_alerts + ml_blocks
        combined_alerts.sort(key=lambda x: x.get("Timestamp", ""), reverse=True)
        alert_logs = combined_alerts[:6]
        
        blocked_ips = list(logs_col.aggregate([
            {"$match": {"Decision": "BLOCK"}},
            {"$group": {"_id": "$Source_IP", "last_seen": {"$max": "$Timestamp"}, "count": {"$sum": 1}}},
            {"$sort": {"last_seen": -1}}, {"$limit": 6}
        ]))
        
        report_summary = [
            {"label": "Total Throughput", "value": f"{total_logs} PKTS"},
            {"label": "Threats Mitigated", "value": f"{blocked_count}"},
            {"label": "Latency (avg)", "value": "12ms"},
            {"label": "Uptime", "value": "99.98%"}
        ]
        
        threat_percentage = ((total_logs - allow_count) / total_logs * 100) if total_logs > 0 else 0

        return jsonify({
            "total_logs": total_logs,
            "blocked_count": blocked_count,
            "alert_count": alert_count,
            "allow_count": allow_count,
            "active_threats": blocked_count + alert_count + throttle_count,
            "attack_types": attack_types,
            "risk_stats": risk_info,
            "recent_threats": recent_threats,
            "unique_threat_ips": unique_threat_ips,
            "chart_data": chart_data,
            "attack_summary": attack_summary,
            "alert_logs": alert_logs,
            "blocked_ips": blocked_ips,
            "report_summary": report_summary,
            "threat_percentage": round(threat_percentage, 2)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# 2. LIVE LOGS — Recent packet traffic
# ─────────────────────────────────────────────
@app.route("/api/live-logs", methods=["GET"])
def live_logs():
    try:
        limit = int(request.args.get("limit", 100))
        limit = min(limit, 500)

        logs = list(logs_col.find(
            {},
            {"_id": 0}
        ).sort("Timestamp", -1).limit(limit))

        # Normalize numeric fields
        for log in logs:
            log["Final_Risk"] = safe_float(log.get("Final_Risk"))
            log["PPS"] = safe_float(log.get("PPS"))
            log["ML_Risk"] = safe_float(log.get("ML_Risk"))
            log["MITM_Risk"] = safe_float(log.get("MITM_Risk"))

        return jsonify({"logs": logs, "count": len(logs)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# 3. REPORTS — Aggregated traffic statistics
# ─────────────────────────────────────────────
@app.route("/api/reports", methods=["GET"])
def reports():
    try:
        total = logs_col.count_documents({})

        # Decision distribution
        decision_pipeline = [
            {"$match": {"Decision": {"$ne": None}}},
            {"$group": {"_id": "$Decision", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        decisions = {item["_id"]: item["count"] for item in logs_col.aggregate(decision_pipeline) if item["_id"]}

        # Attack type distribution
        attack_pipeline = [
            {"$match": {"Attack_Type": {"$ne": None}}},
            {"$group": {"_id": "$Attack_Type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        attacks = {item["_id"]: item["count"] for item in logs_col.aggregate(attack_pipeline) if item["_id"]}

        # Top 10 attacker IPs (by threat count)
        top_attackers_pipeline = [
            {"$match": {"Decision": {"$nin": ["ALLOW", None]}}},
            {"$group": {
                "_id": "$Source_IP",
                "threat_count": {"$sum": 1},
                "avg_risk": {"$avg": {"$cond": [{"$isNumber": "$Final_Risk"}, "$Final_Risk", 0]}},
                "max_pps": {"$max": {"$cond": [{"$isNumber": "$PPS"}, "$PPS", 0]}},
                "attack_types": {"$addToSet": "$Attack_Type"}
            }},
            {"$sort": {"threat_count": -1}},
            {"$limit": 10}
        ]
        top_attackers = list(logs_col.aggregate(top_attackers_pipeline))
        for a in top_attackers:
            a["ip"] = a.pop("_id")
            a["avg_risk"] = safe_float(a.get("avg_risk"))
            a["max_pps"] = safe_float(a.get("max_pps"))

        # Top 10 targeted IPs
        top_targets_pipeline = [
            {"$match": {"Decision": {"$nin": ["ALLOW", None]}}},
            {"$group": {
                "_id": "$Dest_IP",
                "hit_count": {"$sum": 1},
                "avg_risk": {"$avg": {"$cond": [{"$isNumber": "$Final_Risk"}, "$Final_Risk", 0]}}
            }},
            {"$sort": {"hit_count": -1}},
            {"$limit": 10}
        ]
        top_targets = list(logs_col.aggregate(top_targets_pipeline))
        for t in top_targets:
            t["ip"] = t.pop("_id")
            t["avg_risk"] = safe_float(t.get("avg_risk"))

        # PPS statistics
        pps_pipeline = [
            {"$match": {"PPS": {"$type": "number"}}},
            {"$group": {
                "_id": None,
                "total_pps": {"$sum": "$PPS"},
                "avg_pps": {"$avg": "$PPS"},
                "max_pps": {"$max": "$PPS"}
            }}
        ]
        pps_stats = list(logs_col.aggregate(pps_pipeline))
        pps_info = pps_stats[0] if pps_stats else {"total_pps": 0, "avg_pps": 0, "max_pps": 0}
        pps_info.pop("_id", None)

        # Risk statistics
        risk_pipeline = [
            {"$match": {"Final_Risk": {"$type": "number"}}},
            {"$group": {
                "_id": None,
                "avg_ml_risk": {"$avg": {"$cond": [{"$isNumber": "$ML_Risk"}, "$ML_Risk", 0]}},
                "avg_mitm_risk": {"$avg": {"$cond": [{"$isNumber": "$MITM_Risk"}, "$MITM_Risk", 0]}},
                "avg_final_risk": {"$avg": "$Final_Risk"}
            }}
        ]
        risk_stats = list(logs_col.aggregate(risk_pipeline))
        risk_info = risk_stats[0] if risk_stats else {"avg_ml_risk": 0, "avg_mitm_risk": 0, "avg_final_risk": 0}
        risk_info.pop("_id", None)

        threat_percentage = ((total - decisions.get("ALLOW", 0)) / total * 100) if total > 0 else 0

        # Traffic collection summaries
        traffic_summary = {}
        for name, col in traffic_collections.items():
            traffic_summary[name] = col.count_documents({})

        return jsonify({
            "total_packets": total,
            "decisions": decisions,
            "attack_types": attacks,
            "top_attackers": top_attackers,
            "top_targets": top_targets,
            "pps_stats": pps_info,
            "risk_stats": risk_info,
            "threat_percentage": round(threat_percentage, 2),
            "traffic_summary": traffic_summary
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# 4. HISTORY — Logs with date/time filters
# ─────────────────────────────────────────────
@app.route("/api/history", methods=["GET"])
def history():
    try:
        start = request.args.get("start")
        end = request.args.get("end")
        attack_type = request.args.get("attack_type")
        decision = request.args.get("decision")
        source_ip = request.args.get("source_ip")
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))
        per_page = min(per_page, 200)

        query = {}

        if start:
            query["Timestamp"] = query.get("Timestamp", {})
            query["Timestamp"]["$gte"] = start

        if end:
            query["Timestamp"] = query.get("Timestamp", {})
            query["Timestamp"]["$lte"] = end

        if attack_type and attack_type != "all":
            query["Attack_Type"] = attack_type

        if decision and decision != "all":
            query["Decision"] = decision.upper()

        if source_ip:
            query["Source_IP"] = {"$regex": source_ip, "$options": "i"}

        total = logs_col.count_documents(query)
        skip = (page - 1) * per_page

        logs = list(logs_col.find(
            query,
            {"_id": 0}
        ).sort("Timestamp", -1).skip(skip).limit(per_page))

        # Normalize
        for log in logs:
            log["Final_Risk"] = safe_float(log.get("Final_Risk"))
            log["PPS"] = safe_float(log.get("PPS"))
            log["ML_Risk"] = safe_float(log.get("ML_Risk"))
            log["MITM_Risk"] = safe_float(log.get("MITM_Risk"))

        return jsonify({
            "logs": logs,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page if per_page > 0 else 0
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# 5. ALERT LOGS — All alerts (IDS + MITM + Security)
# ─────────────────────────────────────────────
@app.route("/api/alert-logs", methods=["GET"])
def alert_logs():
    # 🔐 Security Verification
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not users_col.find_one({"session_token": token}):
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))
        severity = request.args.get("severity")
        per_page = min(per_page, 200)

        # Build queries based on severity
        ids_query = {"Decision": {"$nin": ["ALLOW", None]}}
        mitm_query = {}
        sec_query = {}
        
        if severity and severity.lower() != "all":
            s = severity.upper()
            # IDS
            if s == "CRITICAL":
                ids_query["Final_Risk"] = {"$gte": 0.9}
            elif s == "HIGH":
                ids_query["Final_Risk"] = {"$gte": 0.7, "$lt": 0.9}
            elif s == "MEDIUM":
                ids_query["Final_Risk"] = {"$gte": 0.4, "$lt": 0.7}
            elif s == "LOW":
                ids_query["Final_Risk"] = {"$lt": 0.4}
                
            # MITM
            mitm_query["threat_level"] = s
            
            # Security
            if s == "CRITICAL":
                sec_query["Severity_Score"] = {"$gte": 8}
            elif s == "HIGH":
                sec_query["Severity_Score"] = {"$gte": 6, "$lt": 8}
            elif s == "MEDIUM":
                sec_query["Severity_Score"] = {"$gte": 4, "$lt": 6}
            elif s == "LOW":
                sec_query["Severity_Score"] = {"$lt": 4}

        # IDS Alerts from batch_logs (non-ALLOW)
        total_ids = logs_col.count_documents(ids_query)
        skip = (page - 1) * per_page
        ids_alerts = list(logs_col.find(
            ids_query,
            {"_id": 0}
        ).sort("Timestamp", -1).skip(skip).limit(per_page))

        # Classify severity
        for alert in ids_alerts:
            alert["Final_Risk"] = safe_float(alert.get("Final_Risk"))
            alert["PPS"] = safe_float(alert.get("PPS"))
            alert["ML_Risk"] = safe_float(alert.get("ML_Risk"))
            alert["MITM_Risk"] = safe_float(alert.get("MITM_Risk"))
            risk = alert["Final_Risk"]
            if risk >= 0.9:
                alert["severity"] = "CRITICAL"
            elif risk >= 0.7:
                alert["severity"] = "HIGH"
            elif risk >= 0.4:
                alert["severity"] = "MEDIUM"
            else:
                alert["severity"] = "LOW"
            alert["alert_source"] = "IDS"

        # MITM Alerts from DB collection
        mitm_alerts = list(mitm_alerts_col.find(mitm_query, {"_id": 0}).sort("timestamp", -1))
        total_mitm = len(mitm_alerts)
        for alert in mitm_alerts:
            alert["alert_source"] = "MITM"
            alert["severity"] = alert.get("threat_level", "HIGH").upper()

        # Security Alerts
        sec_alerts = list(security_alerts_col.find(sec_query, {"_id": 0}).sort("Timestamp", -1).limit(50))
        for alert in sec_alerts:
            alert["alert_source"] = "SECURITY"
            score = safe_float(alert.get("Severity_Score", 0))
            if score >= 8:
                alert["severity"] = "CRITICAL"
            elif score >= 6:
                alert["severity"] = "HIGH"
            elif score >= 4:
                alert["severity"] = "MEDIUM"
            else:
                alert["severity"] = "LOW"

        # Combine on first page
        all_alerts = ids_alerts
        if page == 1:
            all_alerts = mitm_alerts + sec_alerts + ids_alerts

        # Filter by severity if specified (case-insensitive "all" check)
        if severity and severity.lower() != "all":
            all_alerts = [a for a in all_alerts if a.get("severity", "").upper() == severity.upper()]

        return jsonify({
            "alerts": all_alerts,
            "total_ids_alerts": total_ids,
            "total_mitm_alerts": total_mitm,
            "total_security_alerts": len(sec_alerts),
            "page": page,
            "per_page": per_page
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# 6. BLOCKED IPs — All blocked IP details
# ─────────────────────────────────────────────
@app.route("/api/blocked-ips", methods=["GET"])
def blocked_ips():
    try:
        pipeline = [
            {"$match": {"Decision": "BLOCK"}},
            {"$group": {
                "_id": "$Source_IP",
                "block_count": {"$sum": 1},
                "first_blocked": {"$min": "$Timestamp"},
                "last_blocked": {"$max": "$Timestamp"},
                "avg_risk": {"$avg": {"$cond": [{"$isNumber": "$Final_Risk"}, "$Final_Risk", 0]}},
                "max_risk": {"$max": {"$cond": [{"$isNumber": "$Final_Risk"}, "$Final_Risk", 0]}},
                "avg_pps": {"$avg": {"$cond": [{"$isNumber": "$PPS"}, "$PPS", 0]}},
                "max_pps": {"$max": {"$cond": [{"$isNumber": "$PPS"}, "$PPS", 0]}},
                "attack_types": {"$addToSet": "$Attack_Type"},
                "target_ips": {"$addToSet": "$Dest_IP"},
                "reasons": {"$push": "$Reasons"}
            }},
            {"$sort": {"block_count": -1}}
        ]
        blocked = list(logs_col.aggregate(pipeline))

        for item in blocked:
            item["source_ip"] = item.pop("_id")
            item["avg_risk"] = safe_float(item.get("avg_risk"))
            item["max_risk"] = safe_float(item.get("max_risk"))
            item["avg_pps"] = safe_float(item.get("avg_pps"))
            item["max_pps"] = safe_float(item.get("max_pps"))
            all_reasons = item.get("reasons", [])
            unique_reasons = list(set(r for r in all_reasons if r))[:5]
            item["reasons"] = unique_reasons

        # MITM blocked
        mitm_blocked = list(mitm_alerts_col.find({"blocked": True}, {"_id": 0}))

        return jsonify({
            "blocked_ips": blocked,
            "total_blocked_ips": len(blocked),
            "mitm_blocked": mitm_blocked
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# 7. ATTACK TYPES — Attack classification + drill-down
# ─────────────────────────────────────────────
@app.route("/api/attack-types", methods=["GET"])
def attack_types():
    try:
        attack_type = request.args.get("type")
        db_to_display = {
            "Normal": "Normal IP Traffic",
            "BENIGN": "Normal IP Traffic",
            "Scan": "Port Scan",
            "WAF_Injection": "WAF Injection",
            "Slowloris": "Slowloris",
            "Stretch": "Slowloris",
            "MITM": "MITM",
            "DoS": "DDoS",
            "DDoS": "DDoS",
            "UNKNOWN_ATTACK": None,  # Hide
            "STEALTH_ATTACK": "Stealth Attack",
            "HYBRID_ATTACK": "Hybrid Attack",
            "HIGH_VOLUME_ATTACK": "High Volume Attack",
            "KNOWN_ATTACKER": "Known Attacker",
            "ZERO_DAY": "Zero-Day Attack",
            "Anomaly": "Mixed Attacks",
            "Chaos": "Mixed Attacks",
            "AI_ATTACK": "AI Attack",
            "AI_Attack": "AI Attack"
        }

        if attack_type:
            # ── Drill-down: records for a specific attack type ──

            # Check if this is a traffic collection type
            traffic_col_map = {
                "DoS": "dos_traffic",
                "DDoS": "tcp_volumetric_flood",
                "Port Scan": "scan_traffic",
                "WAF Injection": "waf_injection",
                "Slowloris": "stretch_slow_traffic",
                "MITM": "mitm_traffic",
                "Normal IP Traffic": "normal_traffic",
                "Festival Time Traffic": "festival_traffic",
                "TCP Volumetric Flood": "tcp_volumetric_flood",
                "UDP Volumetric Flood": "udp_volumetric_flood",
                "Half-Open SYN Flood": "syn_flood_traffic",
                "Mixed Attacks": "mixed_attacks"
            }

            page = int(request.args.get("page", 1))
            per_page = int(request.args.get("per_page", 50))
            per_page = min(per_page, 200)
            skip = (page - 1) * per_page

            # Get records from batch_logs matching any raw DB type that maps to this display type
            matching_types = [k for k, v in db_to_display.items() if v == attack_type]
            if attack_type not in matching_types:
                matching_types.append(attack_type)
            query = {"Attack_Type": {"$in": matching_types}} if len(matching_types) > 1 else {"Attack_Type": attack_type}

            total_batch = logs_col.count_documents(query)
            batch_records = list(logs_col.find(query, {"_id": 0}).sort("Timestamp", -1).skip(skip).limit(per_page))

            for r in batch_records:
                r["Final_Risk"] = safe_float(r.get("Final_Risk"))
                r["PPS"] = safe_float(r.get("PPS"))
                r["ML_Risk"] = safe_float(r.get("ML_Risk"))
                r["MITM_Risk"] = safe_float(r.get("MITM_Risk"))
                r["record_source"] = "batch_logs"

            # Also get records from the corresponding traffic collection
            traffic_records = []
            traffic_col_name = traffic_col_map.get(attack_type)
            total_traffic = 0
            if traffic_col_name and traffic_col_name in traffic_collections:
                col = traffic_collections[traffic_col_name]
                total_traffic = col.count_documents({})
                if total_batch == 0 or skip >= total_batch:
                    # Show traffic collection records if no batch_logs for this page
                    traffic_skip = max(0, skip - total_batch)
                    traffic_records = list(col.find({}, {"_id": 0}).sort("Timestamp", -1).skip(traffic_skip).limit(per_page - len(batch_records)))
                    for r in traffic_records:
                        # Normalize field names from traffic collections
                        if "Src_IP" in r:
                            r["Source_IP"] = r.pop("Src_IP")
                        if "Dst_IP" in r:
                            r["Dest_IP"] = r.pop("Dst_IP")
                        r["record_source"] = traffic_col_name
                        r["Attack_Type"] = attack_type

            total = total_batch + total_traffic
            all_records = batch_records + traffic_records

            # Stats
            stats_pipeline = [
                {"$match": query},
                {"$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "avg_risk": {"$avg": {"$cond": [{"$isNumber": "$Final_Risk"}, "$Final_Risk", 0]}},
                    "max_risk": {"$max": {"$cond": [{"$isNumber": "$Final_Risk"}, "$Final_Risk", 0]}},
                    "avg_pps": {"$avg": {"$cond": [{"$isNumber": "$PPS"}, "$PPS", 0]}},
                    "max_pps": {"$max": {"$cond": [{"$isNumber": "$PPS"}, "$PPS", 0]}},
                    "unique_ips": {"$addToSet": "$Source_IP"},
                    "decisions": {"$push": "$Decision"}
                }}
            ]
            stats = list(logs_col.aggregate(stats_pipeline))
            type_stats = {}
            if stats:
                s = stats[0]
                decisions_count = {}
                for d in s.get("decisions", []):
                    if d:
                        decisions_count[d] = decisions_count.get(d, 0) + 1
                type_stats = {
                    "total": total,
                    "batch_total": s["total"],
                    "traffic_total": total_traffic,
                    "avg_risk": safe_round(s.get("avg_risk")),
                    "max_risk": safe_round(s.get("max_risk")),
                    "avg_pps": safe_round(s.get("avg_pps"), 2),
                    "max_pps": safe_round(s.get("max_pps"), 2),
                    "unique_ips": len(s.get("unique_ips", [])),
                    "decisions": decisions_count
                }
            else:
                type_stats = {
                    "total": total_traffic,
                    "batch_total": 0,
                    "traffic_total": total_traffic,
                    "avg_risk": 0, "max_risk": 0,
                    "avg_pps": 0, "max_pps": 0,
                    "unique_ips": 0, "decisions": {}
                }

            return jsonify({
                "attack_type": attack_type,
                "records": all_records,
                "stats": type_stats,
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": (total + per_page - 1) // per_page if per_page > 0 else 0
            })
        else:
            # ── Summary: count of each attack type (Dynamic) ──
            # 1. Aggregate purely from active batch_logs
            pipeline = [
                {"$match": {"Attack_Type": {"$exists": True, "$ne": None, "$ne": ""}}},
                {"$group": {
                    "_id": "$Attack_Type",
                    "count": {"$sum": 1},
                    "avg_risk": {"$avg": {"$cond": [{"$isNumber": "$Final_Risk"}, "$Final_Risk", 0]}},
                    "max_risk": {"$max": {"$cond": [{"$isNumber": "$Final_Risk"}, "$Final_Risk", 0]}},
                    "unique_ips": {"$addToSet": "$Source_IP"}
                }}
            ]
            batch_results = list(logs_col.aggregate(pipeline))
            
            summary_dict = {}
            for t in batch_results:
                raw_type = str(t.get("_id", ""))
                display_name = db_to_display.get(raw_type, raw_type)
                
                if display_name is not None:
                    if display_name not in summary_dict:
                        summary_dict[display_name] = {
                            "attack_type": display_name,
                            "count": 0,
                            "avg_risk": 0.0,
                            "max_risk": 0.0,
                            "unique_ips": 0
                        }
                        
                    s = summary_dict[display_name]
                    s["count"] += int(t.get("count", 0))
                    s["avg_risk"] = max(s["avg_risk"], safe_round(t.get("avg_risk", 0)))
                    s["max_risk"] = max(s["max_risk"], safe_round(t.get("max_risk", 0)))
                    s["unique_ips"] += len(t.get("unique_ips", []))

            # Final list sorted by count descending
            result = sorted(list(summary_dict.values()), key=lambda x: x["count"], reverse=True)
            return jsonify({"attack_types": result})

    except Exception as e:
        print(f"ERROR in attack-types: {str(e)}")
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Health Check
# ─────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    try:
        client.server_info()
        return jsonify({
            "status": "healthy",
            "database": "AI-IDS",
            "collections": db.list_collection_names(),
            "batch_logs_count": logs_col.count_documents({})
        })
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500


# ─────────────────────────────────────────────
# 8. FIREWALL BLOCKS — Real-time OS-level IP blocks
# ─────────────────────────────────────────────
# Firewall blocks are in the same IDS database
firewall_blocks_col = db["firewall_blocks"]


@app.route("/api/firewall-blocks", methods=["GET"])
def firewall_blocks():
    """
    Returns all firewall block records with computed live status.
    Each record includes:
      - ip, reason, severity, blocked_at, unblock_at
      - status: ACTIVE or EXPIRED (computed from timestamps)
      - remaining_seconds: live TTL countdown
    """
    try:
        blocks = list(firewall_blocks_col.find({}, {"_id": 0}).sort("blocked_at", -1))

        now = datetime.now()
        for block in blocks:
            # Compute live status from timestamps
            try:
                unblock_time = datetime.strptime(block.get("unblock_at", ""), "%Y-%m-%d %H:%M:%S")
                remaining = (unblock_time - now).total_seconds()
                if remaining > 0 and block.get("status") == "ACTIVE":
                    block["status"] = "ACTIVE"
                    block["remaining_seconds"] = round(remaining, 1)
                else:
                    block["status"] = "EXPIRED"
                    block["remaining_seconds"] = 0
            except (ValueError, TypeError):
                block["status"] = block.get("status", "UNKNOWN")
                block["remaining_seconds"] = 0

        active_count = sum(1 for b in blocks if b.get("status") == "ACTIVE")

        return jsonify({
            "blocks": blocks,
            "total": len(blocks),
            "active_count": active_count,
            "expired_count": len(blocks) - active_count,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Strict IPv4 validation regex — prevents command injection
_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

def _validate_ip(ip_str: str) -> bool:
    """Validate that a string is a safe IPv4 address (no shell metacharacters)."""
    if not ip_str or not _IP_RE.match(ip_str):
        return False
    parts = ip_str.split('.')
    return all(0 <= int(p) <= 255 for p in parts)


@app.route("/api/unblock-ip", methods=["POST"])
def unblock_ip():
    """
    Manually unblock an IP — removes the firewall rule and updates DB.
    Body: { "ip": "x.x.x.x" }
    """
    try:
        data = request.get_json()
        ip = data.get("ip") if data else None

        if not ip:
            return jsonify({"error": "Missing 'ip' field"}), 400

        # 🔒 SECURITY: Validate IP format to prevent command injection
        if not _validate_ip(ip):
            return jsonify({"error": "Invalid IP address format"}), 400

        # Update MongoDB status
        result = firewall_blocks_col.update_one(
            {"ip": ip, "status": "ACTIVE"},
            {"$set": {
                "status": "EXPIRED",
                "unblocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "manual_unblock": True
            }}
        )

        if result.modified_count == 0:
            return jsonify({"error": f"No active block found for {ip}"}), 404

        # Execute firewall unblock command (safe: IP validated above)
        import platform
        import subprocess
        os_type = platform.system().lower()
        rule_name = f"IDS_BLOCK_{ip.replace('.', '_')}"

        if os_type == "windows":
            cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}']
        else:
            cmd = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']

        try:
            subprocess.run(cmd, capture_output=True, timeout=10)
        except Exception as fw_err:
            # Log but don't fail — DB is already updated
            print(f"Firewall unblock command warning: {fw_err}")

        return jsonify({
            "success": True,
            "message": f"IP {ip} unblocked successfully",
            "ip": ip
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# 9. CYBER DEFENSE AI — Pipeline Stats & Endpoints
# ─────────────────────────────────────────────
pipeline_results_col = db["pipeline_results"]


@app.route("/api/pipeline-stats", methods=["GET"])
def pipeline_stats():
    """
    Real-time pipeline timing metrics.
    Returns avg/p50/p95/p99 per stage from the pipeline_results collection.
    """
    try:
        # Aggregate timing stats from pipeline_results
        pipeline = [
            {"$sort": {"Timestamp": -1}},
            {"$limit": 500},
            {"$group": {
                "_id": None,
                "total_flows": {"$sum": 1},
                "avg_capture": {"$avg": "$timing.capture_time_ms"},
                "avg_feature": {"$avg": "$timing.feature_time_ms"},
                "avg_behavior": {"$avg": "$timing.behavior_time_ms"},
                "avg_ml": {"$avg": "$timing.ml_time_ms"},
                "avg_ai_defense": {"$avg": "$timing.ai_defense_time_ms"},
                "avg_intelligence": {"$avg": "$timing.intelligence_time_ms"},
                "avg_correlation": {"$avg": "$timing.correlation_time_ms"},
                "avg_zero_day": {"$avg": "$timing.zero_day_time_ms"},
                "avg_decision": {"$avg": "$timing.decision_time_ms"},
                "avg_response": {"$avg": "$timing.response_time_ms"},
                "avg_total_detection": {"$avg": "$timing.total_detection_time_ms"},
                "avg_total_response": {"$avg": "$timing.total_response_time_ms"},
            }}
        ]
        stats = list(pipeline_results_col.aggregate(pipeline))
        timing_stats = stats[0] if stats else {}
        timing_stats.pop("_id", None)

        # Attack type distribution from pipeline results
        attack_pipeline = [
            {"$match": {"attack_type": {"$ne": "BENIGN"}}},
            {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        attack_dist = {
            item["_id"]: item["count"]
            for item in pipeline_results_col.aggregate(attack_pipeline)
            if item["_id"]
        }

        # Zero-day count
        zero_day_count = pipeline_results_col.count_documents({"is_zero_day": True})

        # Action distribution
        action_pipeline = [
            {"$group": {"_id": "$action", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        action_dist = {
            item["_id"]: item["count"]
            for item in pipeline_results_col.aggregate(action_pipeline)
            if item["_id"]
        }

        # Risk level distribution
        risk_pipeline = [
            {"$group": {"_id": "$risk_level", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        risk_dist = {
            item["_id"]: item["count"]
            for item in pipeline_results_col.aggregate(risk_pipeline)
            if item["_id"]
        }

        return jsonify({
            "timing": timing_stats,
            "attack_distribution": attack_dist,
            "action_distribution": action_dist,
            "risk_distribution": risk_dist,
            "zero_day_count": zero_day_count,
            "total_pipeline_results": pipeline_results_col.count_documents({}),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/zero-day-alerts", methods=["GET"])
def zero_day_alerts():
    """
    Returns all detected zero-day / unknown attack patterns.
    """
    try:
        limit = int(request.args.get("limit", 50))
        limit = min(limit, 200)

        alerts = list(pipeline_results_col.find(
            {"is_zero_day": True},
            {"_id": 0}
        ).sort("Timestamp", -1).limit(limit))

        # Normalize numeric fields
        for alert in alerts:
            alert["anomaly_score"] = safe_float(alert.get("anomaly_score"))
            alert["confidence"] = safe_float(alert.get("confidence"))

        return jsonify({
            "zero_day_alerts": alerts,
            "total": pipeline_results_col.count_documents({"is_zero_day": True}),
            "count": len(alerts),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/correlation-events", methods=["GET"])
def correlation_events():
    """
    Returns pipeline results that have active correlation signals.
    """
    try:
        limit = int(request.args.get("limit", 50))
        limit = min(limit, 200)

        # Find results with non-empty correlation_id
        corr_results = list(pipeline_results_col.find(
            {"correlation_id": {"$ne": "", "$exists": True}},
            {"_id": 0}
        ).sort("Timestamp", -1).limit(limit))

        return jsonify({
            "correlation_events": corr_results,
            "count": len(corr_results),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/pipeline-results", methods=["GET"])
def pipeline_results():
    """
    Returns raw pipeline results with strict JSON output.
    Supports filtering by attack_type, action, risk_level.
    """
    try:
        limit = int(request.args.get("limit", 50))
        limit = min(limit, 200)
        attack_type = request.args.get("attack_type")
        action = request.args.get("action")
        risk_level = request.args.get("risk_level")

        query = {}
        if attack_type and attack_type != "all":
            query["attack_type"] = attack_type
        if action and action != "all":
            query["action"] = action
        if risk_level and risk_level != "all":
            query["risk_level"] = risk_level

        results = list(pipeline_results_col.find(
            query, {"_id": 0}
        ).sort("Timestamp", -1).limit(limit))

        return jsonify({
            "results": results,
            "total": pipeline_results_col.count_documents(query),
            "count": len(results),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# 10. FLOW BUFFER STATS — V3 Buffer Monitoring
# ─────────────────────────────────────────────

@app.route("/api/flow-buffer-stats", methods=["GET"])
def flow_buffer_stats():
    """
    Returns flow buffer statistics from recent pipeline results.
    Aggregates buffer_stats from the pipeline_results collection.
    """
    try:
        buffer_pipeline = [
            {"$sort": {"Timestamp": -1}},
            {"$limit": 200},
            {"$group": {
                "_id": None,
                "total_flows": {"$sum": 1},
                "avg_packet_count": {"$avg": "$buffer_stats.packet_count"},
                "avg_duration": {"$avg": "$buffer_stats.duration_sec"},
                "avg_packet_rate": {"$avg": "$buffer_stats.packet_rate"},
                "avg_byte_rate": {"$avg": "$buffer_stats.byte_rate"},
                "avg_entropy": {"$avg": "$buffer_stats.entropy"},
                "avg_burst_count": {"$avg": "$buffer_stats.burst_count"},
                "max_packet_rate": {"$max": "$buffer_stats.packet_rate"},
                "max_entropy": {"$max": "$buffer_stats.entropy"},
                "total_packets": {"$sum": "$buffer_stats.packet_count"},
                "total_bytes": {"$sum": "$buffer_stats.total_bytes"},
            }}
        ]
        stats = list(pipeline_results_col.aggregate(buffer_pipeline))
        buffer_info = stats[0] if stats else {}
        buffer_info.pop("_id", None)

        # Optimization usage stats
        opt_pipeline = [
            {"$sort": {"Timestamp": -1}},
            {"$limit": 200},
            {"$unwind": {"path": "$optimization_applied", "preserveNullAndEmptyArrays": False}},
            {"$group": {"_id": "$optimization_applied", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        opt_dist = {
            item["_id"]: item["count"]
            for item in pipeline_results_col.aggregate(opt_pipeline)
            if item["_id"]
        }

        return jsonify({
            "buffer_stats": buffer_info,
            "optimization_usage": opt_dist,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("=" * 50)
    print("🛡️  Cyber Defense AI V3 — Backend API Server")
    print(f"📊 Database: AI-IDS @ {MONGO_URI}")
    print(f"🔗 Server: http://localhost:5005")
    print(f"🧠 Pipeline: /api/pipeline-stats, /api/flow-buffer-stats")
    print(f"🔴 Zero-Day: /api/zero-day-alerts")
    print(f"🔗 Correlation: /api/correlation-events, /api/pipeline-results")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5005, debug=True)
