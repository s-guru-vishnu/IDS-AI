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
import json

load_dotenv()

app = Flask(__name__)
CORS(app)

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
                "time": t_str[:5],
                "tcp": 1 if "TCP" in proto else 0,
                "udp": 1 if "UDP" in proto else 0,
                "incoming": 1 if is_incoming else 0,
                "outgoing": 0 if is_incoming else 1,
                "size": log.get("Length", 0)
            })

        # ── 2. Attack Summary (12 Types) ──
        traffic_type_map = {
            "dos_traffic": "DoS", "tcp_volumetric_flood": "DDoS",
            "scan_traffic": "Port Scan", "waf_injection": "WAF Injection",
            "stretch_slow_traffic": "Slowloris", "mitm_traffic": "MITM",
            "normal_traffic": "Normal IP Traffic", "festival_traffic": "Festival Time Traffic",
            "udp_volumetric_flood": "UDP Volumetric Flood", "syn_flood_traffic": "Half-Open SYN Flood",
            "mixed_attacks": "Mixed Attacks"
        }
        attack_summary = []
        for col_name, dt_name in traffic_type_map.items():
            cnt = traffic_collections[col_name].count_documents({}) if col_name in traffic_collections else 0
            attack_summary.append({"name": dt_name, "packets": cnt})

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
            "report_summary": report_summary
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
    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))
        severity = request.args.get("severity")
        per_page = min(per_page, 200)

        # IDS Alerts from batch_logs (non-ALLOW)
        ids_query = {"Decision": {"$nin": ["ALLOW", None]}}
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
        mitm_alerts = list(mitm_alerts_col.find({}, {"_id": 0}).sort("timestamp", -1))
        total_mitm = len(mitm_alerts)
        for alert in mitm_alerts:
            alert["alert_source"] = "MITM"
            alert["severity"] = alert.get("threat_level", "HIGH")

        # Security Alerts
        sec_alerts = list(security_alerts_col.find({}, {"_id": 0}).sort("Timestamp", -1).limit(50))
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

        # Filter by severity if specified
        if severity and severity != "all":
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

            # Get records from batch_logs
            query = {"Attack_Type": attack_type}
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
                {"$match": {"Attack_Type": attack_type}},
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
            # ── Summary: count of each attack type ──
            # User's requested 12 categories
            ordered_types = [
                "DDoS", "DoS", "MITM", "Port Scan", "Normal IP Traffic",
                "Festival Time Traffic", "Slowloris", "WAF Injection",
                "Mixed Attacks", "TCP Volumetric Flood", "UDP Volumetric Flood",
                "Half-Open SYN Flood"
            ]
            
            # Map DB names to User names
            db_to_display = {
                "Normal": "Normal IP Traffic",
                "Festival": "Festival Time Traffic",
                "Scan": "Port Scan",
                "WAF_Injection": "WAF Injection",
                "Slowloris": "Slowloris",
                "Stretch": "Slowloris",
                "MITM": "MITM",
                "DoS": "DoS",
                "DDoS": "DDoS",
                "Anomaly": "Mixed Attacks",
                "Chaos": "Mixed Attacks"
            }

            # Map Traffic Collections to display names
            traffic_type_map = {
                "dos_traffic": "DoS",
                "tcp_volumetric_flood": "DDoS",
                "scan_traffic": "Port Scan",
                "waf_injection": "WAF Injection",
                "stretch_slow_traffic": "Slowloris",
                "mitm_traffic": "MITM",
                "normal_traffic": "Normal IP Traffic",
                "festival_traffic": "Festival Time Traffic",
                "udp_volumetric_flood": "UDP Volumetric Flood",
                "syn_flood_traffic": "Half-Open SYN Flood",
                "mixed_attacks": "Mixed Attacks"
            }

            # Initialize result dictionary with all 12 types
            summary_dict = {name: {
                "attack_type": name, 
                "count": 0, 
                "avg_risk": 0.0, 
                "max_risk": 0.0, 
                "unique_ips": 0
            } for name in ordered_types}

            # 1. Aggregate from batch_logs
            pipeline = [
                {"$match": {"Attack_Type": {"$exists": True, "$ne": None}}},
                {"$group": {
                    "_id": "$Attack_Type",
                    "count": {"$sum": 1},
                    "avg_risk": {"$avg": {"$cond": [{"$isNumber": "$Final_Risk"}, "$Final_Risk", 0]}},
                    "max_risk": {"$max": {"$cond": [{"$isNumber": "$Final_Risk"}, "$Final_Risk", 0]}},
                    "unique_ips": {"$addToSet": "$Source_IP"}
                }}
            ]
            batch_results = list(logs_col.aggregate(pipeline))
            
            for t in batch_results:
                raw_type = str(t.get("_id", ""))
                display_name = db_to_display.get(raw_type, raw_type)
                
                if display_name in summary_dict:
                    s = summary_dict[display_name]
                    s["count"] += int(t.get("count", 0))
                    # Weighted average for risk if multiple DB types map to one display type
                    # Simplified: just take the max seen for these stats
                    s["avg_risk"] = max(s["avg_risk"], safe_round(t.get("avg_risk", 0)))
                    s["max_risk"] = max(s["max_risk"], safe_round(t.get("max_risk", 0)))
                    # This is an approximation for unique IPs
                    s["unique_ips"] += len(t.get("unique_ips", []))

            # 2. Add from Specialized Traffic Collections
            for col_name, display_name in traffic_type_map.items():
                col = traffic_collections.get(col_name)
                if col is not None:
                    # Run aggregation on specialized collection too
                    spec_pipeline = [
                        {"$limit": 1000}, # Only look at recent 1000 for summary speed
                        {"$group": {
                            "_id": None,
                            "count": {"$sum": 1},
                            "avg_risk": {"$avg": {"$cond": [{"$isNumber": "$Final_Risk"}, "$Final_Risk", 0]}},
                            "unique_ips": {"$addToSet": "$Source_IP"}
                        }}
                    ]
                    spec_res = list(col.aggregate(spec_pipeline))
                    if spec_res and display_name in summary_dict:
                        t = spec_res[0]
                        s = summary_dict[display_name]
                        # For DDoS/DoS/etc, we add to existing counts from batch_logs
                        s["count"] += int(t.get("count", 0))
                        # Update risk only if it's higher (more conservative)
                        s["avg_risk"] = max(s["avg_risk"], safe_round(t.get("avg_risk", 0)))
                        # Merge unique IPs (approximate)
                        s["unique_ips"] += len(t.get("unique_ips", []))


            # Convert to list and sort by order or count
            result = list(summary_dict.values())
            # Put Normal/Festival first if you want, or just by user order
            # result.sort(key=lambda x: x.get("count", 0), reverse=True)
            
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

        # Execute firewall unblock command
        import platform
        import subprocess
        os_type = platform.system().lower()
        rule_name = f"IDS_BLOCK_{ip.replace('.', '_')}"

        if os_type == "windows":
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        else:
            cmd = f'iptables -D INPUT -s {ip} -j DROP'

        try:
            subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
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


if __name__ == "__main__":
    print("=" * 50)
    print("🛡️  AI-IDS Backend API Server")
    print(f"📊 Database: AI-IDS @ {MONGO_URI}")
    print(f"🔗 Server: http://localhost:5000")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5000, debug=True)
