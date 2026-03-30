"""
groq_explainer.py — Explainable AI Layer for AI-IDS
=====================================================
Uses Groq's LLM API to translate raw detection results into
clear, human-readable threat narratives printed alongside alerts.

Features:
  - Completely non-blocking: runs in a background thread
  - Rate-limited: max 1 Groq call per 15 seconds per IP (no spam)
  - Degrades gracefully: if Groq is unavailable, falls back to
    a built-in rule-based explanation
  - Formats output like a professional SOC analyst report
"""

import os
import time
import threading
import logging
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger("ids.groq_explainer")

# ─────────────────────────────────────────────────────────────
# Rate-limit tracker: ip → last_explained_timestamp
# ─────────────────────────────────────────────────────────────
_last_explained: dict = defaultdict(float)
_COOLDOWN_SEC = 15  # Only explain same IP once per 15 s
_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────
# Groq Client (lazy-loaded so missing key doesn't crash import)
# ─────────────────────────────────────────────────────────────
_groq_client = None
_groq_init_attempted = False


def _get_groq_client():
    global _groq_client, _groq_init_attempted
    if _groq_init_attempted:
        return _groq_client
    _groq_init_attempted = True
    try:
        from groq import Groq
        api_key = os.getenv("GROQ_API_KEY", "").strip()
        if not api_key:
            logger.warning("[XAI] GROQ_API_KEY not set — using rule-based fallback")
            return None
        _groq_client = Groq(api_key=api_key)
        logger.info("[XAI] Groq client initialized ✓")
        return _groq_client
    except ImportError:
        logger.warning("[XAI] 'groq' package not installed — run: pip install groq")
        return None
    except Exception as e:
        logger.error(f"[XAI] Failed to init Groq client: {e}")
        return None


# ─────────────────────────────────────────────────────────────
# Rule-Based Fallback (no API needed)
# ─────────────────────────────────────────────────────────────
def _rule_based_explanation(src_ip, dst_ip, pps, mitm_risk, ml_risk,
                             final_risk, decision, attack_type, reasons):
    """Generate a concise explanation without calling Groq."""
    lines = []

    # Attack vector narrative
    if attack_type == "MITM":
        lines.append(f"🔍 Layer-2 Anomaly: {src_ip} is showing ARP/TTL manipulation patterns consistent with a Man-in-the-Middle attack.")
        lines.append(f"   Probability is high ({mitm_risk:.0%}) that this device is attempting to intercept traffic meant for {dst_ip}.")
    elif attack_type in ("DoS", "DDoS"):
        lines.append(f"🔍 Volumetric Flood: {src_ip} is transmitting {pps:.0f} packets/sec toward {dst_ip}.")
        lines.append(f"   Current traffic volume exceeds the safety threshold, indicating a {'Distributed ' if attack_type == 'DDoS' else ''}Denial-of-Service attempt.")
    elif attack_type == "Scan" or "Port Scan" in attack_type:
        lines.append(f"🔍 Reconnaissance activity from {src_ip}: Device is probing multiple ports or sending non-SF flags.")
        lines.append(f"   This behavior is typical of an attacker scanning for open vulnerabilities or mapping the network.")
    elif attack_type == "WAF_Injection":
        lines.append(f"🔍 Application Attack: Payload from {src_ip} contains characters matching SQL Injection or XSS signatures.")
        lines.append(f"   The Web Application Firewall (WAF) layer intercepted this direct attempt to exploit software vulnerabilities.")
    elif attack_type == "Slowloris":
        lines.append(f"🔍 Connection Exhaustion: {src_ip} is holding many half-open HTTP connections.")
        lines.append(f"   Slowloris attacks aim to crash web servers by exhausting the available connection pool with slow, incomplete requests.")
    elif attack_type == "Distributed_SYN":
        lines.append(f"🔍 Stealth Coordination: Multiple IPs are collaborating to send SYN packets without completing handshakes.")
        lines.append(f"   Aggregate network SYN count is abnormal, despite individual IP rates being low.")
    else:
        lines.append(f"🔍 Behavioral Anomaly: {src_ip} shows traffic patterns that deviate from normal baseline behavior.")
        lines.append(f"   Risk score ({final_risk:.0%}) is driven by anomalous feature vectors detected by the AI models.")

    # Decision rationale
    decision_map = {
        "block":    "🚫 Recommendation: BLOCK. The traffic is confirmed malicious and has been firewalled to protect the infrastructure.",
        "throttle": "⚠️  Recommendation: THROTTLE. The traffic is suspicious; rate-limiting has been applied to mitigate potential impact.",
        "alert":    "🔔 Recommendation: MONITOR. Low-confidence anomaly detected. Admin review is advised for source IP visibility.",
        "allow":    "✅ Recommendation: ALLOW. System is tracking these signals but no immediate threat confirmed.",
    }
    lines.append(f"\n   {decision_map.get(decision.lower(), f'Action: {decision.upper()}')}")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# Groq LLM Explanation
# ─────────────────────────────────────────────────────────────
def _call_groq(src_ip, dst_ip, pps, mitm_risk, ml_risk, final_risk,
               decision, attack_type, reasons_text):
    """Call Groq API and return a plain-English SOC analyst report."""
    client = _get_groq_client()
    if client is None:
        return None  # Fall back to rule-based

    prompt = f"""You are a senior SOC (Security Operations Center) analyst reviewing an AI-IDS alert.
Explain the following detection in plain English to a non-technical network admin.
Be concise (3-5 sentences max), professional, and actionable.
Do NOT repeat numbers verbatim — interpret what they mean.

DETECTION DETAILS:
- Source IP: {src_ip}
- Destination IP: {dst_ip}
- Packets/sec: {pps:.1f}
- Attack Type: {attack_type}
- MITM Risk: {mitm_risk:.0%}
- ML Model Risk: {ml_risk:.0%}
- Final Risk Score: {final_risk:.0%}
- Decision: {decision.upper()}
- Detection Reasons: {reasons_text}

Write 1 paragraph explaining: what is happening, why it's suspicious, and what the admin should do."""

    try:
        response = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.4,
            max_tokens=200,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"[XAI] Groq API call failed: {e}")
        return None


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────
def explain_alert(src_ip: str, dst_ip: str, pps: float, mitm_risk: float,
                  ml_risk: float, final_risk: float, decision: str,
                  attack_type: str, reasons: list,
                  mongo_collection=None, query: dict = None,
                  secondary_collection=None):
    """
    Non-blocking entry point — spawns a background thread to generate
    and print the AI explanation so the detection pipeline isn't delayed.
    
    Args:
        src_ip, dst_ip     : Source and destination IP addresses
        pps                : Packets per second (float)
        mitm_risk          : MITM risk score 0.0–1.0
        ml_risk            : ML model risk score 0.0–1.0
        final_risk         : Combined final risk score 0.0–1.0
        decision           : 'allow' | 'alert' | 'throttle' | 'block'
        attack_type        : e.g. 'MITM', 'DoS', 'DDoS', 'Scan', etc.
        reasons            : List of reason strings from the decision engine
        mongo_collection   : Optional pymongo collection to update
        query              : Optional query to find the document to update
    """
    now = time.time()
    with _lock:
        if now - _last_explained[src_ip] < _COOLDOWN_SEC:
            return  # Still in cooldown for this IP
        _last_explained[src_ip] = now

    thread = threading.Thread(
        target=_explain_worker,
        args=(src_ip, dst_ip, pps, mitm_risk, ml_risk,
              final_risk, decision, attack_type, reasons,
              mongo_collection, query, secondary_collection),
        daemon=True,
        name=f"xai-{src_ip}"
    )
    thread.start()


def _explain_worker(src_ip, dst_ip, pps, mitm_risk, ml_risk,
                    final_risk, decision, attack_type, reasons,
                    mongo_collection=None, query=None,
                    secondary_collection=None):
    """Background worker: generates and prints explanation."""
    reasons_text = " | ".join(reasons) if reasons else "No specific reason captured"
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Try Groq first, fall back to rule-based
    explanation = _call_groq(src_ip, dst_ip, pps, mitm_risk, ml_risk,
                              final_risk, decision, attack_type, reasons_text)
    
    source_name = "🤖 Groq AI" if (_get_groq_client() is not None and explanation and "Rate limit" not in explanation) else "📋 Rule-Based"
    
    if not explanation:
        explanation = _rule_based_explanation(src_ip, dst_ip, pps, mitm_risk,
                                              ml_risk, final_risk, decision,
                                              attack_type, reasons)
    
    # Save to MongoDB if available
    if mongo_collection is not None and query is not None:
        try:
            # Add a small delay to ensure the document was inserted by the main thread
            time.sleep(1.5) 
            # Update primary collection
            mongo_collection.update_one(
                query,
                {"$set": {
                    "XAI_Explanation": explanation,
                    "XAI_Source": source_name,
                    "XAI_Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }}
            )
            
            # Update secondary collection if provided
            if secondary_collection is not None:
                secondary_collection.update_one(
                    query,
                    {"$set": {
                        "XAI_Explanation": explanation,
                        "XAI_Source": source_name,
                        "XAI_Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }}
                )
            
            logger.info(f"[XAI] Saved explanation for {src_ip} to MongoDB collections")
        except Exception as e:
            logger.error(f"[XAI] Failed to save to MongoDB: {e}")

    # Terminal Output
    print(f"\n  ╔══════════════════════════════════════════════════════════════╗")
    print(f"  ║  🧠 XAI EXPLANATION [{timestamp}] — {src_ip:<15} ({source_name})")
    print(f"  ╠══════════════════════════════════════════════════════════════╣")
    for line in explanation.splitlines():
        if line.strip():
            print(f"  ║  {line[:60]}") # Simple wrap
            if len(line) > 60:
                print(f"  ║  {line[60:]}")
    print(f"  ╚══════════════════════════════════════════════════════════════╝\n")
