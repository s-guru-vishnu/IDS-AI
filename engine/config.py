"""
config.py — Centralized Engine Configuration
==============================================
All configuration is loaded from environment variables with safe defaults.
Import this module instead of calling os.getenv() directly.
"""

import os
from dotenv import load_dotenv

# Load .env from engine directory first, then project root
_engine_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_engine_dir)

load_dotenv(os.path.join(_engine_dir, ".env"))
load_dotenv(os.path.join(_project_root, ".env"))


class EngineConfig:
    """Read-only configuration loaded from environment variables."""

    # ── Database ──
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")

    # ── Backend API ──
    BACKEND_URL = os.getenv("BACKEND_URL", "https://cybermatrix-api.onrender.com")

    # ── Engine Identity ──
    ENGINE_NAME = os.getenv("ENGINE_NAME", "ids-engine-01")
    ENVIRONMENT = os.getenv("ENVIRONMENT", "production")

    # ── AI / XAI ──
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

    # ── Logging ──
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
    LOG_DIR = os.path.join(_engine_dir, "logs")

    # ── Network ──
    NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", None)  # None = sniff all

    # ── Heartbeat ──
    HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "30"))

    @classmethod
    def print_summary(cls):
        """Print a non-sensitive config summary at startup."""
        print("=" * 55)
        print(f"  ENGINE CONFIG — {cls.ENGINE_NAME}")
        print(f"  Environment : {cls.ENVIRONMENT}")
        print(f"  Backend URL : {cls.BACKEND_URL}")
        print(f"  Mongo URI   : {'***' + cls.MONGO_URI[-20:] if len(cls.MONGO_URI) > 25 else cls.MONGO_URI}")
        print(f"  Log Level   : {cls.LOG_LEVEL}")
        print(f"  Interface   : {cls.NETWORK_INTERFACE or 'ALL'}")
        print(f"  Heartbeat   : every {cls.HEARTBEAT_INTERVAL}s")
        print(f"  Groq XAI    : {'enabled' if cls.GROQ_API_KEY else 'disabled'}")
        print("=" * 55)
