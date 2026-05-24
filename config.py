#!/usr/bin/env python3
"""
config.py - Carga configuración desde variables de entorno (.env)
"""

import os
from dotenv import load_dotenv
from pathlib import Path

# ──────────────────────────────────────────────
# CARGAR .env PRIMERO (antes de leer variables)
# ──────────────────────────────────────────────
env_path = Path(__file__).parent / ".env"
if not env_path.exists():
    env_path = Path.cwd() / ".env"

load_dotenv(dotenv_path=env_path)

# ──────────────────────────────────────────────
# VARIABLES DE BASE DE DATOS
# ──────────────────────────────────────────────
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "agente_ia"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "admin123"),
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "5432")),
}

# ──────────────────────────────────────────────
# API KEYS OSINT
# ──────────────────────────────────────────────
VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

# ──────────────────────────────────────────────
# CONFIGURACIÓN DJANGO (si la necesitas en otros scripts)
# ──────────────────────────────────────────────
DJANGO_SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "")
DJANGO_DEBUG = os.getenv("DJANGO_DEBUG", "False").lower() == "true"
DJANGO_ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")
SESSION_INACTIVITY_TIMEOUT_SECONDS = int(os.getenv("SESSION_INACTIVITY_TIMEOUT_SECONDS", "900"))
SESSION_ABSOLUTE_TIMEOUT_SECONDS = int(os.getenv("SESSION_ABSOLUTE_TIMEOUT_SECONDS", "28800"))