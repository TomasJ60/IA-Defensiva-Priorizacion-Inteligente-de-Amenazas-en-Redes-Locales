#!/usr/bin/env python3
"""
utils.py - Utilidades: conexión a base de datos
"""

# NO necesitas cargar .env aquí porque config.py ya lo hace
from config import DB_CONFIG
import psycopg2


def get_db_connection():
    """
    Crea y retorna una conexión a PostgreSQL usando la configuración de config.py
    """
    return psycopg2.connect(**DB_CONFIG)