#!/usr/bin/env python3
import time
from pathlib import Path
import sys

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

from utils import get_db_connection

conn = get_db_connection()
cur = conn.cursor()

def simular_alerta(firma, severidad, reputacion):
    print(f"📡 Simulando alerta: {firma}...")
    cur.execute("""
        INSERT INTO alertas (fecha, ip_origen, ip_destino, firma, severidad, reputacion_osint)
        VALUES (NOW(), '185.120.10.1', '192.168.1.93', %s, %s, %s)
    """, (firma, severidad, reputacion))
    conn.commit()

# --- Escenario de Demo ---
print("🚀 Iniciando simulación de ataques...")

# 1. Alerta de ruido (Baja prioridad)
simular_alerta("Connection attempt to public NTP server", 3, 0)
time.sleep(1)

# 2. Alerta peligrosa (Alta prioridad detectada por IA)
simular_alerta("MALWARE: Emotet Banking Trojan Download", 1, 15)
time.sleep(1)

# 3. Alerta sospechosa (Fuerza bruta)
simular_alerta("ET SCAN Potential SSH Brute Force", 2, 5)

print("\n✅ ¡Ataques simulados! Corre 'python3 ia_motor.py' para ver cómo la IA los clasifica.")
cur.close()
conn.close()
