#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/tomas/Desktop/proyecto/src')

from utils import get_db_connection
import pandas as pd

conn = get_db_connection()

# Test 1: Ver qué hay en ambas tablas
print("=== TABLA alertas (ip_destino) ===")
df_alertas = pd.read_sql_query("SELECT id, ip_destino FROM alertas WHERE prioridad_ia IS NULL LIMIT 3", conn)
print(df_alertas)
print(f"Tipo de ip_destino: {df_alertas['ip_destino'].dtype}")

print("\n=== TABLA monitoreo_activo (ip) ===")
df_activos = pd.read_sql_query("SELECT id, ip, criticidad FROM monitoreo_activo", conn)
print(df_activos)
print(f"Tipo de ip: {df_activos['ip'].dtype}")

# Test 2: Intentar el JOIN con casting
print("\n=== TEST JOIN CON CASTING ===")
query_join = """
    SELECT a.id, a.ip_destino, act.ip, act.criticidad
    FROM alertas a
    LEFT JOIN monitoreo_activo act ON a.ip_destino::text = act.ip::text
    WHERE a.prioridad_ia IS NULL
"""
try:
    df_join = pd.read_sql_query(query_join, conn)
    print("✅ JOIN exitoso:")
    print(df_join)
except Exception as e:
    print(f"❌ JOIN falló: {e}")

# Test 3: Intentar sin casting
print("\n=== TEST JOIN SIN CASTING ===")
query_join2 = """
    SELECT a.id, a.ip_destino, (act.ip)::text as act_ip_text, act.criticidad
    FROM alertas a
    LEFT JOIN monitoreo_activo act ON (a.ip_destino::inet = act.ip)
    WHERE a.prioridad_ia IS NULL LIMIT 3
"""
try:
    df_join2 = pd.read_sql_query(query_join2, conn)
    print("✅ JOIN alternativo exitoso:")
    print(df_join2)
except Exception as e:
    print(f"❌ JOIN alternativo falló: {e}")

conn.close()
