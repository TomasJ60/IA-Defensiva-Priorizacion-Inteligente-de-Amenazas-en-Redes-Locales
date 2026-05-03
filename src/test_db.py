# src/test_db.py
from utils import get_db_connection
try:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT version();")
    print("✅ ¡CONEXIÓN EXITOSA!")
    print(cur.fetchone())
    cur.close()
    conn.close()
except Exception as e:
    print(f"❌ Falló la conexión: {e}")