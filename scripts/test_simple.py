#!/usr/bin/env python3
"""
Prueba funcional ampliada del motor de priorizacion.
Crea varios activos, inserta alertas de distintos niveles
y muestra si la clasificacion final fue coherente.
"""
import sys
import time
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

import pandas as pd
from utils import get_db_connection


def limpiar_base():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("TRUNCATE TABLE alertas, monitoreo_activo RESTART IDENTITY CASCADE")
    conn.commit()
    cur.close()
    conn.close()
    print("Base de datos limpiada.")


def insertar_activos():
    activos = [
        ("192.168.1.10", "Impresora", 1),
        ("192.168.1.20", "Workstation", 2),
        ("192.168.1.30", "Servidor Critico", 5),
        ("192.168.1.40", "Base de Datos", 5),
        ("192.168.1.50", "Servidor Aplicaciones", 4),
        ("192.168.1.60", "Portatil Usuario", 1),
    ]

    conn = get_db_connection()
    cur = conn.cursor()
    for ip, nombre, criticidad in activos:
        cur.execute(
            "INSERT INTO monitoreo_activo (ip, nombre, criticidad) VALUES (%s, %s, %s)",
            (ip, nombre, criticidad)
        )
    conn.commit()
    cur.close()
    conn.close()
    print(f"{len(activos)} activos insertados.")


def insertar_alertas():
    casos = [
        {
            "ip": "192.168.1.10",
            "sev": 3,
            "osint": 0,
            "firma": "Caso 1 - Bajo",
            "esperado": "BAJA/NORMAL"
        },
        {
            "ip": "192.168.1.20",
            "sev": 2,
            "osint": 3,
            "firma": "Caso 2 - Medio",
            "esperado": "ALERTA/PRECAUCION"
        },
        {
            "ip": "192.168.1.30",
            "sev": 1,
            "osint": 15,
            "firma": "Caso 3 - Critico",
            "esperado": "CRITICA"
        },
        {
            "ip": "192.168.1.40",
            "sev": 1,
            "osint": 5,
            "firma": "Caso 4 - Critico por activo",
            "esperado": "CRITICA"
        },
        {
            "ip": "192.168.1.50",
            "sev": 2,
            "osint": 8,
            "firma": "Caso 5 - Alto",
            "esperado": "PRECAUCION"
        },
        {
            "ip": "192.168.1.60",
            "sev": 1,
            "osint": 0,
            "firma": "Caso 6 - Bajo por activo poco critico",
            "esperado": "ALERTA/PRECAUCION"
        },
    ]

    conn = get_db_connection()
    cur = conn.cursor()
    for caso in casos:
        cur.execute(
            """
            INSERT INTO alertas (fecha, ip_origen, ip_destino, firma, severidad, reputacion_osint)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                datetime.now(),
                "203.0.113.50",
                caso["ip"],
                caso["firma"],
                caso["sev"],
                caso["osint"],
            )
        )
    conn.commit()
    cur.close()
    conn.close()
    print(f"{len(casos)} alertas insertadas.")
    return casos


def esperar_procesamiento(segundos=5):
    print(f"Esperando {segundos} segundos para que el motor procese...")
    time.sleep(segundos)


def clasificar_nivel(score):
    if score >= 75:
        return "CRITICA"
    if score >= 50:
        return "PRECAUCION"
    if score >= 25:
        return "ALERTA"
    return "BAJA/NORMAL"


def mostrar_resultados():
    conn = get_db_connection()
    query = """
    SELECT
        a.id,
        a.firma,
        a.ip_destino,
        a.severidad,
        a.reputacion_osint,
        COALESCE(act.criticidad, 1) AS criticidad,
        act.nombre,
        a.prioridad_ia,
        a.recomendacion,
        a.explicacion
    FROM alertas a
    LEFT JOIN monitoreo_activo act ON a.ip_destino = host(act.ip)
    ORDER BY a.id ASC
    """
    df = pd.read_sql_query(query, conn)
    conn.close()

    print("\n" + "=" * 110)
    print("RESULTADOS DEL PROCESAMIENTO")
    print("=" * 110)

    for _, row in df.iterrows():
        score = float(row["prioridad_ia"] or 0)
        nivel = clasificar_nivel(score)

        print(f"\nID: {int(row['id'])} | {row['firma']}")
        print(f"   Activo: {row['nombre']} ({row['ip_destino']})")
        print(
            f"   Criticidad: {int(row['criticidad'])}/5 | "
            f"Severidad: {int(row['severidad'])} | "
            f"OSINT: {int(row['reputacion_osint'])}"
        )
        print(f"   Nivel final: {nivel}")
        print(f"   Score: {score:.1f}/105")
        print(f"   Recomendacion: {row['recomendacion']}")
        print(f"   Explicacion: {row['explicacion']}")

    print("\n" + "=" * 110 + "\n")


def main():
    limpiar_base()
    insertar_activos()
    insertar_alertas()
    esperar_procesamiento()
    mostrar_resultados()


if __name__ == "__main__":
    main()
