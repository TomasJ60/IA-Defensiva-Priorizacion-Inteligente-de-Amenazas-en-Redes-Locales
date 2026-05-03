#!/usr/bin/env python3
"""
Script de prueba para validar el algoritmo de clasificación de alertas
"""
import sys
import os
sys.path.insert(0, '/home/tomas/Desktop/proyecto/src')

import psycopg2
from utils import get_db_connection
import pandas as pd
from datetime import datetime

def limpiar_base_datos():
    """Elimina datos de pruebas anteriores"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM alertas")
        cur.execute("DELETE FROM monitoreo_activo")
        conn.commit()
        cur.close()
        conn.close()
        print("✅ Base de datos limpiada.")
    except Exception as e:
        print(f"❌ Error al limpiar: {e}")

def insertar_datos_prueba():
    """Inserta datos de prueba para validar el algoritmo"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar si la tabla existe
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_name = 'monitoreo_activo'
            );
        """)
        tabla_existe = cur.fetchone()[0]
        
        if not tabla_existe:
            print("❌ Error: La tabla monitoreo_activo no existe en la base de datos")
            cur.close()
            conn.close()
            return
        
        # Insertar activos con diferentes niveles de criticidad
        activos = [
            ("192.168.1.50", "Servidor Web", 5),      # Crítico
            ("192.168.1.100", "Base de Datos", 4),    # Muy Importante
            ("192.168.1.150", "Workstation", 2),      # Normal
            ("192.168.1.200", "Impresora", 1),        # Bajo
        ]
        
        for ip, nombre, criticidad in activos:
            try:
                cur.execute(
                    "INSERT INTO monitoreo_activo (ip, nombre, criticidad) VALUES (%s, %s, %s)",
                    (ip, nombre, criticidad)
                )
            except psycopg2.IntegrityError:
                conn.rollback()  # IP duplicada, ignorar
        
        conn.commit()
        print(f"✅ {len(activos)} activos insertados.")
        
        # Verificar activos insertados
        cur.execute("SELECT ip, criticidad FROM monitoreo_activo ORDER BY ip")
        activos_db = cur.fetchall()
        print(f"   Activos en BD: {activos_db}")
        
        # Casos de prueba: (ip_destino, severidad, reputation_osint, descripción)
        casos_prueba = [
            ("192.168.1.50", 1, 15, "🔴 CRÍTICO: Severidad Alta + OSINT 15 + Criticidad 5"),
            ("192.168.1.50", 1, 0,  "🔴 CRÍTICO: Severidad Alta + Sin OSINT + Criticidad 5"),
            ("192.168.1.100", 1, 8, "🟠 ALTO RIESGO: Severidad Alta + OSINT 8 + Criticidad 4"),
            ("192.168.1.150", 0, 5, "🟡 MEDIO: Sin Severidad + OSINT 5 + Criticidad 2"),
            ("192.168.1.200", 0, 0, "🟢 BAJO: Sin Severidad + Sin OSINT + Criticidad 1"),
            ("10.0.0.1", 1, 10,     "⚠️ EXTERNO: Severidad Alta + OSINT 10 + Sin Activo"),
        ]
        
        for ip_dest, sev, rep, desc in casos_prueba:
            cur.execute(
                """INSERT INTO alertas (fecha, ip_origen, ip_destino, firma, severidad, reputacion_osint) 
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (datetime.now(), "203.0.113.50", ip_dest, desc, sev, rep)
            )
        
        conn.commit()
        print(f"✅ {len(casos_prueba)} alertas de prueba insertadas.")
        
        cur.close()
        conn.close()
        
    except Exception as e:
        print(f"❌ Error al insertar datos: {e}")

def mostrar_resultados():
    """Muestra los resultados del procesamiento"""
    try:
        conn = get_db_connection()
        
        query = """
        SELECT 
            a.id,
            a.ip_destino,
            a.severidad,
            a.reputacion_osint,
            COALESCE(act.criticidad, 1) as criticidad,
            a.prioridad_ia,
            a.recomendacion,
            a.explicacion
        FROM alertas a
        LEFT JOIN monitoreo_activo act ON a.ip_destino = host(act.ip)
        ORDER BY a.prioridad_ia DESC
        """
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        print("\n" + "="*120)
        print("📊 RESULTADOS DEL PROCESAMIENTO DE ALERTAS")
        print("="*120)
        
        for idx, row in df.iterrows():
            score = row['prioridad_ia'] if row['prioridad_ia'] is not None else 0
            
            # Colorear según el nivel
            if score >= 75:
                emoji = "🔴"
            elif score >= 50:
                emoji = "🟠"
            elif score >= 25:
                emoji = "🟡"
            else:
                emoji = "🟢"
            
            print(f"\n{emoji} ID: {int(row['id'])} | IP: {row['ip_destino']}")
            print(f"   Severidad: {int(row['severidad'])} | OSINT: {int(row['reputacion_osint'])} | Criticidad: {int(row['criticidad'])}")
            print(f"   📈 SCORE: {score:.1f}/105")
            print(f"   ✓ {row['recomendacion']}")
            print(f"   📝 {row['explicacion']}")
        
        print("\n" + "="*120)
        print("ANÁLISIS:")
        print(f"  - Alertas CRÍTICAS (≥75):    {len(df[df['prioridad_ia'] >= 75])}")
        print(f"  - Alertas PRECAUCIÓN (50-74): {len(df[(df['prioridad_ia'] >= 50) & (df['prioridad_ia'] < 75)])}")
        print(f"  - Alertas ALERTA (25-49):     {len(df[(df['prioridad_ia'] >= 25) & (df['prioridad_ia'] < 50)])}")
        print(f"  - Alertas NORMALES (<25):     {len(df[df['prioridad_ia'] < 25])}")
        print("="*120 + "\n")
        
    except Exception as e:
        print(f"❌ Error al mostrar resultados: {e}")

if __name__ == "__main__":
    print("\n🔧 INICIANDO PRUEBAS DEL ALGORITMO DE CLASIFICACIÓN\n")
    
    limpiar_base_datos()
    insertar_datos_prueba()
    
    print("\n⏳ Esperando 3 segundos para que el motor procese las alertas...")
    import time
    time.sleep(3)
    
    mostrar_resultados()
