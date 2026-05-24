#!/usr/bin/env python3
"""
diagnostico_bd.py - Revisa qué columnas faltan en la BD
Ejecutar: python3 diagnostico_bd.py
"""

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_DIR = SCRIPT_DIR.parent

if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

try:
    from utils import get_db_connection
except ImportError:
    print("❌ ERROR: No se encuentra utils.py")
    sys.exit(1)

def diagnosticar():
    print("\n" + "="*70)
    print("🔍 DIAGNÓSTICO DE BASE DE DATOS")
    print("="*70 + "\n")
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # ============================================================
        # VERIFICAR TABLA ALERTAS
        # ============================================================
        
        print("📋 VERIFICANDO TABLA 'alertas'...\n")
        
        cursor.execute("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_name = 'alertas'
            )
        """)
        
        tabla_existe = cursor.fetchone()[0]
        
        if not tabla_existe:
            print("❌ ERROR: Tabla 'alertas' NO EXISTE")
            print("   Crea la tabla primero con tu script de inicialización")
            conn.close()
            return False
        
        print("✅ Tabla 'alertas' existe\n")
        
        # ============================================================
        # LISTAR COLUMNAS EXISTENTES
        # ============================================================
        
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'alertas'
            ORDER BY ordinal_position
        """)
        
        columnas = cursor.fetchall()
        
        print("📊 COLUMNAS EXISTENTES:")
        for col_name, col_type in columnas:
            print(f"   ✅ {col_name}: {col_type}")
        
        # ============================================================
        # VERIFICAR COLUMNAS REQUERIDAS
        # ============================================================
        
        print("\n📋 VERIFICANDO COLUMNAS REQUERIDAS PARA MEJORADO:\n")
        
        columnas_requeridas = {
            'payload_malicioso': 'BOOLEAN',
            'indicadores_malware': 'TEXT',
            'detalles_payload': 'TEXT',
            'fecha_analisis_ia': 'TIMESTAMP',
        }
        
        columnas_existentes = {col[0]: col[1] for col in columnas}
        
        faltan = []
        presentes = []
        
        for col_name, col_type in columnas_requeridas.items():
            if col_name in columnas_existentes:
                print(f"   ✅ {col_name}: EXISTE ({columnas_existentes[col_name]})")
                presentes.append(col_name)
            else:
                print(f"   ❌ {col_name}: FALTA ({col_type})")
                faltan.append((col_name, col_type))
        
        # ============================================================
        # ESTADO GENERAL
        # ============================================================
        
        print("\n" + "="*70)
        
        if not faltan:
            print("✅ BD LISTA PARA VERSIÓN MEJORADA")
            print("   Puedes usar: agente_MEJORADO.py e ia_motor_MEJORADO.py")
            cursor.execute("SELECT COUNT(*) FROM alertas")
            total = cursor.fetchone()[0]
            print(f"\n   Total de alertas: {total}")
            
        else:
            print(f"⚠️  FALTAN {len(faltan)} COLUMNAS")
            print("\n   Opciones para arreglar:")
            print("\n   OPCIÓN 1 - Automática (RECOMENDADA):")
            print("      python3 ejecutar_migracion.py")
            print("\n   OPCIÓN 2 - Manual con SQL:")
            for col_name, col_type in faltan:
                print(f"      ALTER TABLE alertas ADD COLUMN {col_name} {col_type};")
        
        print("="*70 + "\n")
        
        conn.close()
        return len(faltan) == 0
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

if __name__ == "__main__":
    success = diagnosticar()
    sys.exit(0 if success else 1)
