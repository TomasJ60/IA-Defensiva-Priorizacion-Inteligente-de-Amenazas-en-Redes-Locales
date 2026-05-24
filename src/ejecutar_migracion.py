#!/usr/bin/env python3
"""
EJECUTAR PRIMERO: python3 ejecutar_migracion.py
Esto agrega las columnas faltantes a la BD automáticamente
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
    print("   Asegúrate de estar en el directorio correcto del proyecto")
    sys.exit(1)

def migrar_bd():
    """Ejecuta la migración automáticamente"""
    print("\n" + "="*70)
    print("🔧 INICIANDO MIGRACIÓN DE BASE DE DATOS")
    print("="*70 + "\n")
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # ============================================================
        # AGREGAR COLUMNAS
        # ============================================================
        
        print("📋 Paso 1: Agregando columnas faltantes...")
        
        columnas = [
            ("payload_malicioso", "BOOLEAN DEFAULT FALSE"),
            ("indicadores_malware", "TEXT DEFAULT ''"),
            ("detalles_payload", "TEXT DEFAULT ''"),
            ("fecha_analisis_ia", "TIMESTAMP"),
        ]
        
        for col_name, col_type in columnas:
            try:
                cursor.execute(f"""
                    ALTER TABLE alertas 
                    ADD COLUMN IF NOT EXISTS {col_name} {col_type}
                """)
                print(f"   ✅ Columna '{col_name}' agregada/verificada")
            except Exception as e:
                print(f"   ⚠️ Error con columna '{col_name}': {e}")
        
        conn.commit()
        
        # ============================================================
        # CREAR ÍNDICES
        # ============================================================
        
        print("\n📋 Paso 2: Creando índices para mejor performance...")
        
        indices = [
            ("idx_payload_malicioso", "CREATE INDEX IF NOT EXISTS idx_payload_malicioso ON alertas(payload_malicioso)"),
            ("idx_prioridad_ia", "CREATE INDEX IF NOT EXISTS idx_prioridad_ia ON alertas(prioridad_ia DESC NULLS LAST)"),
            ("idx_vt_malicious", "CREATE INDEX IF NOT EXISTS idx_vt_malicious ON alertas(vt_malicious DESC)"),
        ]
        
        for idx_name, idx_sql in indices:
            try:
                cursor.execute(idx_sql)
                print(f"   ✅ Índice '{idx_name}' creado/verificado")
            except Exception as e:
                print(f"   ⚠️ Error con índice '{idx_name}': {e}")
        
        conn.commit()
        
        # ============================================================
        # VERIFICAR QUE TODO ESTÁ BIEN
        # ============================================================
        
        print("\n📋 Paso 3: Verificando estructura...")
        
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'alertas' 
            AND column_name IN ('payload_malicioso', 'indicadores_malware', 'detalles_payload', 'fecha_analisis_ia')
            ORDER BY ordinal_position
        """)
        
        columnas_verificadas = cursor.fetchall()
        
        if len(columnas_verificadas) == 4:
            print(f"   ✅ Todas las {len(columnas_verificadas)} columnas existen:")
            for col_name, col_type in columnas_verificadas:
                print(f"      - {col_name}: {col_type}")
        else:
            print(f"   ⚠️ Solo encontradas {len(columnas_verificadas)} columnas de 4 esperadas")
            for col_name, col_type in columnas_verificadas:
                print(f"      - {col_name}: {col_type}")
        
        # ============================================================
        # ESTADÍSTICAS
        # ============================================================
        
        print("\n📊 Estadísticas de la tabla alertas:")
        
        cursor.execute("SELECT COUNT(*) FROM alertas")
        total = cursor.fetchone()[0]
        print(f"   📈 Total de alertas: {total}")
        
        cursor.execute("SELECT COUNT(*) FROM alertas WHERE prioridad_ia IS NOT NULL")
        con_ia = cursor.fetchone()[0]
        print(f"   🤖 Alertas con IA procesadas: {con_ia}")
        
        cursor.execute("SELECT COUNT(*) FROM alertas WHERE payload_malicioso = true")
        malware = cursor.fetchone()[0]
        print(f"   🔥 Alertas con malware en payload: {malware}")
        
        conn.close()
        
        print("\n" + "="*70)
        print("✅ MIGRACIÓN COMPLETADA EXITOSAMENTE")
        print("="*70)
        print("\n🚀 Ahora puedes ejecutar:")
        print("   python3 agente.py")
        print("   python3 ia_motor.py")
        print("\n")
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR CRÍTICO EN MIGRACIÓN: {e}")
        print("\n🔧 SOLUCIONES POSIBLES:")
        print("   1. Verifica que la BD está corriendo: 'psql -U tu_usuario -d tu_bd'")
        print("   2. Verifica credenciales en .env")
        print("   3. Verifica que el usuario tiene permisos: 'GRANT ALL ON alertas TO tu_usuario'")
        print("   4. Si persiste, ejecuta manualmente: 'psql -U tu_usuario -d tu_bd -f FIX_URGENTE.sql'")
        return False

if __name__ == "__main__":
    success = migrar_bd()
    sys.exit(0 if success else 1)
