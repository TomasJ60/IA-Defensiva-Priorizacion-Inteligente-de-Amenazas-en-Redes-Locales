#!/usr/bin/env python3
"""
ia_motor.py - Motor de Priorización Real-Time (VERSIÓN FINAL PARA ENTREGA)
✅ CORRECCIÓN: Conversión de tipos NumPy a Python para evitar errores de DB.
✅ LÓGICA DE ESCALADA: Garantiza que amenazas confirmadas lleguen a zona crítica.
"""

import os
import sys
import time
import warnings
import joblib
import pandas as pd
from pathlib import Path

# Configuración de rutas
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_DIR = SCRIPT_DIR.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from utils import get_db_connection
from dotenv import load_dotenv

warnings.filterwarnings("ignore")
load_dotenv(dotenv_path=PROJECT_DIR / ".env")

IA_CRITICAL_THRESHOLD = float(os.getenv("IA_CRITICAL_THRESHOLD", "85.0"))

# ============================================================
# CARGA DE MODELO
# ============================================================
MODEL_PATH = PROJECT_DIR / "data" / "modelo_alertas.joblib"

try:
    artifact = joblib.load(MODEL_PATH)
    RF_MODEL = artifact["model"] if isinstance(artifact, dict) else artifact
    # El modelo espera exactamente estos 3 atributos
    FEATURES_COLUMNS = ["severidad", "reputacion_osint", "criticidad_activo"]
    print(f"✅ MODELO IA CARGADO: Random Forest listo para demostración.")
except Exception as e:
    print(f"❌ ERROR CRÍTICO CARGANDO MODELO IA: {e}")
    sys.exit(1)

# ============================================================
# LÓGICA DE PRIORIZACIÓN
# ============================================================

def predecir_prioridad(severidad, osint_score, criticidad_activo, payload_malicioso, indicadores_malware):
    """
    Calcula la prioridad final combinando ML y lógica de seguridad ejecutiva.
    """
    try:
        # 1. Preparar entrada para el modelo
        x_input = pd.DataFrame(
            [[int(severidad), float(osint_score), int(criticidad_activo)]], 
            columns=FEATURES_COLUMNS
        )
        
        # 2. Obtener probabilidad base (0.0 a 1.0)
        # Convertimos a float() de Python inmediatamente para evitar errores de NumPy
        prob_malicia = float(RF_MODEL.predict_proba(x_input)[0][1])
        
        # 3. LÓGICA DE ESCALADA PARA LA SUSTENTACIÓN
        # Si detectamos malware en payload o la reputación OSINT es crítica (>80)
        indicadores = []
        if indicadores_malware:
            indicadores = [item.strip() for item in str(indicadores_malware).split(",") if item.strip()]

        if payload_malicioso or osint_score > 80:
            # Garantizar rango crítico: 85% a 100%
            score_final = 85.0 + (prob_malicia * 15.0)
            if payload_malicioso:
                razon_critica = "malware detectado por payload/indicadores"
            else:
                razon_critica = f"OSINT crítico ({float(osint_score):.1f})"
            print(f"   🔥 ESCALADA CRÍTICA: {razon_critica}.")
        
        elif osint_score > 40 or severidad <= 2:
            # Rango de precaución: 60% a 84%
            score_final = 60.0 + (prob_malicia * 24.0)
        
        else:
            # Basado puramente en probabilidad estadística
            score_final = prob_malicia * 100.0

        # Devolvemos un float estándar de Python redondeado a 1 decimal
        score_final = float(round(min(score_final, 100.0), 1))
        return score_final, {
            "prob_malicia": round(prob_malicia * 100.0, 1),
            "indicadores": indicadores,
            "payload_malicioso": bool(payload_malicioso),
            "criticidad_activo": int(criticidad_activo),
            "osint_score": float(osint_score),
            "severidad": int(severidad),
            "escalada_por_osint": bool((not payload_malicioso) and float(osint_score) > 80),
        }

    except Exception as e:
        print(f"   ⚠️ Error en cálculo IA: {e}")
        score_fallback = 85.0 if payload_malicioso else 20.0
        return score_fallback, {
            "prob_malicia": None,
            "indicadores": [],
            "payload_malicioso": bool(payload_malicioso),
            "criticidad_activo": int(criticidad_activo),
            "osint_score": float(osint_score),
            "severidad": int(severidad),
            "escalada_por_osint": False,
        }

def generar_recomendacion(score, payload, osint, indicadores, firma, activo, criticidad):
    """
    Genera una recomendación local y rápida sin llamadas externas.
    """
    score = float(score)
    osint = float(osint)
    criticidad = int(criticidad)
    payload = bool(payload)
    indicadores = [item for item in indicadores if item] if indicadores else []
    indicador_texto = f" Indicadores: {', '.join(indicadores)}." if indicadores else ""
    firma_clara = firma.strip() if firma else "Alerta sin firma detallada"
    origen = "Detección de malware" if payload else ("Reputación OSINT crítica" if osint > 80 else "Análisis interno de riesgo")

    if payload or osint > 80 or score >= IA_CRITICAL_THRESHOLD:
        return (
            f"🔥 CRÍTICO: {origen} para {activo} (criticidad {criticidad}). Score IA {score:.1f}%.{indicador_texto} "
            f"DIAGNÓSTICO TÉCNICO: {firma_clara} indica una amenaza con alta probabilidad de compromiso y movimiento lateral. "
            "PLAN DE ACCIÓN INMEDIATO: 1) Aislar el origen/destino identificado. "
            "2) Revisar logs de red, procesos y conexiones asociadas. "
            "3) Verificar integridad de archivos, reglas de seguridad y reputación de la IP. "
            "JUSTIFICACIÓN OSINT: La reputación observada y los indicadores de malware elevan la prioridad a respuesta inmediata."
        )
    elif score >= 60:
        return (
            f"⚠️ ALERTA MEDIA: {origen}. Score IA {score:.1f}% para {activo} (criticidad {criticidad}).{indicador_texto} "
            f"DIAGNÓSTICO TÉCNICO: {firma_clara} sugiere actividad potencialmente sospechosa que requiere verificación. "
            "PLAN DE ACCIÓN INMEDIATO: 1) Corroborar logs de eventos y tráfico. "
            "2) Revisar reputación de IP y contexto del activo. "
            "3) Mantener monitoreo activo y escalar si el patrón persiste. "
            "JUSTIFICACIÓN OSINT: La reputación observada apoya la necesidad de un análisis inmediato."
        )
    else:
        return (
            f"✅ ALERTA BAJA: Score IA {score:.1f}% para {activo}. {indicador_texto} "
            f"DIAGNÓSTICO TÉCNICO: {firma_clara} no muestra señales de compromiso inmediato. "
            "PLAN DE ACCIÓN INMEDIATO: 1) Continuar monitoreando el incidente. "
            "2) Revisar nuevamente si cambia la reputación o aparecen nuevos indicadores. "
            "3) Preparar respuesta rápida si la severidad aumenta. "
            "JUSTIFICACIÓN OSINT: La reputación actual no exige intervención urgente, pero conviene mantener el análisis."
        )

# ============================================================
# PROCESAMIENTO DE ALERTAS
# ============================================================

def procesar_alertas():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Consultar alertas que no tienen procesamiento de IA
        # Hacemos JOIN con activos para tener el contexto local
        cur.execute("""
            SELECT a.id, a.severidad, a.osint_score, a.payload_malicioso, a.indicadores_malware,
                   GREATEST(COALESCE(act.criticidad, 1), 1) as crit_act,
                   COALESCE(act.nombre, a.ip_destino) as activo_nombre,
                   a.firma
            FROM alertas a
            LEFT JOIN monitoreo_activo act ON host(act.ip) = a.ip_destino
            WHERE a.prioridad_ia IS NULL
            ORDER BY a.id ASC
        """)
        
        filas = cur.fetchall()
        if not filas:
            cur.close()
            conn.close()
            return False

        for r in filas:
            al_id, sev, osint, payload, ind, crit_act, activo_nombre, firma = r
            
            # Calcular score asegurando tipos nativos de Python
            score, score_meta = predecir_prioridad(sev, osint, crit_act, payload, ind)
            reco = generar_recomendacion(score, payload, osint, score_meta["indicadores"], firma, activo_nombre, crit_act)
            indicadores_texto = ", ".join(score_meta["indicadores"]) if score_meta["indicadores"] else "Sin indicadores específicos"
            origen_critico = "payload/indicadores" if payload else ("OSINT" if score_meta["escalada_por_osint"] else "modelo")
            expli = (
                f"IA Random Forest analizó contexto: Sev={sev}, OSINT={osint}, Activo={crit_act}. "
                f"Probabilidad base={score_meta['prob_malicia']}%. Resultado: {score}% de riesgo. "
                f"Origen criticidad={origen_critico}. Payload malicioso={bool(payload)}. "
                f"Indicadores malware={indicadores_texto}."
            )

            # Guardar resultados
            cur.execute("""
                UPDATE alertas 
                SET prioridad_ia = %s, 
                    explicacion = %s, 
                    recomendacion = %s, 
                    fecha_analisis_ia = NOW()
                WHERE id = %s
            """, (score, expli, reco, al_id))
            
            status = "🔴 CRÍTICO" if score >= 85 else "🟡 ALERTA"
            malware_estado = "True" if payload else "False"
            motivo = "payload/indicadores" if payload else ("osint" if score_meta["escalada_por_osint"] else "modelo")
            indicadores_log = ", ".join(score_meta["indicadores"]) if score_meta["indicadores"] else "sin indicadores"
            print(
                f"   [{status}] ID {al_id} -> Score: {score}% "
                f"(Malware: {malware_estado} | Motivo: {motivo} | Indicadores: {indicadores_log})"
            )

        conn.commit()
        cur.close()
        conn.close()
        return True
    except Exception as e:
        print(f"❌ Error en procesamiento de base de datos: {e}")
        return False

# ============================================================
# BUCLE PRINCIPAL
# ============================================================

def main():
    print("=" * 60)
    print("🤖 MOTOR DE INFERENCIA IA INICIADO - MODO REAL-TIME")
    print(f"📈 Usando modelo: {MODEL_PATH}")
    print("=" * 60)

    while True:
        try:
            # Procesar alertas. Si procesó, intentar de nuevo inmediatamente. 
            # Si no, esperar medio segundo.
            if not procesar_alertas():
                time.sleep(0.5)
            else:
                continue
        except KeyboardInterrupt:
            print("\nMotor detenido por el usuario.")
            break
        except Exception as e:
            print(f"Error imprevisto: {e}")
            time.sleep(2)

if __name__ == "__main__":
    main()
