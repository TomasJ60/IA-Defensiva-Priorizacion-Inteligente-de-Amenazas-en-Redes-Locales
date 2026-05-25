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

THREAT_PATTERNS = {
    "malware": ["ransomware", "trojan", "worm", "backdoor", "malware", "shellcode", "payload"],
    "phishing": ["phishing", "phish", "credential", "spoof", "login attempt"],
    "scan": ["scan", "syn-rst", "portscan", "recon", "rafaga tcp", "icmp", "probe"],
    "web_attack": ["sql", "xss", "http", "web attack", "exploit kit", "command injection"],
    "lateral_movement": ["smb", "psexec", "rdp", "winrm", "ssh brute", "lateral"],
    "c2": ["command-and-control", "c2", "beacon", "callback", "botnet"],
    "dns_abuse": ["dns", "domain", "tunneling", "dnscat", "query"],
}

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
    firma_clara = firma.strip() if firma else "Alerta sin firma detallada"
    threat_type = inferir_tipo_amenaza(firma_clara, indicadores, payload, osint)
    severity_label = obtener_nivel_prioridad(score)
    impact_text = describir_impacto(threat_type, criticidad, activo)
    action_plan = construir_plan_accion(threat_type, score, payload, osint, criticidad, activo)
    indicator_text = f" Indicadores observados: {', '.join(indicadores)}." if indicadores else ""
    justification = construir_justificacion(threat_type, score, payload, osint, criticidad)

    return (
        f"{severity_label}: {impact_text}. "
        f"Firma analizada: {firma_clara}. "
        f"Score IA: {score:.1f} sobre 100.{indicator_text} "
        f"Accion sugerida para el analista: {action_plan} "
        f"Motivo: {justification}"
    )


def inferir_tipo_amenaza(firma, indicadores, payload, osint):
    texto = " ".join([firma or "", " ".join(indicadores or [])]).lower()
    if payload:
        return "malware"
    if osint >= 80:
        return "c2"

    for threat_type, patterns in THREAT_PATTERNS.items():
        if any(pattern in texto for pattern in patterns):
            return threat_type
    return "actividad_sospechosa"


def obtener_nivel_prioridad(score):
    if score >= 90:
        return "Prioridad critica"
    if score >= 75:
        return "Prioridad alta"
    if score >= 55:
        return "Prioridad media"
    return "Prioridad baja"


def describir_impacto(threat_type, criticidad, activo):
    base = {
        "malware": "Posible compromiso activo o ejecucion de codigo malicioso",
        "phishing": "Intento de engaño o captura de credenciales",
        "scan": "Actividad de reconocimiento o enumeracion de servicios",
        "web_attack": "Intento de explotacion sobre servicio web",
        "lateral_movement": "Posible movimiento lateral entre equipos internos",
        "c2": "Comunicacion con infraestructura de mando y control o IP con reputacion muy alta",
        "dns_abuse": "Uso anomalo de DNS que podria ocultar exfiltracion o resolucion maliciosa",
        "actividad_sospechosa": "Actividad anomala que requiere validacion contextual",
    }.get(threat_type, "Actividad anomala que requiere validacion contextual")

    if criticidad >= 4:
        return f"{base} sobre un activo sensible: {activo}"
    return f"{base} sobre {activo}"


def construir_plan_accion(threat_type, score, payload, osint, criticidad, activo):
    containment = "aislar temporalmente el host o el flujo afectado" if score >= IA_CRITICAL_THRESHOLD or payload else "mantener el flujo bajo observacion reforzada"

    plans = {
        "malware": (
            f"1) {containment}; "
            "2) revisar procesos, archivos recientes, persistencia y conexiones salientes del equipo; "
            "3) obtener IOC de la firma y buscar si aparecen en otros hosts."
        ),
        "phishing": (
            "1) validar si el dominio, correo o IP ya fue visto por usuarios internos; "
            "2) revisar intentos de autenticacion y cambios recientes en cuentas relacionadas; "
            "3) bloquear el origen si se confirma el intento de suplantacion."
        ),
        "scan": (
            "1) confirmar si el origen pertenece a pruebas autorizadas o inventario interno; "
            "2) revisar puertos destino y frecuencia de los intentos en los ultimos minutos; "
            "3) aplicar bloqueo perimetral o regla de IDS si el patron continua."
        ),
        "web_attack": (
            "1) revisar logs HTTP y parametros solicitados al servicio; "
            "2) verificar si hubo errores 4xx/5xx, ejecucion anomala o cambios en la aplicacion; "
            "3) endurecer reglas WAF o bloqueo del origen segun evidencia."
        ),
        "lateral_movement": (
            "1) revisar autenticaciones laterales, sesiones remotas y uso de credenciales administrativas; "
            "2) contrastar el origen con ventanas de mantenimiento autorizadas; "
            "3) segmentar o bloquear el acceso entre equipos si no hay justificacion operativa."
        ),
        "c2": (
            "1) revisar conexiones repetitivas hacia la IP o dominio indicado; "
            "2) validar reputacion externa, puertos y frecuencia del beaconing; "
            "3) contener la comunicacion y buscar persistencia en el host afectado."
        ),
        "dns_abuse": (
            "1) inspeccionar el dominio consultado y la frecuencia de consultas DNS; "
            "2) validar si existe tunelizacion o resolucion hacia infraestructura no autorizada; "
            "3) bloquear el dominio o resolver alternativo si se confirma abuso."
        ),
        "actividad_sospechosa": (
            "1) revisar el contexto del activo, el origen y el momento del evento; "
            "2) contrastar con logs de red y sistema para descartar falso positivo; "
            "3) escalar a contencion si aparecen nuevas alertas relacionadas."
        ),
    }

    plan = plans.get(threat_type, plans["actividad_sospechosa"])
    if osint >= 70 and "reputacion" not in plan.lower():
        plan += " 4) validar reputacion del origen y del destino con las fuentes OSINT disponibles."
    if criticidad >= 5:
        plan += f" 5) priorizar la revision porque {activo} tiene criticidad maxima."
    return plan


def construir_justificacion(threat_type, score, payload, osint, criticidad):
    reasons = [f"el modelo asigno {score:.1f} puntos"]
    if payload:
        reasons.append("se detectaron indicadores de payload malicioso")
    if osint >= 60:
        reasons.append(f"la reputacion OSINT es elevada ({osint:.1f})")
    if criticidad >= 4:
        reasons.append(f"el activo tiene criticidad {criticidad}/5")
    if threat_type != "actividad_sospechosa":
        reasons.append(f"el patron coincide con un escenario de {threat_type.replace('_', ' ')}")
    return "; ".join(reasons) + "."

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
