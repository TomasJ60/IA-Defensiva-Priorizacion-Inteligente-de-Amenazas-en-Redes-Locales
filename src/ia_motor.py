#!/usr/bin/env python3
from pathlib import Path
import pickle
import time
import warnings

import pandas as pd

from utils import get_db_connection

warnings.filterwarnings("ignore")

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "data" / "modelo_alertas.joblib"
METRICS_PATH = BASE_DIR / "data" / "model_metrics.json"
FEATURES = ["severidad", "reputacion_osint", "criticidad_activo"]


def cargar_modelo():
    if not MODEL_PATH.exists():
        return None

    with MODEL_PATH.open("rb") as fh:
        modelo = pickle.load(fh)
    if not isinstance(modelo, dict):
        return None

    return modelo


def consultar_alertas_pendientes(conn):
    query = """
        SELECT
            a.id,
            COALESCE(a.severidad, 3) AS severidad,
            COALESCE(a.reputacion_osint, 0) AS reputacion_osint,
            COALESCE(a.osint_score, 0) AS osint_score,
            COALESCE(a.vt_malicious, 0) AS vt_malicious,
            COALESCE(a.vt_reputation, 0) AS vt_reputation,
            COALESCE(a.abuse_confidence, 0) AS abuse_confidence,
            COALESCE(a.abuse_reports, 0) AS abuse_reports,
            COALESCE(a.gn_noise, FALSE) AS gn_noise,
            COALESCE(a.gn_riot, FALSE) AS gn_riot,
            COALESCE(a.gn_classification, 'unknown') AS gn_classification,
            COALESCE(a.otx_pulse_count, 0) AS otx_pulse_count,
            COALESCE(act.criticidad, 1) AS criticidad_activo
        FROM alertas a
        LEFT JOIN monitoreo_activo act ON a.ip_destino = host(act.ip)
        WHERE a.prioridad_ia IS NULL
        ORDER BY a.id ASC
    """
    return pd.read_sql_query(query, conn)


def probabilidad_heuristica(severidad, reputacion_osint, criticidad_activo, osint_score=0):
    sev_norm = max(0.0, min(1.0, (4 - float(severidad)) / 3))
    base_osint = max(float(reputacion_osint), float(osint_score) / 10)
    osint_norm = max(0.0, min(1.0, base_osint / 10))
    crit_norm = max(0.0, min(1.0, float(criticidad_activo) / 5))
    return round((sev_norm * 0.4) + (osint_norm * 0.35) + (crit_norm * 0.25), 4)


def probabilidad_modelo(modelo, severidad, reputacion_osint, criticidad_activo, osint_score=0):
    if not modelo:
        return probabilidad_heuristica(severidad, reputacion_osint, criticidad_activo, osint_score), "heuristico"

    clf = modelo["model"]
    classes = list(clf.classes_)
    features = pd.DataFrame(
        [[severidad, reputacion_osint, criticidad_activo]],
        columns=modelo.get("features", FEATURES),
    )
    probas = clf.predict_proba(features)[0]
    if 1 not in classes:
        return probabilidad_heuristica(severidad, reputacion_osint, criticidad_activo, osint_score), "heuristico"
    return float(probas[classes.index(1)]), "ml"


def calcular_score(prob_mal, severidad, reputacion_osint, criticidad_activo, osint_score=0):
    severidad = int(severidad)
    reputacion_osint = int(reputacion_osint)
    criticidad_activo = int(criticidad_activo)
    osint_score = float(osint_score)

    score_crit = criticidad_activo * 8
    score_ia = prob_mal * 25
    score_sev_map = {1: 12, 2: 6, 3: 2}
    score_sev = score_sev_map.get(severidad, 3)
    score_osint = min(reputacion_osint, 5) * 2
    score_osint += min(osint_score, 40) * 0.5

    return float(round(score_ia + score_osint + score_sev + score_crit, 1))


def calcular_ajuste_contextual(
    vt_malicious,
    vt_reputation,
    abuse_confidence,
    abuse_reports,
    gn_noise,
    gn_riot,
    gn_classification,
    otx_pulse_count,
):
    ajuste = 0.0

    if vt_malicious > 0:
        ajuste += min(vt_malicious, 5) * 4
    if abuse_confidence >= 25:
        ajuste += min(abuse_confidence, 80) * 0.12
    if abuse_reports >= 10:
        ajuste += min(abuse_reports, 50) * 0.08
    if otx_pulse_count > 0:
        ajuste += min(otx_pulse_count, 10) * 1.8
    if gn_noise and not gn_riot:
        ajuste += 4
    if gn_classification == "malicious":
        ajuste += 8

    contexto_benigno = (
        gn_riot
        and gn_classification == "benign"
        and vt_malicious == 0
        and abuse_confidence == 0
        and otx_pulse_count == 0
    )
    if contexto_benigno:
        ajuste -= 18
        if vt_reputation > 0:
            ajuste -= 8

    return round(ajuste, 1)


def construir_explicacion(
    prob_mal,
    fuente_prob,
    severidad,
    reputacion_osint,
    criticidad_activo,
    osint_score,
    vt_malicious,
    abuse_confidence,
    gn_noise,
    gn_riot,
    gn_classification,
    otx_pulse_count,
    ajuste_contextual,
    modelo,
):
    if fuente_prob == "ml":
        metricas = ""
        if modelo and modelo.get("metrics"):
            f1 = modelo["metrics"].get("f1")
            accuracy = modelo["metrics"].get("accuracy")
            partes_metricas = []
            if accuracy is not None:
                partes_metricas.append(f"acc={accuracy:.2f}")
            if f1 is not None:
                partes_metricas.append(f"f1={f1:.2f}")
            if partes_metricas:
                metricas = " (" + ", ".join(partes_metricas) + ")"
        base = f"ML{metricas}: {int(prob_mal * 100)}% riesgo. "
    else:
        base = f"Heuristica: {int(prob_mal * 100)}% riesgo estimado. "

    base += f"Criticidad: {int(criticidad_activo)}/5. "
    if float(osint_score) > 0:
        base += f"OSINT score: {float(osint_score):.1f}. "
    if int(reputacion_osint) > 0:
        base += f"VT maliciosos: {int(reputacion_osint)}. "
    if int(vt_malicious) > 0:
        base += f"VT+={int(vt_malicious)}. "
    if int(abuse_confidence) > 0:
        base += f"AbuseIPDB: {int(abuse_confidence)}%. "
    if gn_riot:
        base += "GreyNoise RIOT. "
    elif gn_noise:
        base += "GreyNoise noise. "
    if gn_classification and gn_classification != "unknown":
        base += f"Clase GN: {gn_classification}. "
    if int(otx_pulse_count) > 0:
        base += f"OTX pulses: {int(otx_pulse_count)}. "
    if float(ajuste_contextual) != 0:
        if ajuste_contextual > 0:
            base += f"Ajuste contextual: +{ajuste_contextual:.1f}. "
        else:
            base += f"Ajuste contextual: {ajuste_contextual:.1f}. "
    if int(severidad) == 1:
        base += "Severidad: Alta."
    elif int(severidad) == 2:
        base += "Severidad: Media."
    else:
        base += "Severidad: Baja."
    return base


def construir_recomendacion(score_final):
    if score_final >= 80:
        return "URGENTE: Aislar host inmediatamente."
    if score_final >= 55:
        return "PRECAUCION: Aumentar monitoreo."
    if score_final >= 25:
        return "ALERTA: Revisar actividad."
    return "Comportamiento normal."


def procesar_alertas(conn, modelo):
    cur = conn.cursor()
    df_nuevas = consultar_alertas_pendientes(conn)

    if df_nuevas.empty:
        cur.close()
        return 0

    print(f"Analizando {len(df_nuevas)} alertas pendientes...")

    for _, row in df_nuevas.iterrows():
        alerta_id = int(row["id"])
        severidad = int(row["severidad"])
        reputacion_osint = int(row["reputacion_osint"])
        osint_score = float(row["osint_score"])
        vt_malicious = int(row["vt_malicious"])
        vt_reputation = int(row["vt_reputation"])
        abuse_confidence = int(row["abuse_confidence"])
        abuse_reports = int(row["abuse_reports"])
        gn_noise = bool(row["gn_noise"])
        gn_riot = bool(row["gn_riot"])
        gn_classification = str(row["gn_classification"] or "unknown")
        otx_pulse_count = int(row["otx_pulse_count"])
        criticidad_activo = int(row["criticidad_activo"])

        prob_mal, fuente_prob = probabilidad_modelo(
            modelo,
            severidad,
            reputacion_osint,
            criticidad_activo,
            osint_score,
        )
        score_base = calcular_score(prob_mal, severidad, reputacion_osint, criticidad_activo, osint_score)
        ajuste_contextual = calcular_ajuste_contextual(
            vt_malicious,
            vt_reputation,
            abuse_confidence,
            abuse_reports,
            gn_noise,
            gn_riot,
            gn_classification,
            otx_pulse_count,
        )
        score_final = float(round(max(0, min(100, score_base + ajuste_contextual)), 1))
        explicacion = construir_explicacion(
            prob_mal,
            fuente_prob,
            severidad,
            reputacion_osint,
            criticidad_activo,
            osint_score,
            vt_malicious,
            abuse_confidence,
            gn_noise,
            gn_riot,
            gn_classification,
            otx_pulse_count,
            ajuste_contextual,
            modelo,
        )
        recomendacion = construir_recomendacion(score_final)

        cur.execute(
            """
            UPDATE alertas
            SET prioridad_ia = %s, explicacion = %s, recomendacion = %s
            WHERE id = %s
            """,
            (score_final, explicacion, recomendacion, alerta_id),
        )

    conn.commit()
    cur.close()
    print("Procesamiento finalizado.")
    return len(df_nuevas)


def ejecutar_motor():
    print("Motor IA iniciado. Monitoreando base de datos...")
    modelo = cargar_modelo()
    if modelo:
        print(f"Modelo cargado desde {MODEL_PATH.name}.")
    else:
        print("No hay modelo entrenado. Se usara el modo heuristico.")

    while True:
        try:
            conn = get_db_connection()
            try:
                procesar_alertas(conn, modelo)
            finally:
                conn.close()
        except Exception as e:
            print(f"Error en el motor: {e}")

        time.sleep(2)


if __name__ == "__main__":
    ejecutar_motor()
