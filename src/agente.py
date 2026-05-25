#!/usr/bin/env python3
"""
agente.py - Agente de detección SOC (FILTRO EXCLUSIVO DEBIAN)
✅ FILTRO DE RED: Solo procesa tráfico de las IPs 192.168.100.2 y 192.168.100.10
✅ SIN RUIDO: Ignora telemetría de Windows y otras interfaces.
"""

import os
import sys
import json
import time
import logging
import ipaddress
from pathlib import Path
from dotenv import load_dotenv

# Configuración de rutas
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_DIR = SCRIPT_DIR.parent
env_path = PROJECT_DIR / ".env"
load_dotenv(dotenv_path=env_path)

if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from osint import enriquecer_ip, es_ip_privada, diagnosticar_osint
from utils import get_db_connection

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("agente")

log_file = "/var/log/suricata/eve.json"
MONITORED_IPS = set(
    item.strip()
    for item in os.getenv("MONITORED_IPS", "192.168.100.2,192.168.100.10").split(",")
    if item.strip()
)
MONITORED_NETWORKS = [
    ipaddress.ip_network(item.strip(), strict=False)
    for item in os.getenv("MONITORED_NETWORKS", "").split(",")
    if item.strip()
]

# Palabras clave de malware
MALWARE_KEYWORDS = ["ransomware", "trojan", "worm", "backdoor", "shellcode", "exploit", "wannacry"]
FLOW_WINDOW_SECONDS = 60
FLOW_ALERT_THRESHOLD = 1
SYNTHETIC_FLOW_STATE = {}

def extraer_metadata_hint(data):
    event_type = data.get("event_type")
    if event_type == "dns":
        dns_data = data.get("dns", {}) or {}
        return (
            dns_data.get("query")
            or dns_data.get("rrname")
            or (
                dns_data.get("answers", [{}])[0].get("rrname")
                if dns_data.get("answers")
                else ""
            )
            or ""
        )
    if event_type == "tls": return data.get("tls", {}).get("sni", "")
    if event_type == "http": return data.get("http", {}).get("hostname", "")
    return ""


def _cleanup_flow_state(now_ts):
    expired = []
    for key, state in SYNTHETIC_FLOW_STATE.items():
        if now_ts - state["first_seen"] > FLOW_WINDOW_SECONDS and now_ts - state["last_seen"] > FLOW_WINDOW_SECONDS:
            expired.append(key)
    for key in expired:
        SYNTHETIC_FLOW_STATE.pop(key, None)


def construir_firma_evento(data, target_osint):
    event_type = (data.get("event_type") or "").lower()
    hint = extraer_metadata_hint(data).strip()
    signature = data.get("alert", {}).get("signature", "").strip()

    if signature:
        return signature
    if hint:
        return hint
    if target_osint:
        return f"{event_type.upper()} {target_osint}" if event_type else str(target_osint)
    return event_type.upper() if event_type else "Evento de red"


def normalizar_tipo_trafico(data):
    event_type = (data.get("event_type") or "").strip().lower()
    mapping = {
        "dns": "DNS",
        "http": "HTTP",
        "tls": "TLS/SSL",
        "alert": "ALERT",
    }
    if event_type in mapping:
        return mapping[event_type]

    app_proto = (data.get("app_proto") or "").strip().lower()
    if app_proto == "dns":
        return "DNS"
    if app_proto == "http":
        return "HTTP"
    if app_proto == "tls":
        return "TLS/SSL"

    return event_type.upper() if event_type else "DESCONOCIDO"


def detectar_flujo_sospechoso(data):
    if (data.get("event_type") or "").lower() != "flow":
        return None

    proto = (data.get("proto") or "").upper()
    flow = data.get("flow", {}) or {}
    tcp = data.get("tcp", {}) or {}

    # Caso 1: ráfaga SYN/RST típica de hping3/escaneo
    if proto == "TCP":
        if (
            tcp.get("syn") is True
            and tcp.get("rst") is True
            and flow.get("state") == "closed"
            and flow.get("reason") == "timeout"
            and int(flow.get("pkts_toserver", 0)) <= 3
            and int(flow.get("pkts_toclient", 0)) <= 1
        ):
            return {
                "signature": "HEURISTICA SOC - Escaneo/Rafaga TCP SYN-RST",
                "severity": 1,
                "payload_malicioso": True,
                "indicadores": [
                    "Patrón SYN/RST repetitivo",
                    "Flujo TCP cerrado sin sesión estable",
                    "Posible hping3 / escaneo activo",
                ],
            }

    # Caso 2: ICMP repetitivo no esperado
    if proto == "ICMP" and data.get("icmp_type") == 8:
        if int(flow.get("pkts_toserver", 0)) >= 3:
            return {
                "signature": "HEURISTICA SOC - Sonda ICMP repetitiva",
                "severity": 2,
                "payload_malicioso": True,
                "indicadores": [
                    "Ráfaga ICMP Echo Request",
                    "Posible reconocimiento de red",
                ],
            }

    return None


def registrar_alerta_sintetica(cursor, data, detection, target_osint, now_ts):
    src = data.get("src_ip", "")
    dst = data.get("dest_ip", "")
    proto = (data.get("proto") or "FLOW").upper()
    dest_port = data.get("dest_port") or 0
    cache_key = (src, dst, dest_port, proto, detection["signature"])
    state = SYNTHETIC_FLOW_STATE.setdefault(
        cache_key,
        {"count": 0, "first_seen": now_ts, "last_seen": now_ts, "last_emitted": 0},
    )
    state["count"] += 1
    state["last_seen"] = now_ts

    if state["count"] < FLOW_ALERT_THRESHOLD:
        return ("pending", state["count"], cache_key)

    if now_ts - state["last_emitted"] < FLOW_WINDOW_SECONDS:
        return ("cooldown", state["count"], cache_key)

    state["last_emitted"] = now_ts

    osint = enriquecer_ip(target_osint)
    osint_score = calcular_score_amenaza_aumentado(
        osint,
        detection["indicadores"],
        detection["severity"],
    )

    firma = f"{detection['signature']} [{proto}:{dest_port}] x{state['count']}"
    cursor.execute("""
        INSERT INTO alertas (
            fecha, ip_origen, ip_destino, firma, severidad, reputacion_osint,
            osint_score, tipo_trafico, payload_malicioso, indicadores_malware, vt_malicious
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (
        data.get("timestamp"), src, dst, firma, detection["severity"], int(osint_score),
        osint_score, proto, detection["payload_malicioso"], ",".join(detection["indicadores"]),
        osint.get("vt_malicious", 0),
    ))
    return ("alert", cursor.fetchone()[0], cache_key)

def analizar_payload_malicioso(data):
    indicadores = []
    sig = data.get("alert", {}).get("signature", "").lower() if data.get("event_type") == "alert" else ""
    hint = extraer_metadata_hint(data).lower()
    
    for kw in MALWARE_KEYWORDS:
        if kw in sig or kw in hint:
            indicadores.append(f"Patrón detectado: {kw}")
    
    # Detectar uso de curl/herramientas (Tráfico no humano)
    ua = data.get("http", {}).get("http_user_agent", "").lower()
    if "curl" in ua or "python" in ua:
        indicadores.append("User-Agent sospechoso (bot/script)")

    return len(indicadores) > 0, indicadores

def calcular_score_amenaza_aumentado(osint_data, indicadores_payload, base_severidad):
    base_score = float(osint_data.get("osint_score", 0))
    puntos_malware = len(indicadores_payload) * 20
    score_final = base_score + puntos_malware + (base_severidad * 5)
    if len(indicadores_payload) > 0: score_final *= 1.4
    return min(round(score_final, 1), 100.0)


def _ip_is_monitored(ip):
    if not ip:
        return False
    if ip in MONITORED_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in MONITORED_NETWORKS)


def procesar():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
    except Exception as e:
        logger.error(f"Error DB: {e}"); return

    print("=" * 60)
    print(f"🚀 AGENTE MONITOREANDO IPS: {', '.join(sorted(MONITORED_IPS))}")
    if MONITORED_NETWORKS:
        print(f"🚀 AGENTE MONITOREANDO REDES: {', '.join(str(net) for net in MONITORED_NETWORKS)}")
    print("=" * 60)

    if not os.path.exists(log_file): return

    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        while True:
            linea = f.readline()
            if not linea:
                time.sleep(0.1); continue

            try:
                data = json.loads(linea)
                
                # 🛡️ FILTRO DE SEGURIDAD: Solo IPs o redes monitorizadas 🛡️
                src = data.get("src_ip", "")
                dst = data.get("dest_ip", "")
                if not _ip_is_monitored(src) and not _ip_is_monitored(dst):
                    continue # Ignora tráfico fuera de los endpoints/redes vigiladas

                event_type = data.get("event_type")
                if event_type not in ["alert", "dns", "http", "tls", "flow"]:
                    continue

                # Identificar objetivo para OSINT
                hint = extraer_metadata_hint(data)
                target_osint = hint or (dst if not es_ip_privada(dst) else src)

                now_ts = time.time()
                _cleanup_flow_state(now_ts)

                # Evitar bucle con APIs
                if any(api in str(target_osint).lower() for api in ["virustotal", "abuseipdb", "alienvault"]):
                    continue

                if event_type == "flow":
                    detection = detectar_flujo_sospechoso(data)
                    if not detection:
                        continue
                    result = registrar_alerta_sintetica(cursor, data, detection, target_osint, now_ts)
                    status, value, cache_key = result
                    if status == "pending":
                        print(
                            f"📡 Flujo sospechoso acumulado de Debian -> {dst} "
                            f"({value}/{FLOW_ALERT_THRESHOLD}) [{cache_key[3]}]"
                        )
                        continue
                    if status == "cooldown":
                        print(
                            f"📡 Flujo sospechoso repetido de Debian -> {dst} "
                            f"(en espera de nueva ventana) [{cache_key[3]}]"
                        )
                        continue
                    al_id = value
                    print(f"📡 Flujo sospechoso confirmado de Debian -> {dst}")
                    cursor.execute("NOTIFY alertas_nuevas, %s", (str(al_id),))
                    conn.commit()
                    print(f"   ✅ ALERTA HEURISTICA GUARDADA ID {al_id}")
                    continue

                print(f"📡 Evento detectado de Debian -> {target_osint}")

                # Análisis y OSINT
                es_malicioso, indicadores = analizar_payload_malicioso(data)
                osint = enriquecer_ip(target_osint)
                osint_score = calcular_score_amenaza_aumentado(osint, indicadores, int(data.get("alert", {}).get("severity", 3)))

                # Guardar
                firma_evento = construir_firma_evento(data, target_osint)

                tipo_trafico = normalizar_tipo_trafico(data)

                cursor.execute("""
                    INSERT INTO alertas (fecha, ip_origen, ip_destino, firma, severidad, reputacion_osint, 
                    osint_score, tipo_trafico, payload_malicioso, indicadores_malware, vt_malicious)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
                """, (data.get("timestamp"), src, dst, firma_evento,
                      int(data.get("alert", {}).get("severity", 3)), int(osint_score), osint_score, 
                      tipo_trafico, es_malicioso, ",".join(indicadores), osint.get("vt_malicious", 0)))
                
                al_id = cursor.fetchone()[0]
                cursor.execute("NOTIFY alertas_nuevas, %s", (str(al_id),))
                conn.commit()
                print(f"   ✅ GUARDADO ID {al_id}")

            except Exception as e:
                continue

if __name__ == "__main__":
    procesar()
