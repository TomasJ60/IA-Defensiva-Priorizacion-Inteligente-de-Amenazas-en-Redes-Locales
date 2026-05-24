#!/usr/bin/env python3
"""
osint.py - Módulo de enriquecimiento OSINT Dinámico (IPs y Dominios)
"""

import ipaddress
import logging
import time
import requests
import re

# Importar config
from config import ABUSEIPDB_API_KEY, GREYNOISE_API_KEY, OTX_API_KEY, VT_API_KEY

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Helpers de Identificación
# ──────────────────────────────────────────────

def identificar_tipo(objetivo: str) -> str:
    """Detecta si el objetivo es 'ip' o 'dominio'."""
    try:
        ipaddress.ip_address(objetivo)
        return "ip"
    except ValueError:
        # Validar si parece un dominio (contiene puntos y no espacios)
        if "." in objetivo and " " not in objetivo:
            return "dominio"
    return "desconocido"

def es_ip_privada(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_loopback or obj.is_link_local
    except ValueError:
        return False

def _get_con_reintentos(url: str, headers: dict, params: dict = None, intentos: int = 2):
    for intento in range(intentos):
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=10)
            return resp
        except Exception as e:
            logger.warning(f"Error en intento {intento+1} para {url}: {e}")
            if intento < intentos - 1: time.sleep(1)
    return None

# ──────────────────────────────────────────────
# Fuentes OSINT
# ──────────────────────────────────────────────

def consultar_virustotal(objetivo: str, tipo: str) -> dict:
    res = {"vt_malicious": 0, "vt_suspicious": 0, "vt_reputation": 0, "vt_disponible": False, "vt_razon_fallo": ""}
    
    if not VT_API_KEY:
        res["vt_razon_fallo"] = "no_api_key"
        return res

    # CAMBIO DINÁMICO DE ENDPOINT
    endpoint = "ip_addresses" if tipo == "ip" else "domains"
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{objetivo}"
    headers = {"x-apikey": VT_API_KEY}

    resp = _get_con_reintentos(url, headers)
    if resp and resp.status_code == 200:
        try:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            res.update({
                "vt_malicious": int(stats.get("malicious", 0)),
                "vt_suspicious": int(stats.get("suspicious", 0)),
                "vt_reputation": int(data.get("reputation", 0)),
                "vt_disponible": True
            })
        except Exception as e: res["vt_razon_fallo"] = f"parse_error_{e}"
    else:
        res["vt_razon_fallo"] = f"http_{resp.status_code if resp else 'timeout'}"
    
    return res

def consultar_otx(objetivo: str, tipo: str) -> dict:
    res = {"otx_pulse_count": 0, "otx_tags": "", "otx_disponible": False, "otx_razon_fallo": ""}
    
    if not OTX_API_KEY: return res

    # CAMBIO DINÁMICO DE ENDPOINT
    tipo_otx = "IPv4" if tipo == "ip" else "domain"
    url = f"https://otx.alienvault.com/api/v1/indicators/{tipo_otx}/{objetivo}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    resp = _get_con_reintentos(url, headers)
    if resp and resp.status_code == 200:
        try:
            pinfo = resp.json().get("pulse_info", {})
            pulses = pinfo.get("pulses", [])
            tags = {t for p in pulses for t in p.get("tags", [])}
            res.update({
                "otx_pulse_count": int(pinfo.get("count", 0)),
                "otx_tags": ", ".join(list(tags)[:10]), # max 10 tags
                "otx_disponible": True
            })
        except Exception: res["otx_razon_fallo"] = "parse_error"
    return res

def consultar_abuseipdb(objetivo: str, tipo: str) -> dict:
    res = {"abuse_confidence": 0, "abuse_reports": 0, "abuse_disponible": False}
    if tipo != "ip" or not ABUSEIPDB_API_KEY: return res # Solo IPs

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {"ipAddress": objetivo, "maxAgeInDays": 90}

    resp = _get_con_reintentos(url, headers, params)
    if resp and resp.status_code == 200:
        data = resp.json().get("data", {})
        res.update({
            "abuse_confidence": int(data.get("abuseConfidenceScore", 0)),
            "abuse_reports": int(data.get("totalReports", 0)),
            "abuse_disponible": True
        })
    return res

def consultar_greynoise(objetivo: str, tipo: str) -> dict:
    res = {"gn_classification": "unknown", "gn_riot": False, "gn_disponible": False}
    if tipo != "ip": return res # Solo IPs

    url = f"https://api.greynoise.io/v3/community/{objetivo}"
    headers = {"Accept": "application/json"}
    if GREYNOISE_API_KEY: headers["key"] = GREYNOISE_API_KEY

    resp = _get_con_reintentos(url, headers)
    if resp and resp.status_code == 200:
        data = resp.json()
        res.update({
            "gn_classification": data.get("classification", "unknown"),
            "gn_riot": bool(data.get("riot", False)),
            "gn_disponible": True
        })
    return res

# ──────────────────────────────────────────────
# Orquestador Principal (Usado por agente.py)
# ──────────────────────────────────────────────

def enriquecer_ip(objetivo: str) -> dict:
    """
    Función unificada que analiza IPs o Dominios.
    """
    tipo = identificar_tipo(objetivo)
    
    enriquecimiento = {
        "vt_malicious": 0, "vt_suspicious": 0, "vt_reputation": 0,
        "abuse_confidence": 0, "abuse_reports": 0,
        "gn_noise": False, "gn_riot": False, "gn_classification": "unknown",
        "otx_pulse_count": 0, "otx_tags": "", "otx_malware_families": "",
        "vt_disponible": False, "abuse_disponible": False, "gn_disponible": False, "otx_disponible": False,
        "osint_score": 0.0, "osint_disponible": False, "osint_razon_sin_datos": "", "ip_es_privada": False
    }

    if not objetivo or tipo == "desconocido":
        enriquecimiento["osint_razon_sin_datos"] = "objetivo_invalido"
        return enriquecimiento

    if tipo == "ip" and es_ip_privada(objetivo):
        enriquecimiento["ip_es_privada"] = True
        enriquecimiento["osint_razon_sin_datos"] = "ip_privada"
        return enriquecimiento

    logger.info(f"Consultando OSINT para {tipo}: {objetivo}")

    # Consultas paralelas conceptualmente (secuenciales aquí)
    vt = consultar_virustotal(objetivo, tipo)
    otx = consultar_otx(objetivo, tipo)
    ab = consultar_abuseipdb(objetivo, tipo)
    gn = consultar_greynoise(objetivo, tipo)

    enriquecimiento.update(vt)
    enriquecimiento.update(otx)
    enriquecimiento.update(ab)
    enriquecimiento.update(gn)

    enriquecimiento["osint_disponible"] = any([
        vt['vt_disponible'],
        otx['otx_disponible'],
        ab['abuse_disponible'],
        gn['gn_disponible'],
    ])
    
    # Cálculo de OSINT SCORE base (esto ayuda al Random Forest a tener una feature numérica fuerte)
    enriquecimiento["osint_score"] = calcular_osint_score_dinamico(enriquecimiento)
    
    return enriquecimiento

def calcular_osint_score_dinamico(e: dict) -> float:
    """
    Calcula un valor 0-100 combinando las métricas obtenidas.
    VERSIÓN 2: Pesos mejorados + GreyNoise integrado.
    """
    score = 0.0
    
    # 1. VirusTotal: 1 motor malo = 10 pts, 10 motores = 50 pts (cap)
    score += min(e.get("vt_malicious", 0) * 8.0, 50.0)
    
    # 2. AbuseIPDB: 0-100% confianza → 0-50 pts (aumentado de 30 a 50)
    score += (e.get("abuse_confidence", 0) / 100.0) * 50.0
    
    # 3. OTX: 1 pulso = 10 pts (aumentado de 5), máx 40 pts
    score += min(e.get("otx_pulse_count", 0) * 10.0, 40.0)
    
    # 4. GreyNoise: "malicious" +30, "benign" -20, "unknown" 0
    gn_class = e.get("gn_classification", "unknown").lower()
    if gn_class == "malicious":
        score += 30.0
    elif gn_class == "benign":
        score = max(score - 20.0, 0.0)  # Nunca negativo
    # else: unknown → no suma ni resta
    
    # 5. Si es RIOT (legítimo comprobado), penalizar fuerte
    #    pero SOLO si GreyNoise lo dice explícitamente
    if e.get("gn_riot"):
        score = score * 0.2  # Reducir drásticamente pero no anular totalmente
    
    return round(min(score, 100.0), 1)

def diagnosticar_osint() -> dict:
    estado = {"virustotal": bool(VT_API_KEY), "abuseipdb": bool(ABUSEIPDB_API_KEY), "greynoise": bool(GREYNOISE_API_KEY), "otx": bool(OTX_API_KEY)}
    return estado