import ipaddress

import requests

from config import ABUSEIPDB_API_KEY, GREYNOISE_API_KEY, OTX_API_KEY, VT_API_KEY


def es_ip_privada(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def consultar_virustotal(ip):
    resultado = {
        "vt_malicious": 0,
        "vt_suspicious": 0,
        "vt_reputation": 0,
    }

    if not ip or es_ip_privada(ip) or not VT_API_KEY:
        return resultado

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            return resultado

        attributes = response.json().get("data", {}).get("attributes", {})
        analysis = attributes.get("last_analysis_stats", {})
        resultado["vt_malicious"] = int(analysis.get("malicious", 0) or 0)
        resultado["vt_suspicious"] = int(analysis.get("suspicious", 0) or 0)
        resultado["vt_reputation"] = int(attributes.get("reputation", 0) or 0)
    except requests.RequestException:
        return resultado
    except (TypeError, ValueError):
        return resultado

    return resultado


def consultar_abuseipdb(ip):
    resultado = {
        "abuse_confidence": 0,
        "abuse_reports": 0,
    }

    if not ip or es_ip_privada(ip) or not ABUSEIPDB_API_KEY:
        return resultado

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY,
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code != 200:
            return resultado

        data = response.json().get("data", {})
        resultado["abuse_confidence"] = int(data.get("abuseConfidenceScore", 0) or 0)
        resultado["abuse_reports"] = int(data.get("totalReports", 0) or 0)
    except requests.RequestException:
        return resultado
    except (TypeError, ValueError):
        return resultado

    return resultado


def consultar_greynoise(ip):
    resultado = {
        "gn_noise": False,
        "gn_riot": False,
        "gn_classification": "unknown",
    }

    if not ip or es_ip_privada(ip):
        return resultado

    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"Accept": "application/json"}
    if GREYNOISE_API_KEY:
        headers["key"] = GREYNOISE_API_KEY

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code in (404, 429):
            return resultado
        if response.status_code != 200:
            return resultado

        data = response.json()
        resultado["gn_noise"] = bool(data.get("noise", False))
        resultado["gn_riot"] = bool(data.get("riot", False))
        resultado["gn_classification"] = str(data.get("classification", "unknown") or "unknown")
    except requests.RequestException:
        return resultado
    except (TypeError, ValueError):
        return resultado

    return resultado


def consultar_otx(ip):
    resultado = {
        "otx_pulse_count": 0,
        "otx_tags": "",
        "otx_malware_families": "",
    }

    if not ip or es_ip_privada(ip) or not OTX_API_KEY:
        return resultado

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {
        "X-OTX-API-KEY": OTX_API_KEY,
        "Accept": "application/json",
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            return resultado

        data = response.json()
        pulse_info = data.get("pulse_info", {}) or {}
        pulses = pulse_info.get("pulses", []) or []

        resultado["otx_pulse_count"] = int(pulse_info.get("count", 0) or 0)

        tags = set()
        malware_families = set()
        for pulse in pulses:
            for tag in pulse.get("tags", []) or []:
                if tag:
                    tags.add(str(tag))
            for family in pulse.get("malware_families", []) or []:
                if isinstance(family, dict):
                    family = family.get("display_name") or family.get("name")
                if family:
                    malware_families.add(str(family))

        resultado["otx_tags"] = ", ".join(sorted(tags))
        resultado["otx_malware_families"] = ", ".join(sorted(malware_families))
    except requests.RequestException:
        return resultado
    except (TypeError, ValueError):
        return resultado

    return resultado


def enriquecer_ip(ip):
    enriquecimiento = {
        "vt_malicious": 0,
        "vt_suspicious": 0,
        "vt_reputation": 0,
        "abuse_confidence": 0,
        "abuse_reports": 0,
        "gn_noise": False,
        "gn_riot": False,
        "gn_classification": "unknown",
        "otx_pulse_count": 0,
        "otx_tags": "",
        "otx_malware_families": "",
    }

    enriquecimiento.update(consultar_virustotal(ip))
    enriquecimiento.update(consultar_abuseipdb(ip))
    enriquecimiento.update(consultar_greynoise(ip))
    enriquecimiento.update(consultar_otx(ip))
    enriquecimiento["osint_score"] = calcular_osint_score(enriquecimiento)
    return enriquecimiento


def calcular_osint_score(enriquecimiento):
    vt_score = min(int(enriquecimiento.get("vt_malicious", 0)), 10) * 3
    vt_score += min(int(enriquecimiento.get("vt_suspicious", 0)), 5) * 1

    abuse_score = min(int(enriquecimiento.get("abuse_confidence", 0)), 100) * 0.25
    abuse_score += min(int(enriquecimiento.get("abuse_reports", 0)), 20) * 0.5

    if enriquecimiento.get("gn_riot"):
        gn_score = -10
    elif enriquecimiento.get("gn_noise"):
        gn_score = 5
    else:
        gn_score = 0

    if enriquecimiento.get("gn_classification") == "malicious":
        gn_score += 10

    otx_score = min(int(enriquecimiento.get("otx_pulse_count", 0)), 10) * 2

    return round(max(0, vt_score + abuse_score + gn_score + otx_score), 1)
