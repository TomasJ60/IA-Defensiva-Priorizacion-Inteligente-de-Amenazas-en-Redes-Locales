import ipaddress
import json
import os
import re
import subprocess
import tldextract
from pathlib import Path
from functools import wraps

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.sessions.models import Session
from django.contrib.auth.views import LoginView
from django.db.models import Avg, Count, Q
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from .audit import log_security_event
from .models import Activo, Alerta, AuthLockout, MonitoredEndpoint, SecurityEvent, TwoFactorDevice, SuricataConfig
from .roles import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_VIEWER,
    assign_soc_role,
    clear_soc_roles,
    get_role_label,
    is_admin_user,
    require_admin_access,
    require_asset_management,
    require_soc_access,
    user_can_manage_assets,
    user_can_view_sensitive_data,
)
from .throttling import (
    clear_failures,
    get_block_message,
    get_failure_message,
    get_lockout,
    normalize_subject,
    register_failure,
)
from .totp import construir_otpauth_uri, construir_qr_data_uri, generar_secreto_base32, verificar_totp


SESSION_2FA_USER_KEY = "two_factor_user_id"
SESSION_2FA_PASSED_KEY = "two_factor_passed"
SESSION_POST_2FA_REDIRECT_KEY = "post_2fa_redirect"
TWO_FACTOR_ISSUER = "Agente IA"
PROJECT_DIR = Path(__file__).resolve().parents[2]
MODEL_METRICS_PATH = PROJECT_DIR / "data" / "model_metrics.json"


def _get_enabled_monitored_ips():
    return list(
        MonitoredEndpoint.objects.filter(is_enabled=True).values_list("ip", flat=True)
    )

def _filter_alertas_for_enabled_targets(queryset):
    # enabled_ips = _get_enabled_monitored_ips()
    # if not enabled_ips:
    #    return queryset

    #query = Q()
    #for ip in enabled_ips:
    #    query |= Q(ip_origen=ip) | Q(ip_destino=ip)
    return queryset


def _run_ping_check(ip_address):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip_address],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "reachable": False,
            "latency_ms": None,
            "message": f"Ping fallido: {exc}",
        }

    output = f"{result.stdout}\n{result.stderr}"
    latency_match = re.search(r"time=([0-9]+(?:\.[0-9]+)?)\s*ms", output)
    latency_ms = float(latency_match.group(1)) if latency_match else None

    if result.returncode == 0:
        message = "Conectividad verificada correctamente."
        if latency_ms is not None:
            message = f"Conectividad verificada ({latency_ms:.2f} ms)."
        return {
            "reachable": True,
            "latency_ms": latency_ms,
            "message": message,
        }

    return {
        "reachable": False,
        "latency_ms": latency_ms,
        "message": "Sin respuesta al ping.",
    }


def _parse_ip_link_output(output):
    interfaces = []
    for line in output.splitlines():
        parts = line.split(':', 2)
        if len(parts) < 2:
            continue
        name = parts[1].strip().split('@')[0]
        if name and name != 'lo':
            interfaces.append(name)
    return interfaces


def _detect_active_network_interfaces():
    interfaces = []
    try:
        result = subprocess.run(
            ['ip', '-o', 'link', 'show', 'up'],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if result.returncode == 0:
            interfaces = _parse_ip_link_output(result.stdout)
    except Exception:
        interfaces = []

    if not interfaces:
        try:
            net_dir = Path('/sys/class/net')
            interfaces = [p.name for p in net_dir.iterdir() if p.is_dir() and p.name != 'lo']
        except Exception:
            interfaces = []

    return interfaces


def _normalize_interface_list(value):
    return [iface.strip() for iface in value.split(',') if iface.strip()]


def _load_project_env():
    env_path = Path(settings.PROJECT_ROOT) / '.env'
    values = {}
    if not env_path.exists():
        return values

    for raw_line in env_path.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _save_project_env(updates):
    env_path = Path(settings.PROJECT_ROOT) / '.env'
    if not env_path.exists():
        env_path.write_text('', encoding='utf-8')

    existing_lines = env_path.read_text(encoding='utf-8').splitlines()
    seen = set()
    output_lines = []
    for raw_line in existing_lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith('#') or '=' not in raw_line:
            output_lines.append(raw_line)
            continue
        key, _ = raw_line.split('=', 1)
        key = key.strip()
        if key in updates:
            output_lines.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            output_lines.append(raw_line)
    for key, value in updates.items():
        if key not in seen:
            output_lines.append(f"{key}={value}")
    env_path.write_text('\n'.join(output_lines) + '\n', encoding='utf-8')


def _severity_badge(value):
    if value is None:
        return {"label": "Sin clasificar", "tone": "neutral"}
    if value >= 5:
        return {"label": "Critica", "tone": "critical"}
    if value >= 4:
        return {"label": "Alta", "tone": "high"}
    if value >= 3:
        return {"label": "Media", "tone": "medium"}
    return {"label": "Baja", "tone": "low"}


def _priority_badge(value):
    score = value or 0
    if score >= 95:
        return {"label": "Maxima", "tone": "critical"}
    if score >= 85:
        return {"label": "Elevada", "tone": "high"}
    if score >= 70:
        return {"label": "Vigilancia", "tone": "medium"}
    return {"label": "Reducida", "tone": "low"}


def _safe_localtime(value):
    if not value:
        return None
    if isinstance(value, str):
        parsed = parse_datetime(value)
        if parsed is None:
            parsed_date = parse_date(value)
            if parsed_date is not None:
                from datetime import datetime

                parsed = datetime.combine(parsed_date, datetime.min.time())
        value = parsed or value
    try:
        return timezone.localtime(value)
    except Exception:
        return value


def _extract_ml_metrics(explanation):
    """Extrae métricas desde la explicación IA."""
    metrics = {
        'accuracy': None,
        'f1': None,
        'risk_percentage': None,
        'criticidad': None,
        'osint_score': None,
        'ajuste_contextual': None,
        'severidad': None,
    }
    
    if not explanation:
        return metrics
    
    try:
        # Extraer porcentaje de riesgo (ej: 96.8%)
        risk_match = re.search(r'probabilidad de amenaza del ([\d.]+)%', explanation, re.IGNORECASE)
        if risk_match:
            metrics['risk_percentage'] = float(risk_match.group(1))
        
        # Extraer OSINT (ej: OSINT (45.0))
        osint_match = re.search(r'OSINT \(([\d.]+)\)', explanation, re.IGNORECASE)
        if osint_match:
            metrics['osint_score'] = float(osint_match.group(1))
        
        # Extraer Criticidad (ej: criticidad del activo (5/5))
        crit_match = re.search(r'criticidad del activo \((\d+)/5\)', explanation, re.IGNORECASE)
        if crit_match:
            metrics['criticidad'] = int(crit_match.group(1))

        # Extraer accuracy y f1 si están incluidos en la explicación
        acc_match = re.search(r'\baccuracy\b[:=]?\s*([\d.]+)\s*%?', explanation, re.IGNORECASE)
        if acc_match:
            accuracy_value = float(acc_match.group(1))
            if accuracy_value <= 1:
                accuracy_value *= 100
            metrics['accuracy'] = round(accuracy_value, 1)

        f1_match = re.search(r'\bf1\b[:=]?\s*([\d.]+)\s*%?', explanation, re.IGNORECASE)
        if f1_match:
            f1_value = float(f1_match.group(1))
            if f1_value <= 1:
                f1_value *= 100
            metrics['f1'] = round(f1_value, 1)
    except Exception:
        pass
    
    return metrics


def _load_model_metrics():
    metrics = {
        "accuracy": None,
        "f1": None,
        "precision": None,
        "recall": None,
        "train_rows": None,
        "test_rows": None,
        "dataset_rows": None,
    }

    try:
        if not MODEL_METRICS_PATH.exists():
            return metrics

        with MODEL_METRICS_PATH.open("r", encoding="utf-8") as fh:
            raw_metrics = json.load(fh)

        for key in ("accuracy", "f1", "precision", "recall"):
            value = raw_metrics.get(key)
            if value is None:
                continue
            value = float(value)
            if value <= 1:
                value *= 100
            metrics[key] = round(value, 2)

        for key in ("train_rows", "test_rows", "dataset_rows"):
            value = raw_metrics.get(key)
            if value is not None:
                metrics[key] = int(value)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass

    return metrics


def _infer_service_from_signature(signature):
    """Inferir un servicio/dispositivo conocido a partir de la firma."""
    if not signature:
        return None

    lower = signature.lower()
    providers = [
        ("youtube", "YouTube"),
        ("google", "Google"),
        ("cloudflare", "Cloudflare"),
        ("microsoft", "Microsoft"),
        ("amazon", "Amazon"),
        ("aws", "AWS"),
        ("azure", "Azure"),
        ("facebook", "Facebook"),
        ("apple", "Apple"),
        ("linkedin", "LinkedIn"),
        ("twitter", "Twitter"),
        ("dropbox", "Dropbox"),
        ("slack", "Slack"),
        ("github", "GitHub"),
        ("gmail", "Gmail"),
    ]

    for token, label in providers:
        if token in lower:
            return label

    # Detectar firmas comunes de tráfico benigno que no incluyen dominio explícito.
    if "web navigation" in lower or "trusted domain" in lower:
        return "Navegación Web"
    if "legitimate cloud service" in lower or "cloud service" in lower:
        return "Servicio en la nube"
    if "reserved internal ssh traffic" in lower or "ssh traffic" in lower:
        return "SSH Interno"
    if "internal ssh" in lower:
        return "SSH Interno"
    if "trusted" in lower and "domain" in lower:
        return "Dominio confiable"
    if "dns query" in lower:
        return "Consulta DNS"

    fallback_domain_match = re.search(
        r"\b([a-z0-9-]+\.(?:com|net|org|io|cloud|tech|app|site|dev|es|mx|uk|gov|edu|biz|info|co|tv|me))\b",
        lower,
    )
    if fallback_domain_match:
        return fallback_domain_match.group(1)

    service_match = re.search(r"\b([a-z0-9]{3,})\s+(dns|http|ssl|tls|ssh|smtp|ftp|icmp)\b", lower)
    if service_match:
        return service_match.group(1).title()

    return None


def _extract_primary_domain(text):
    """
    Extrae el dominio principal real desde eventos DNS.
    """
    if not text:
        return None

    patterns = [
        r"rrname':\s*'([^']+)'",
        r"\[Dominio:\s*([^\]]+)\]",
        r"\[Host:\s*([^\]]+)\]",
        r"\[SNI:\s*([^\]]+)\]",
        r"hostname[:=]\s*([^\s,;]+)",
        r"domain[:=]\s*([^\s,;]+)",
        r"host[:=]\s*([^\s,;]+)",
        r"https?://([^\s/]+)",
        r"\b([a-z0-9-]+\.(?:com|net|org|io|cloud|tech|app|site|dev|es|mx|uk|gov|edu|biz|info|co|tv|me))\b",
    ]

    raw_domain = None
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            raw_domain = match.group(1).lower().strip()
            break

    if not raw_domain:
        return None

    raw_domain = raw_domain.rstrip(".")
    raw_domain = re.sub(r":\d+$", "", raw_domain)

    extracted = tldextract.extract(raw_domain)

    if not extracted.domain or not extracted.suffix:
        return raw_domain

    return f"{extracted.domain}.{extracted.suffix}"


def _normalize_text(value):
    return (value or "").strip().lower()


def _build_endpoint_index():
    activos = {
        str(activo.ip): {"name": activo.nombre, "kind": "activo"}
        for activo in Activo.objects.all().only("ip", "nombre")
    }
    monitoreados = {
        str(endpoint.ip): {"name": endpoint.nombre, "kind": "monitoreado"}
        for endpoint in MonitoredEndpoint.objects.all().only("ip", "nombre")
    }
    return {"activos": activos, "monitoreados": monitoreados}


def _sync_asset_and_endpoint_names(ip, nombre):
    if not ip or not nombre:
        return
    Activo.objects.filter(ip=ip).update(nombre=nombre)
    MonitoredEndpoint.objects.filter(ip=ip).update(nombre=nombre)


def _sync_enabled_monitored_endpoints_into_assets():
    for endpoint in MonitoredEndpoint.objects.filter(is_enabled=True).only("ip", "nombre"):
        Activo.objects.get_or_create(
            ip=endpoint.ip,
            defaults={
                "nombre": endpoint.nombre or f"Endpoint {endpoint.ip}",
                "criticidad": 3,
            },
        )
        # Si el activo ya existía, no sobreescribimos su criticidad.
        Activo.objects.filter(ip=endpoint.ip).update(nombre=endpoint.nombre or f"Endpoint {endpoint.ip}")


def _parse_indicator_list(raw_value):
    if not raw_value:
        return []
    return [item.strip() for item in str(raw_value).split(",") if item.strip()]


def _resolve_endpoint(ip_value, endpoint_index):
    ip_value = (ip_value or "").strip()
    if not ip_value:
        return {
            "ip": None,
            "name": None,
            "kind": None,
            "display": "Sin IP",
            "display_with_ip": "Sin IP",
        }

    endpoint = (
        endpoint_index["activos"].get(ip_value)
        or endpoint_index["monitoreados"].get(ip_value)
        or {}
    )
    name = endpoint.get("name")
    kind = endpoint.get("kind")
    display = f"{name} ({ip_value})" if name else ip_value

    return {
        "ip": ip_value,
        "name": name,
        "kind": kind,
        "display": display,
        "display_with_ip": display,
    }


def _is_private_ip(ip_value):
    try:
        return ipaddress.ip_address((ip_value or "").strip()).is_private
    except ValueError:
        return False


def _build_benign_group_key(alerta, osint_context_data):
    primary_domain = _normalize_text(osint_context_data.get("primary_domain"))
    if primary_domain in {"", "n/a"}:
        primary_domain = ""

    traffic_type = _normalize_text(osint_context_data.get("traffic_type"))
    source_ip = _normalize_text(alerta.ip_origen)
    destination_ip = _normalize_text(alerta.ip_destino)
    cleaned_signature = _normalize_text(_clean_dns_signature(alerta.firma))
    fallback_name = _normalize_text(osint_context_data.get("service_detected"))

    return (
        source_ip or "sin-origen",
        destination_ip or "sin-destino",
        traffic_type or "sin-tipo",
        primary_domain or fallback_name or cleaned_signature or "sin-firma",
    )


def _build_critical_group_key(alerta, osint_context_data):
    affected_asset = _normalize_text(osint_context_data.get("destination_name"))
    affected_ip = _normalize_text(alerta.ip_destino)
    source_ip = _normalize_text(alerta.ip_origen)
    destination_ip = _normalize_text(alerta.ip_destino)
    threat_type = _normalize_text(_clean_dns_signature(alerta.firma))

    return (
        affected_asset or "sin-activo",
        affected_ip or "sin-ip",
        source_ip or "sin-origen",
        destination_ip or "sin-destino",
        threat_type or "sin-amenaza",
    )


def _is_benign_group_candidate(alerta, osint_context_data):
    prioridad = alerta.prioridad_ia or 0
    severidad = alerta.severidad if alerta.severidad is not None else 3
    service_name = (osint_context_data.get("service_detected") or "").strip().lower()
    traffic_type = (osint_context_data.get("traffic_type") or "").strip().upper()
    has_malicious_osint = bool(alerta.vt_malicious or alerta.vt_suspicious)
    generic_signature = _normalize_text(alerta.firma) in {"", "alerta", "evento de red"}
    same_flow_ip_only = (
        osint_context_data.get("primary_domain") in (None, "", "N/A")
        and bool(_normalize_text(alerta.ip_destino))
    )

    known_benign_services = {
        "google", "youtube", "cloudflare", "microsoft", "aws", "azure",
        "amazon", "github", "slack", "dropbox", "facebook", "apple",
        "linkedin", "gmail", "8.8.8.8", "1.1.1.1",
    }

    if has_malicious_osint:
        return False

    if prioridad < 25:
        return True

    if severidad <= 3 and prioridad < 45:
        return True

    if service_name in known_benign_services and prioridad < 60:
        return True

    if same_flow_ip_only and generic_signature and traffic_type in {"DNS", "HTTP", "TLS/SSL"} and prioridad < 50:
        return True

    return False


def _clean_dns_signature(signature):
    """
    Limpia firmas DNS horribles de Suricata
    y extrae el dominio real.
    """
    if not signature:
        return "DNS Query"

    try:
        primary_domain = _extract_primary_domain(signature)
        if primary_domain:
            return f"DNS Query - {primary_domain}"

    except Exception:
        pass

    return signature


def _is_whitelisted_domain(domain):
    """
    Verifica si un dominio está en lista blanca.
    """
    if not domain:
        return False
    return False


def _build_osint_context(alerta, endpoint_index=None):
    """
    Construye contexto OSINT seguro para el dashboard.
    """
    firma = (alerta.firma or "").lower()
    
    # Extraer el dominio REAL desde la firma usando tldextract
    primary_domain = _extract_primary_domain(alerta.firma)
    inferred_service = _infer_service_from_signature(alerta.firma)

    # Prioridad 1: dato real guardado por el agente. Prioridad 2: inferencia por firma.
    traffic_type = (getattr(alerta, "tipo_trafico", None) or "").strip()
    if not traffic_type:
        traffic_type = "Desconocido"
        if re.search(r"\bdns\b", firma):
            traffic_type = "DNS"
        elif re.search(r"\bhttps?\b|web navigation|http", firma):
            traffic_type = "HTTP"
        elif re.search(r"\btls\b|\bssl\b|tls handshake|ssl handshake", firma):
            traffic_type = "TLS/SSL"
        elif re.search(r"\bicmp\b", firma):
            traffic_type = "ICMP"
        elif re.search(r"\bssh\b", firma):
            traffic_type = "SSH"
        elif re.search(r"\bsmtp\b", firma):
            traffic_type = "SMTP"
        elif re.search(r"\bftp\b", firma):
            traffic_type = "FTP"

    source = _resolve_endpoint(alerta.ip_origen, endpoint_index or {"activos": {}, "monitoreados": {}})
    destination = _resolve_endpoint(alerta.ip_destino, endpoint_index or {"activos": {}, "monitoreados": {}})

    if primary_domain:
        service_detected = primary_domain
    elif destination["name"]:
        service_detected = destination["name"]
    elif source["name"]:
        service_detected = source["name"]
    elif alerta.ip_destino and not _is_private_ip(alerta.ip_destino):
        service_detected = alerta.ip_destino
    else:
        service_detected = inferred_service or "No identificado"

    source_label = source["display"]
    destination_label = destination["display"]

    # Reputación OSINT - solo datos reales de la alerta
    reputation_parts = []
    if alerta.vt_malicious:
        reputation_parts.append(f"VT malicious: {alerta.vt_malicious}")
    if alerta.vt_suspicious:
        reputation_parts.append(f"VT suspicious: {alerta.vt_suspicious}")
    if alerta.abuse_confidence:
        reputation_parts.append(f"AbuseIPDB: {alerta.abuse_confidence}%")
    if alerta.otx_pulse_count:
        reputation_parts.append(f"OTX pulses: {alerta.otx_pulse_count}")
    if alerta.osint_score is not None:
        reputation_parts.append(f"OSINT score: {alerta.osint_score}")

    osint_reputation = " | ".join(reputation_parts) if reputation_parts else "Sin datos OSINT"

    # Riesgo basado SOLO en la prioridad IA
    risk_score = alerta.prioridad_ia or 0
    if risk_score >= 90:
        traffic_risk = "CRITICO"
    elif risk_score >= 70:
        traffic_risk = "ALTO"
    elif risk_score >= 40:
        traffic_risk = "MEDIO"
    else:
        traffic_risk = "BAJO"

    context_summary = (
        f"Origen: {source_label} | "
        f"Destino: {destination_label} | "
        f"Dominio: {primary_domain or alerta.ip_destino or 'No identificado'} | "
        f"Tipo: {traffic_type} | "
        f"Riesgo: {traffic_risk}"
    )

    return {
        "service_detected": service_detected,
        "primary_domain": primary_domain or alerta.ip_destino or "N/A",
        "traffic_type": traffic_type,
        "osint_reputation": osint_reputation,
        "traffic_risk": traffic_risk,
        "is_whitelisted": False,
        "summary": context_summary,
        "source": source,
        "destination": destination,
        "source_label": source_label,
        "destination_label": destination_label,
        "source_name": source["name"] or "No identificado",
        "destination_name": destination["name"] or "No identificado",
        "source_is_private": _is_private_ip(alerta.ip_origen),
        "destination_is_private": _is_private_ip(alerta.ip_destino),
    }


def _build_osint_engine_results(alerta):
    vt_data_available = any(
        value is not None
        for value in [alerta.vt_malicious, alerta.vt_suspicious, alerta.vt_reputation]
    )
    abuse_data_available = any(
        value is not None
        for value in [alerta.abuse_confidence, alerta.abuse_reports]
    )
    greynoise_data_available = any(
        value is not None
        for value in [alerta.gn_noise, alerta.gn_riot]
    ) or bool((alerta.gn_classification or "").strip())
    otx_data_available = alerta.otx_pulse_count is not None or bool((alerta.otx_tags or "").strip()) or bool((alerta.otx_malware_families or "").strip())

    vt_summary = "Sin datos consultados"
    if vt_data_available:
        vt_summary = (
            f"Maliciosos: {alerta.vt_malicious or 0} · "
            f"Sospechosos: {alerta.vt_suspicious or 0} · "
            f"Reputacion: {alerta.vt_reputation if alerta.vt_reputation is not None else 'N/D'}"
        )

    abuse_summary = "Sin datos consultados"
    if abuse_data_available:
        abuse_summary = (
            f"Confianza de abuso: {alerta.abuse_confidence if alerta.abuse_confidence is not None else 0}% · "
            f"Reportes: {alerta.abuse_reports if alerta.abuse_reports is not None else 0}"
        )

    greynoise_summary = "Sin datos consultados"
    if greynoise_data_available:
        greynoise_summary = (
            f"Noise: {'Si' if alerta.gn_noise else 'No'} · "
            f"RIOT: {'Si' if alerta.gn_riot else 'No'} · "
            f"Clasificacion: {(alerta.gn_classification or 'N/D')}"
        )

    otx_summary = "Sin datos consultados"
    if otx_data_available:
        otx_summary = (
            f"Pulsos: {alerta.otx_pulse_count if alerta.otx_pulse_count is not None else 0} · "
            f"Tags: {(alerta.otx_tags or 'Sin tags')} · "
            f"Familias: {(alerta.otx_malware_families or 'Sin familias')}"
        )

    engines = [
        {
            "name": "VirusTotal",
            "summary": vt_summary,
            "has_signal": bool((alerta.vt_malicious or 0) > 0 or (alerta.vt_suspicious or 0) > 0),
            "available": vt_data_available,
        },
        {
            "name": "AbuseIPDB",
            "summary": abuse_summary,
            "has_signal": bool((alerta.abuse_confidence or 0) > 0 or (alerta.abuse_reports or 0) > 0),
            "available": abuse_data_available,
        },
        {
            "name": "GreyNoise",
            "summary": greynoise_summary,
            "has_signal": bool(alerta.gn_noise or (alerta.gn_classification or "").strip()),
            "available": greynoise_data_available,
        },
        {
            "name": "AlienVault OTX",
            "summary": otx_summary,
            "has_signal": bool((alerta.otx_pulse_count or 0) > 0 or (alerta.otx_tags or "").strip() or (alerta.otx_malware_families or "").strip()),
            "available": otx_data_available,
        },
    ]
    signal_sources = [engine["name"] for engine in engines if engine["has_signal"]]
    external_signal_summary = ", ".join(signal_sources) if signal_sources else ""
    fallback_summary = ""
    if not signal_sources and (alerta.osint_score or 0) > 0:
        if alerta.payload_malicioso or (alerta.indicadores_malware or "").strip():
            fallback_summary = "El score alto no viene de un proveedor OSINT externo visible. En este caso parece impulsado por heuristica local, payload o indicadores detectados por el agente."
        else:
            fallback_summary = "La alerta conserva un score OSINT, pero no evidencia detallada por proveedor. Probablemente fue generada antes de guardar el desglose completo."
    return engines, external_signal_summary, fallback_summary


def _format_alert_for_dashboard(alerta, can_view_sensitive, endpoint_index=None):
    fecha_local = _safe_localtime(alerta.fecha)
    severity = _severity_badge(alerta.severidad)
    priority = _priority_badge(alerta.prioridad_ia)
    
    # Texto dinámico mientras la IA procesa
    if alerta.prioridad_ia is None:
        explanation = "Procesando analisis IA..."
        recommendation = "Pendiente de recomendacion IA..."
    else:
        explanation = alerta.explicacion or "Sin explicacion generada todavia."
        recommendation = alerta.recomendacion or "Escalar al analista responsable para revision detallada."
    
    ml_metrics = _extract_ml_metrics(explanation)
    model_metrics = _load_model_metrics()
    if ml_metrics["accuracy"] is None:
        ml_metrics["accuracy"] = model_metrics["accuracy"]
    if ml_metrics["f1"] is None:
        ml_metrics["f1"] = model_metrics["f1"]
    ml_metrics["precision"] = model_metrics["precision"]
    ml_metrics["recall"] = model_metrics["recall"]
    ml_metrics["train_rows"] = model_metrics["train_rows"]
    ml_metrics["test_rows"] = model_metrics["test_rows"]
    ml_metrics["dataset_rows"] = model_metrics["dataset_rows"]
    osint_context_data = _build_osint_context(alerta, endpoint_index=endpoint_index)
    osint_engines, osint_signal_sources, osint_signal_note = _build_osint_engine_results(alerta)

    if not can_view_sensitive:
        explanation = "Detalle restringido para este rol. Revisa con un analista o un administrador."
        recommendation = "Elevar la alerta a un rol con acceso ampliado para aplicar la contencion adecuada."

    if hasattr(fecha_local, "strftime"):
        fecha_display = fecha_local.strftime("%d %b %Y")
        hora_display = fecha_local.strftime("%H:%M:%S")
    elif fecha_local:
        fecha_display = str(fecha_local)
        hora_display = "--:--:--"
    else:
        fecha_display = "Sin fecha"
        hora_display = "--:--:--"

    osint_context = []
    if alerta.vt_malicious or alerta.vt_suspicious or alerta.vt_reputation:
        osint_context.append(f"VT: {alerta.vt_malicious or '-'}")
    if alerta.abuse_confidence is not None:
        osint_context.append(f"Abuse: {alerta.abuse_confidence}")
    if alerta.otx_pulse_count:
        osint_context.append(f"OTX: {alerta.otx_pulse_count}")

    repeticiones = getattr(alerta, '_repeticiones', 1)

    return {
        "id": alerta.id,
        "fecha": fecha_local,
        "fecha_display": fecha_display,
        "hora_display": hora_display,
        "ip_origen": alerta.ip_origen,
        "ip_destino": alerta.ip_destino,
        "ip_origen_display": alerta.ip_origen if can_view_sensitive else "Protegida",
        "ip_destino_display": alerta.ip_destino if can_view_sensitive else "Protegida",
        "source_label": osint_context_data["source_label"] if can_view_sensitive else osint_context_data["source_name"],
        "destination_label": osint_context_data["destination_label"] if can_view_sensitive else osint_context_data["destination_name"],
        "source_name": osint_context_data["source_name"],
        "destination_name": osint_context_data["destination_name"],
        "activo_afectado": osint_context_data["destination_name"] or osint_context_data["destination_label"] or "No identificado",
        "tipo_amenaza": _clean_dns_signature(alerta.firma),
        "firma": _clean_dns_signature(alerta.firma),
        "severidad": alerta.severidad,
        "severity_badge": severity,
        "priority_badge": priority,
        "prioridad_ia": alerta.prioridad_ia or 0,
        "osint_score": alerta.osint_score or 0,
        "reputacion_osint": alerta.reputacion_osint,
        "explicacion_display": explanation,
        "recomendacion_display": recommendation,
        "payload_malicioso": alerta.payload_malicioso,
        "indicadores_malware": _parse_indicator_list(alerta.indicadores_malware),
        "indicadores_malware_texto": alerta.indicadores_malware or "",
        "vt_malicious": alerta.vt_malicious,
        "vt_suspicious": alerta.vt_suspicious,
        "vt_reputation": alerta.vt_reputation,
        "abuse_confidence": alerta.abuse_confidence,
        "abuse_reports": alerta.abuse_reports,
        "gn_noise": alerta.gn_noise,
        "gn_riot": alerta.gn_riot,
        "gn_classification": alerta.gn_classification,
        "otx_pulse_count": alerta.otx_pulse_count,
        "otx_tags": alerta.otx_tags,
        "otx_malware_families": alerta.otx_malware_families,
        "osint_signal_sources": osint_signal_sources,
        "osint_signal_note": osint_signal_note,
        "ml_metrics": ml_metrics,
        "osint_context": osint_context_data["summary"],
        "osint_context_data": osint_context_data,
        "osint_engines": osint_engines,
        "explicacion_raw": alerta.explicacion,
        "service_detected": osint_context_data["service_detected"],
        "primary_domain": osint_context_data["primary_domain"],
        "traffic_type": osint_context_data["traffic_type"],
        "osint_reputation": osint_context_data["osint_reputation"],
        "traffic_risk": osint_context_data["traffic_risk"],
        "is_whitelisted": osint_context_data["is_whitelisted"],
        "servicio_detectado": osint_context_data["service_detected"],
        "dominio_principal": osint_context_data["primary_domain"],
        "tipo_trafico": osint_context_data["traffic_type"],
        "origen_resuelto": osint_context_data["source_label"] if can_view_sensitive else osint_context_data["source_name"],
        "destino_resuelto": osint_context_data["destination_label"] if can_view_sensitive else osint_context_data["destination_name"],
        "repeticiones": repeticiones,
        "es_agrupada": repeticiones > 1,
    }


def _build_alert_group_cards(alertas, can_view_sensitive, endpoint_index):
    grouped_alerts = {}

    for alerta in alertas:
        osint_context_data = _build_osint_context(alerta, endpoint_index=endpoint_index)
        key = _build_critical_group_key(alerta, osint_context_data)
        group = grouped_alerts.setdefault(
            key,
            {
                "items": [],
                "latest_alert": alerta,
                "latest_date": alerta.fecha or timezone.now(),
                "highest_score": alerta.prioridad_ia or 0,
            },
        )
        group["items"].append(alerta)

        alert_date = alerta.fecha or timezone.now()
        alert_score = alerta.prioridad_ia or 0
        latest_date = group["latest_date"]
        highest_score = group["highest_score"]
        latest_alert = group["latest_alert"]

        if (
            alert_date > latest_date
            or (alert_date == latest_date and alert_score >= highest_score)
            or (latest_alert.prioridad_ia or 0) < alert_score
        ):
            group["latest_alert"] = alerta
            group["latest_date"] = alert_date
            group["highest_score"] = alert_score

    ordered_groups = sorted(
        grouped_alerts.values(),
        key=lambda group: (
            group["highest_score"],
            group["latest_date"],
        ),
        reverse=True,
    )

    group_cards = []
    for group in ordered_groups:
        sorted_items = sorted(
            group["items"],
            key=lambda item: (
                item.fecha or timezone.now(),
                item.id,
            ),
            reverse=True,
        )

        representative = group["latest_alert"]
        representative._repeticiones = len(sorted_items)
        card = _format_alert_for_dashboard(
            representative,
            can_view_sensitive,
            endpoint_index=endpoint_index,
        )

        card["alertas_relacionadas"] = [
            _format_alert_for_dashboard(
                item,
                can_view_sensitive,
                endpoint_index=endpoint_index,
            )
            for item in sorted_items
        ]
        card["total_alertas_relacionadas"] = len(sorted_items)
        card["es_grupo"] = len(sorted_items) >= 2

        first_date = sorted_items[-1].fecha if sorted_items else None
        last_date = sorted_items[0].fecha if sorted_items else None
        first_local = _safe_localtime(first_date)
        last_local = _safe_localtime(last_date)
        card["primera_ocurrencia_display"] = first_local.strftime("%d %b %Y %H:%M:%S") if hasattr(first_local, "strftime") else "Sin fecha"
        card["ultima_ocurrencia_display"] = last_local.strftime("%d %b %Y %H:%M:%S") if hasattr(last_local, "strftime") else "Sin fecha"
        group_cards.append(card)

    return group_cards


def _build_dashboard_context(request, current_section="overview"):
    can_manage_assets = user_can_manage_assets(request.user)
    can_view_sensitive = user_can_view_sensitive_data(request.user)
    enabled_monitored_ips = _get_enabled_monitored_ips()
    endpoint_index = _build_endpoint_index()

    # SOLUCIÓN: Obtener todas las alertas, SIN FILTRAR por prioridad_ia. 
    base_queryset = _filter_alertas_for_enabled_targets(Alerta.objects.all())

    # Traemos las alertas ordenadas por fecha más reciente
    alertas_recientes = list(base_queryset.order_by("-fecha")[:300])

    alertas_criticas = []
    alertas_benignas_list = []
    
    for alerta in alertas_recientes:
        osint_context_data = _build_osint_context(alerta, endpoint_index=endpoint_index)
        if _is_benign_group_candidate(alerta, osint_context_data):
            alertas_benignas_list.append(alerta)
        else:
            alertas_criticas.append(alerta)
    
    vistas_benignas = {}
    for alerta in alertas_benignas_list:
        osint_context_data = _build_osint_context(alerta, endpoint_index=endpoint_index)
        clave = _build_benign_group_key(alerta, osint_context_data)

        if clave not in vistas_benignas:
            vistas_benignas[clave] = {"alerta": alerta, "contador": 1}
        else:
            vistas_benignas[clave]["contador"] += 1
            fecha_actual = alerta.fecha or timezone.now()
            fecha_guardada = vistas_benignas[clave]["alerta"].fecha or timezone.now()
            if fecha_actual > fecha_guardada:
                vistas_benignas[clave]["alerta"] = alerta
    
    # Ordenar críticas: por score IA (tratando None como 0) y fecha
    alertas_criticas.sort(key=lambda x: (x.prioridad_ia or 0, x.fecha or timezone.now()), reverse=True)

    if current_section == "alertas":
        alert_cards = _build_alert_group_cards(
            alertas_criticas[:120],
            can_view_sensitive,
            endpoint_index,
        )

        benignas_agrupadas = sorted(
            vistas_benignas.values(),
            key=lambda x: x["alerta"].fecha or timezone.now(),
            reverse=True,
        )
        for item in benignas_agrupadas[:30]:
            item["alerta"]._repeticiones = item["contador"]
            card = _format_alert_for_dashboard(
                item["alerta"],
                can_view_sensitive,
                endpoint_index=endpoint_index,
            )
            card["es_grupo"] = False
            card["es_benigna"] = True
            alert_cards.append(card)

        alert_cards.sort(
            key=lambda card: (
                card.get("prioridad_ia", 0),
                card.get("fecha") or timezone.now(),
                card.get("id", 0),
            ),
            reverse=True,
        )
    else:
        alertas_deduplicadas = alertas_criticas[:50]

        # Ordenar benignas por fecha
        benignas_agrupadas = sorted(vistas_benignas.values(), key=lambda x: x["alerta"].fecha or timezone.now(), reverse=True)
        for item in benignas_agrupadas[:15]:
            item["alerta"]._repeticiones = item["contador"]
            alertas_deduplicadas.append(item["alerta"])

        alert_cards = [
            _format_alert_for_dashboard(alerta, can_view_sensitive, endpoint_index=endpoint_index)
            for alerta in alertas_deduplicadas
        ]

    # Contadores reales
    resumen = base_queryset.aggregate(total=Count("id"), promedio=Avg("prioridad_ia"))
    
    return {
        "alertas_criticas_recientes": alert_cards,
        "alertas_osint_recientes": alert_cards[:20],
        "activos_con_alertas": Activo.objects.all().order_by("-criticidad"),
        "total_alertas": resumen["total"] or 0,
        "promedio_prioridad": resumen["promedio"] or 0,
        "role_label": get_role_label(request.user),
        "is_admin_user": is_admin_user(request.user),
        "osint_status": settings.OSINT_PROVIDER_STATUS,
        "osint_configured_count": sum(1 for p in settings.OSINT_PROVIDER_STATUS if p["configured"]),
        "can_manage_assets": can_manage_assets,
        "can_view_sensitive_data": can_view_sensitive,
        "total_alertas_criticas": base_queryset.filter(prioridad_ia__gte=70).count(),
        "ultima_alerta_critica": alert_cards[0] if alert_cards else None,
        "latest_alert_id": base_queryset.order_by("-id").values_list("id", flat=True).first() or 0,
        "criticidad_activos_alta": Activo.objects.filter(criticidad__gte=4).count(),
        "current_section": current_section,
        "enabled_monitored_ips": enabled_monitored_ips,
    }


def _get_post_2fa_redirect(request):
    redirect_to = request.POST.get("next") or request.GET.get("next") or settings.LOGIN_REDIRECT_URL
    login_url = reverse("login")
    if redirect_to == login_url:
        return settings.LOGIN_REDIRECT_URL
    return redirect_to


def _login_subject(request):
    username = normalize_subject(request.POST.get("username") or request.GET.get("username"))
    if username:
        return username
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "") or "anon"


def _two_factor_subject(request):
    if request.user.is_authenticated:
        return normalize_subject(request.user.username)
    return normalize_subject(request.session.get(SESSION_2FA_USER_KEY, "anon"))


def _mark_2fa_pending(request, user_id, redirect_to):
    request.session[SESSION_2FA_USER_KEY] = user_id
    request.session[SESSION_2FA_PASSED_KEY] = False
    request.session[SESSION_POST_2FA_REDIRECT_KEY] = redirect_to or settings.LOGIN_REDIRECT_URL


def _mark_2fa_complete(request):
    request.session[SESSION_2FA_USER_KEY] = request.user.id
    request.session[SESSION_2FA_PASSED_KEY] = True


def _consume_post_2fa_redirect(request):
    return request.session.pop(SESSION_POST_2FA_REDIRECT_KEY, settings.LOGIN_REDIRECT_URL)


def _invalidate_other_sessions(user, current_session_key):
    active_sessions = Session.objects.filter(expire_date__gte=timezone.now())
    invalidated = 0
    for session in active_sessions:
        data = session.get_decoded()
        if str(data.get("_auth_user_id")) == str(user.pk) and session.session_key != current_session_key:
            session.delete()
            invalidated += 1
    return invalidated


def _build_2fa_setup_context(request, device, error=None):
    otpauth_uri = construir_otpauth_uri(device.secret, request.user.username, issuer=TWO_FACTOR_ISSUER)
    return {
        "secret": device.secret,
        "otpauth_uri": otpauth_uri,
        "qr_data_uri": construir_qr_data_uri(otpauth_uri),
        "issuer": TWO_FACTOR_ISSUER,
        "username": request.user.username,
        "error": error,
        "server_time": timezone.localtime(),
    }


def _needs_two_factor(request):
    if not request.user.is_authenticated:
        return False

    device = getattr(request.user, "two_factor_device", None)
    if not device or not device.is_confirmed:
        return True

    return not (
        request.session.get(SESSION_2FA_PASSED_KEY) is True
        and request.session.get(SESSION_2FA_USER_KEY) == request.user.id
    )


def two_factor_required(view_func):
    @wraps(view_func)
    @login_required
    def _wrapped(request, *args, **kwargs):
        if not _needs_two_factor(request):
            return view_func(request, *args, **kwargs)

        device = getattr(request.user, "two_factor_device", None)
        if not device or not device.is_confirmed:
            _mark_2fa_pending(request, request.user.id, request.path)
            return redirect("two_factor_setup")
        _mark_2fa_pending(request, request.user.id, request.path)
        return redirect("two_factor_verify")

    return _wrapped


class TwoFactorLoginView(LoginView):
    template_name = "registration/login.html"

    def post(self, request, *args, **kwargs):
        subject = _login_subject(request)
        lockout = get_lockout("login", subject)
        if lockout and lockout.is_blocked:
            form = self.get_form()
            return self.render_to_response(
                self.get_context_data(
                    form=form,
                    auth_error=get_block_message(lockout, "inicio de sesion"),
                ),
                status=429,
            )
        return super().post(request, *args, **kwargs)

    def form_valid(self, form):
        response = super().form_valid(form)
        clear_failures("login", normalize_subject(self.request.user.username))
        log_security_event(
            self.request,
            "login_success",
            actor=self.request.user,
            details="Inicio de sesion correcto. Pendiente verificacion 2FA.",
        )
        _mark_2fa_pending(self.request, self.request.user.id, _get_post_2fa_redirect(self.request))

        device = getattr(self.request.user, "two_factor_device", None)
        if not device or not device.is_confirmed:
            return redirect("two_factor_setup")
        return redirect("two_factor_verify")

    def get_success_url(self):
        return reverse("soc_dashboard")

    def form_invalid(self, form):
        username = (self.request.POST.get("username") or "").strip()
        subject = _login_subject(self.request)
        lockout, triggered = register_failure("login", subject)
        log_security_event(
            self.request,
            "login_failed",
            username=username,
            details="Credenciales invalidas en el formulario de inicio de sesion.",
        )
        if triggered:
            log_security_event(
                self.request,
                "login_lockout",
                username=username or subject,
                details="Se activo un bloqueo temporal por demasiados intentos fallidos de login.",
            )
        message = (
            get_block_message(lockout, "inicio de sesion")
            if lockout and lockout.is_blocked
            else get_failure_message(lockout, "login", "inicio de sesion")
        )
        return self.render_to_response(
            self.get_context_data(form=form, auth_error=message),
            status=429 if lockout and lockout.is_blocked else 400,
        )


@two_factor_required
@require_soc_access
@never_cache
def soc_dashboard(request):
    return render(request, "monitoreo/overview.html", _build_dashboard_context(request, "overview"))


@two_factor_required
@require_soc_access
@never_cache
def dashboard_alertas(request):
    return render(request, "monitoreo/alertas.html", _build_dashboard_context(request, "alertas"))


@two_factor_required
@require_soc_access
@never_cache
def dashboard_activos(request):
    _sync_enabled_monitored_endpoints_into_assets()
    return render(request, "monitoreo/activos.html", _build_dashboard_context(request, "activos"))


@two_factor_required
@require_soc_access
@never_cache
def dashboard_osint(request):
    return render(request, "monitoreo/osint.html", _build_dashboard_context(request, "osint"))


@two_factor_required
@require_soc_access
@never_cache
def dashboard_redes(request):
    context = _build_dashboard_context(request, "redes")
    env_values = _load_project_env()
    monitored_ips = env_values.get("MONITORED_IPS", "")
    monitored_networks = env_values.get("MONITORED_NETWORKS", "")
    api_keys = {
        "VT_API_KEY": env_values.get("VT_API_KEY", ""),
        "ABUSEIPDB_API_KEY": env_values.get("ABUSEIPDB_API_KEY", ""),
        "GREYNOISE_API_KEY": env_values.get("GREYNOISE_API_KEY", ""),
        "OTX_API_KEY": env_values.get("OTX_API_KEY", ""),
    }
    api_status = {
        "VirusTotal": bool(api_keys["VT_API_KEY"]),
        "AbuseIPDB": bool(api_keys["ABUSEIPDB_API_KEY"]),
        "GreyNoise": bool(api_keys["GREYNOISE_API_KEY"]),
        "OTX": bool(api_keys["OTX_API_KEY"]),
    }
    
    # Parámetros de filtrado de tráfico
    show_all_traffic = request.GET.get('show_all_traffic', 'false').lower() == 'true'
    quick_filter_ip = (request.GET.get('quick_filter_ip') or '').strip()

    # Obtener alertas filtradas según el modo
    queryset = Alerta.objects.all()
    if quick_filter_ip:
        queryset = queryset.filter(Q(ip_origen=quick_filter_ip) | Q(ip_destino=quick_filter_ip))
    elif not show_all_traffic:
        # Filtrar solo por IPs monitoreadas configuradas
        monitored_ips_list = [ip.strip() for ip in monitored_ips.split(',') if ip.strip()]
        monitored_networks_list = [net.strip() for net in monitored_networks.split(',') if net.strip()]
        
        query = Q()
        for ip in monitored_ips_list:
            query |= Q(ip_origen=ip) | Q(ip_destino=ip)
        queryset = queryset.filter(query) if monitored_ips_list else Alerta.objects.none()
    
    alertas_trafico = queryset.order_by('-fecha')[:20]

    if request.method == "POST":
        if not is_admin_user(request.user):
            messages.error(request, "No tienes permisos para modificar esta configuración.")
            return redirect("dashboard_redes")

        action = request.POST.get("action", "")
        updates = {}
        if action == "network_filters":
            updates["MONITORED_IPS"] = request.POST.get("MONITORED_IPS", "").strip()
            updates["MONITORED_NETWORKS"] = request.POST.get("MONITORED_NETWORKS", "").strip()
        elif action == "osint_keys":
            updates["VT_API_KEY"] = request.POST.get("VT_API_KEY", "").strip()
            updates["ABUSEIPDB_API_KEY"] = request.POST.get("ABUSEIPDB_API_KEY", "").strip()
            updates["GREYNOISE_API_KEY"] = request.POST.get("GREYNOISE_API_KEY", "").strip()
            updates["OTX_API_KEY"] = request.POST.get("OTX_API_KEY", "").strip()
        else:
            messages.error(request, "Acción de formulario desconocida.")
            return redirect("dashboard_redes")

        try:
            _save_project_env(updates)
            for key, value in updates.items():
                if value:
                    os.environ[key] = value
                elif key in os.environ:
                    del os.environ[key]
            messages.success(request, "Configuración guardada correctamente. Reinicia los servicios si es necesario.")
        except Exception as e:
            messages.error(request, f"No se pudo guardar la configuración: {str(e)}")
        return redirect("dashboard_redes")

    context.update(
        {
            "monitored_endpoints": MonitoredEndpoint.objects.all(),
            "monitored_ips": monitored_ips,
            "monitored_networks": monitored_networks,
            "api_keys": api_keys,
            "api_status": api_status,
            "alertas_trafico": alertas_trafico,
            "show_all_traffic": show_all_traffic,
            "quick_filter_ip": quick_filter_ip,
        }
    )
    return render(request, "monitoreo/redes.html", context)


@two_factor_required
@require_admin_access
@require_POST
def agregar_endpoint_monitoreado(request):
    nombre = (request.POST.get("nombre") or "").strip()
    ip = (request.POST.get("ip") or "").strip()
    descripcion = (request.POST.get("descripcion") or "").strip()

    if not nombre or not ip:
        messages.error(request, "Nombre e IP son obligatorios para registrar la maquina monitorizada.")
        return redirect("dashboard_redes")

    endpoint, created = MonitoredEndpoint.objects.update_or_create(
        ip=ip,
        defaults={
            "nombre": nombre,
            "descripcion": descripcion,
        },
    )
    Activo.objects.filter(ip=ip).update(nombre=nombre)
    log_security_event(
        request,
        "monitored_endpoint_upsert",
        actor=request.user,
        target_username=ip,
        details=f"Objetivo monitorizado {'creado' if created else 'actualizado'}: {nombre}.",
    )
    messages.success(request, f"Objetivo monitorizado guardado para {nombre} ({ip}).")
    return redirect("dashboard_redes")


@two_factor_required
@require_admin_access
@require_POST
def toggle_endpoint_monitoreado(request, endpoint_id):
    try:
        endpoint = MonitoredEndpoint.objects.get(pk=endpoint_id)
    except MonitoredEndpoint.DoesNotExist:
        messages.error(request, "El objetivo monitorizado no existe.")
        return redirect("dashboard_redes")

    endpoint.is_enabled = not endpoint.is_enabled
    endpoint.save(update_fields=["is_enabled"])
    estado = "habilitado" if endpoint.is_enabled else "deshabilitado"
    log_security_event(
        request,
        "monitored_endpoint_toggled",
        actor=request.user,
        target_username=endpoint.ip,
        details=f"Objetivo monitorizado {estado}: {endpoint.nombre}.",
    )
    messages.success(request, f"Filtro de red {estado} para {endpoint.nombre} ({endpoint.ip}).")
    return redirect("dashboard_redes")


@two_factor_required
@require_admin_access
@require_POST
def verificar_endpoint_monitoreado(request, endpoint_id):
    try:
        endpoint = MonitoredEndpoint.objects.get(pk=endpoint_id)
    except MonitoredEndpoint.DoesNotExist:
        messages.error(request, "El objetivo monitorizado no existe.")
        return redirect("dashboard_redes")

    result = _run_ping_check(endpoint.ip)
    endpoint.last_checked_at = timezone.now()
    endpoint.last_is_reachable = result["reachable"]
    endpoint.last_latency_ms = result["latency_ms"]
    endpoint.last_message = result["message"]
    endpoint.save(
        update_fields=[
            "last_checked_at",
            "last_is_reachable",
            "last_latency_ms",
            "last_message",
        ]
    )
    log_security_event(
        request,
        "monitored_endpoint_verified",
        actor=request.user,
        target_username=endpoint.ip,
        details=f"Verificacion de conectividad para {endpoint.nombre}: {endpoint.last_message}",
    )
    if result["reachable"]:
        messages.success(request, f"{endpoint.nombre} responde correctamente. {endpoint.last_message}")
    else:
        messages.error(request, f"{endpoint.nombre} no respondio. {endpoint.last_message}")
    return redirect("dashboard_redes")


@two_factor_required
@require_admin_access
@require_POST
def eliminar_endpoint_monitoreado(request, endpoint_id):
    try:
        endpoint = MonitoredEndpoint.objects.get(pk=endpoint_id)
    except MonitoredEndpoint.DoesNotExist:
        messages.error(request, "El objetivo monitorizado no existe.")
        return redirect("dashboard_redes")

    nombre = endpoint.nombre
    ip = str(endpoint.ip)
    endpoint.delete()
    log_security_event(
        request,
        "monitored_endpoint_deleted",
        actor=request.user,
        target_username=ip,
        details=f"Objetivo monitorizado eliminado: {nombre}.",
    )
    messages.success(request, f"Objetivo monitorizado eliminado: {nombre} ({ip}).")
    return redirect("dashboard_redes")

@two_factor_required
@require_asset_management
@require_POST
def agregar_activo(request):
    ip = request.POST.get('ip')
    nombre = request.POST.get('nombre', 'Activo')
    criticidad = request.POST.get('criticidad')
    Activo.objects.update_or_create(
        ip=ip,
        defaults={'nombre': nombre, 'criticidad': criticidad}
    )
    MonitoredEndpoint.objects.filter(ip=ip).update(nombre=nombre)
    # Resetear prioridad de alertas asociadas a este IP para que el motor las vuelva a evaluar con la nueva criticidad
    Alerta.objects.filter(ip_destino=ip).update(prioridad_ia=None)
    
    log_security_event(
        request,
        "asset_upsert",
        actor=request.user,
        target_username=ip,
        details=f"Activo actualizado o creado: nombre={nombre}, criticidad={criticidad}.",
    )
    # REDIRIGIR A LA PAGINA DE ACTIVOS PARA VER EL RESULTADO
    return redirect('dashboard_activos')

@two_factor_required
@require_soc_access
@never_cache
@require_GET
def check_notificaciones(request):
    # CAMBIO: Quitamos el filtro de 80. Ahora cualquier alerta nueva (ID más alto)
    # disparará la recarga de la página.
    ultima_alerta = Alerta.objects.order_by('-id').first()
    
    if ultima_alerta:
        return JsonResponse({
            'id': ultima_alerta.id,
            'firma': ultima_alerta.firma,
            'score': ultima_alerta.prioridad_ia or 0,
            'ip_origen': ultima_alerta.ip_origen,
            'recomendacion': ultima_alerta.recomendacion,
        })
    return JsonResponse({'id': None})


@two_factor_required
@require_soc_access
@never_cache
@require_GET
def check_alerts_redes_filtradas(request):
    """Endpoint para obtener alertas filtradas según criterios de la sección Redes."""
    show_all = request.GET.get('show_all', 'false').lower() == 'true'
    quick_filter_ip = (request.GET.get('quick_filter_ip') or '').strip()
    
    queryset = Alerta.objects.all()
    
    if quick_filter_ip:
        # Filtrar por IP específica (origen o destino)
        queryset = queryset.filter(Q(ip_origen=quick_filter_ip) | Q(ip_destino=quick_filter_ip))
    elif not show_all:
        # Usar IPs monitoreadas configuradas
        env_values = _load_project_env()
        monitored_ips = env_values.get('MONITORED_IPS', '').split(',')
        monitored_ips = [ip.strip() for ip in monitored_ips if ip.strip()]
        
        monitored_networks = env_values.get('MONITORED_NETWORKS', '').split(',')
        monitored_networks = [net.strip() for net in monitored_networks if net.strip()]
        
        query = Q()
        for ip in monitored_ips:
            query |= Q(ip_origen=ip) | Q(ip_destino=ip)
        
        for net in monitored_networks:
            try:
                network = ipaddress.ip_network(net, strict=False)
                query |= Q(ip_origen__regex=r'^\d+\.\d+\.\d+\.\d+$') | Q(ip_destino__regex=r'^\d+\.\d+\.\d+\.\d+$')
            except ValueError:
                pass
        
        queryset = queryset.filter(query) if query else Alerta.objects.none()
    
    # Obtener las 5 alertas más recientes filtradas
    alertas_recientes = queryset.order_by('-id')[:5]
    
    if alertas_recientes:
        ultima_alerta = alertas_recientes[0]
        return JsonResponse({
            'id': ultima_alerta.id,
            'firma': ultima_alerta.firma,
            'score': ultima_alerta.prioridad_ia or 0,
            'ip_origen': ultima_alerta.ip_origen,
            'recomendacion': ultima_alerta.recomendacion,
        })
    return JsonResponse({'id': None})


@login_required
@never_cache
def two_factor_setup(request):
    device, created = TwoFactorDevice.objects.get_or_create(
        user=request.user,
        defaults={"secret": generar_secreto_base32()},
    )

    if not device.secret:
        device.secret = generar_secreto_base32()
        device.confirmed_at = None
        device.save(update_fields=["secret", "confirmed_at", "updated_at"])

    if device.is_confirmed:
        if _needs_two_factor(request):
            return redirect("two_factor_verify")
        return redirect("soc_dashboard")

    if request.method == "POST":
        subject = _two_factor_subject(request)
        lockout = get_lockout("two_factor", subject)
        if lockout and lockout.is_blocked:
            context = _build_2fa_setup_context(
                request,
                device,
                error=get_block_message(lockout, "segundo factor"),
            )
            return render(request, "registration/two_factor_setup.html", context, status=429)

        if request.POST.get("action") == "regenerate":
            device.secret = generar_secreto_base32()
            device.confirmed_at = None
            device.save(update_fields=["secret", "confirmed_at", "updated_at"])
            clear_failures("two_factor", subject)
            log_security_event(
                request,
                "two_factor_regenerated",
                actor=request.user,
                details="Se genero un nuevo secreto QR/TOTP durante la configuracion del segundo factor.",
            )
            context = _build_2fa_setup_context(
                request,
                device,
                error="Se genero un nuevo secreto. Escanea el QR actualizado y usa el nuevo codigo de la app.",
            )
            return render(request, "registration/two_factor_setup.html", context)

        code = request.POST.get("code", "")
        if verificar_totp(device.secret, code):
            device.confirmed_at = timezone.now()
            device.save(update_fields=["confirmed_at", "updated_at"])
            _mark_2fa_complete(request)
            clear_failures("two_factor", subject)
            log_security_event(
                request,
                "two_factor_setup_success",
                actor=request.user,
                details="Segundo factor configurado y verificado correctamente.",
            )
            return redirect(_consume_post_2fa_redirect(request))

        lockout, triggered = register_failure("two_factor", subject)
        log_security_event(
            request,
            "two_factor_setup_failed",
            actor=request.user,
            details="Codigo TOTP invalido durante la configuracion inicial del segundo factor.",
        )
        if triggered:
            log_security_event(
                request,
                "two_factor_lockout",
                actor=request.user,
                details="Se activo un bloqueo temporal por demasiados intentos fallidos de 2FA.",
            )
        context = _build_2fa_setup_context(
            request,
            device,
            error=(
                get_block_message(lockout, "segundo factor")
                if lockout and lockout.is_blocked
                else get_failure_message(lockout, "two_factor", "segundo factor")
            ),
        )
        return render(request, "registration/two_factor_setup.html", context, status=429 if lockout and lockout.is_blocked else 400)

    context = _build_2fa_setup_context(request, device)
    return render(request, "registration/two_factor_setup.html", context)


@login_required
@never_cache
def two_factor_verify(request):
    device = getattr(request.user, "two_factor_device", None)
    if not device or not device.is_confirmed:
        return redirect("two_factor_setup")

    if request.method == "POST":
        subject = _two_factor_subject(request)
        lockout = get_lockout("two_factor", subject)
        if lockout and lockout.is_blocked:
            return render(
                request,
                "registration/two_factor_verify.html",
                {
                    "error": get_block_message(lockout, "segundo factor"),
                    "server_time": timezone.localtime(),
                },
                status=429,
            )

        code = request.POST.get("code", "")
        if verificar_totp(device.secret, code):
            _mark_2fa_complete(request)
            clear_failures("two_factor", subject)
            log_security_event(
                request,
                "two_factor_verify_success",
                actor=request.user,
                details="Segundo factor validado correctamente.",
            )
            return redirect(_consume_post_2fa_redirect(request))

        lockout, triggered = register_failure("two_factor", subject)
        log_security_event(
            request,
            "two_factor_verify_failed",
            actor=request.user,
            details="Codigo TOTP invalido durante la verificacion del segundo factor.",
        )
        if triggered:
            log_security_event(
                request,
                "two_factor_lockout",
                actor=request.user,
                details="Se activo un bloqueo temporal por demasiados intentos fallidos de 2FA.",
            )
        return render(
            request,
            "registration/two_factor_verify.html",
            {
                "error": (
                    get_block_message(lockout, "segundo factor")
                    if lockout and lockout.is_blocked
                    else get_failure_message(lockout, "two_factor", "segundo factor")
                ),
                "server_time": timezone.localtime(),
            },
            status=429 if lockout and lockout.is_blocked else 400,
        )

    return render(request, "registration/two_factor_verify.html", {"server_time": timezone.localtime()})


@login_required
@never_cache
@require_POST
def two_factor_reset(request):
    device, _ = TwoFactorDevice.objects.get_or_create(
        user=request.user,
        defaults={"secret": generar_secreto_base32()},
    )
    device.secret = generar_secreto_base32()
    device.confirmed_at = None
    device.save(update_fields=["secret", "confirmed_at", "updated_at"])
    request.session[SESSION_2FA_PASSED_KEY] = False
    request.session[SESSION_2FA_USER_KEY] = request.user.id
    clear_failures("two_factor", _two_factor_subject(request))
    log_security_event(
        request,
        "two_factor_reset",
        actor=request.user,
        details="Se regenero el secreto del segundo factor.",
    )
    return redirect("two_factor_setup")


@two_factor_required
@require_admin_access
@never_cache
def admin_user_access(request):
    User = get_user_model()

    if request.method == "POST":
        action = request.POST.get("action")

        if action == "create_user":
            username = (request.POST.get("username") or "").strip()
            email = (request.POST.get("email") or "").strip()
            password = request.POST.get("password") or ""
            role_name = request.POST.get("role") or ROLE_VIEWER

            if not username or not password:
                messages.error(request, "Usuario y contrasena son obligatorios para crear una cuenta.")
            elif User.objects.filter(username=username).exists():
                messages.error(request, "Ese nombre de usuario ya existe.")
            elif role_name not in {ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER}:
                messages.error(request, "El rol seleccionado no es valido.")
            else:
                user = User.objects.create_user(username=username, email=email, password=password)
                assign_soc_role(user, role_name)
                log_security_event(
                    request,
                    "user_created",
                    actor=request.user,
                    target_username=user.username,
                    details=f"Usuario creado con rol inicial {get_role_label(user)}.",
                )
                messages.success(request, f"Usuario {username} creado con rol {get_role_label(user)}.")
            return redirect("admin_user_access")

        if action == "update_role":
            user_id = request.POST.get("user_id")
            role_name = request.POST.get("role")

            try:
                managed_user = User.objects.get(pk=user_id)
            except User.DoesNotExist:
                messages.error(request, "El usuario seleccionado no existe.")
                return redirect("admin_user_access")

            if managed_user.pk == request.user.pk and role_name != ROLE_ADMIN:
                messages.error(request, "No puedes quitarte a ti mismo el rol de administrador desde esta pantalla.")
                return redirect("admin_user_access")

            if role_name not in {ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER, "none"}:
                messages.error(request, "Rol no valido.")
                return redirect("admin_user_access")

            if role_name == "none":
                clear_soc_roles(managed_user)
                log_security_event(
                    request,
                    "role_removed",
                    actor=request.user,
                    target_username=managed_user.username,
                    details="Se retiraron todos los roles del Agente del usuario.",
                )
                messages.success(request, f"Se retiraron los roles del Agente de {managed_user.username}.")
            else:
                assign_soc_role(managed_user, role_name)
                log_security_event(
                    request,
                    "role_updated",
                    actor=request.user,
                    target_username=managed_user.username,
                    details=f"Nuevo rol asignado: {get_role_label(managed_user)}.",
                )
                messages.success(request, f"Rol actualizado para {managed_user.username}: {get_role_label(managed_user)}.")

            return redirect("admin_user_access")

        if action == "set_password":
            user_id = request.POST.get("user_id")
            new_password = request.POST.get("new_password") or ""

            try:
                managed_user = User.objects.get(pk=user_id)
            except User.DoesNotExist:
                messages.error(request, "El usuario seleccionado no existe.")
                return redirect("admin_user_access")

            if len(new_password) < 8:
                messages.error(request, "La nueva contrasena debe tener al menos 8 caracteres.")
                return redirect("admin_user_access")

            managed_user.set_password(new_password)
            managed_user.save(update_fields=["password"])
            log_security_event(
                request,
                "password_reset_by_admin",
                actor=request.user,
                target_username=managed_user.username,
                details="Contrasena actualizada desde la consola de administracion de accesos.",
            )
            messages.success(request, f"Contrasena actualizada para {managed_user.username}.")
            return redirect("admin_user_access")

        if action == "unlock_access":
            username = normalize_subject(request.POST.get("username"))
            if not username:
                messages.error(request, "No se recibio un usuario valido para desbloquear.")
                return redirect("admin_user_access")

            unlocked = AuthLockout.objects.filter(subject=username).update(
                failed_attempts=0,
                escalation_level=0,
                admin_unlock_required=False,
                blocked_until=None,
            )
            log_security_event(
                request,
                "account_unlocked_by_admin",
                actor=request.user,
                target_username=username,
                details=f"Se reiniciaron {unlocked} bloqueo(s) asociados al usuario.",
            )
            messages.success(request, f"Acceso desbloqueado para {username}.")
            return redirect("admin_user_access")

    users = User.objects.all().order_by("username")
    lockouts = {}
    for lockout in AuthLockout.objects.filter(scope__in=["login", "two_factor"]):
        if lockout.is_blocked or lockout.failed_attempts > 0:
            lockouts[lockout.subject.lower()] = lockout
            lockouts[lockout.subject] = lockout
    context = {
        "users": users,
        "lockouts": lockouts,
        "role_options": [
            (ROLE_ADMIN, "Administrador"),
            (ROLE_ANALYST, "Analista"),
            (ROLE_VIEWER, "Solo lectura"),
            ("none", "Sin acceso al Agente"),
        ],
        "is_admin_user": True,
    }
    return render(request, "monitoreo/admin_user_access.html", context)


@two_factor_required
@require_admin_access
@never_cache
def security_events_dashboard(request):
    query = (request.GET.get("q") or "").strip()
    event_type = (request.GET.get("event_type") or "").strip()

    events = SecurityEvent.objects.all()
    if query:
        events = events.filter(
            Q(username__icontains=query)
            | Q(target_username__icontains=query)
            | Q(ip_address__icontains=query)
            | Q(details__icontains=query)
            | Q(event_type__icontains=query)
        )
    if event_type:
        events = events.filter(event_type=event_type)

    events = events.select_related("actor")[:250]
    event_types = (
        SecurityEvent.objects.order_by()
        .values_list("event_type", flat=True)
        .distinct()
    )
    summary_events = SecurityEvent.objects.all()
    context = {
        "events": events,
        "event_types": event_types,
        "current_query": query,
        "current_event_type": event_type,
        "total_events": summary_events.count(),
        "failed_logins": summary_events.filter(event_type="login_failed").count(),
        "lockouts": summary_events.filter(event_type__icontains="lockout").count(),
        "sensitive_changes": summary_events.filter(
            event_type__in=[
                "password_changed_self",
                "password_changed_admin",
                "role_updated",
                "user_created",
                "asset_upsert",
            ]
        ).count(),
    }
    return render(request, "monitoreo/security_events.html", context)


def permission_denied_view(request, exception=None):
    return render(request, "403.html", {"role_label": get_role_label(request.user)}, status=403)


@login_required
@two_factor_required
@never_cache
def password_change_view(request):
    if request.method == "POST":
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            invalidated = _invalidate_other_sessions(request.user, request.session.session_key)
            log_security_event(
                request,
                "password_changed_self",
                actor=request.user,
                details=f"El usuario cambio su propia contrasena. Se invalidaron {invalidated} sesiones antiguas.",
            )
            messages.success(request, "Tu contrasena fue actualizada correctamente.")
            return redirect("soc_dashboard")
    else:
        form = PasswordChangeForm(request.user)

    for field in form.fields.values():
        existing = field.widget.attrs.get("class", "")
        field.widget.attrs["class"] = (existing + " form-control").strip()

    return render(request, "registration/password_change.html", {"form": form})


@never_cache
def password_help_view(request):
    return render(request, "registration/password_help.html")


@never_cache
def logout_view(request):
    if request.method == "POST":
        actor = request.user if request.user.is_authenticated else None
        username = actor.username if actor else ""
        log_security_event(
            request,
            "logout",
            actor=actor,
            username=username,
            details="Cierre de sesion solicitado por el usuario.",
        )
        auth_logout(request)
        return redirect("login")
    return render(request, "registration/logout.html")


@two_factor_required
@require_soc_access
@require_POST
def limpiar_alertas(request):
    """Borra todas las alertas de la base de datos"""
    Alerta.objects.all().delete()
    log_security_event(
        request, 
        "alerts_purged", 
        actor=request.user, 
        details="El usuario vació la tabla de alertas para una nueva prueba."
    )
    messages.success(request, "Se han borrado todas las alertas correctamente.")
    return redirect('dashboard_alertas')

@two_factor_required
@require_admin_access  # Solo el administrador puede entrar aquí
@require_POST
def eliminar_activo(request, activo_id):
    try:
        activo = Activo.objects.get(id=activo_id)
        nombre = activo.nombre
        ip = activo.ip
        activo.delete()
        log_security_event(request, "asset_deleted", actor=request.user, details=f"Activo eliminado: {nombre} ({ip})")
        messages.success(request, f"Activo {nombre} eliminado correctamente.")
    except Activo.DoesNotExist:
        messages.error(request, "El activo no existe.")
    return redirect('dashboard_activos')

@two_factor_required
@require_admin_access
@require_POST
def editar_activo(request, activo_id):
    try:
        activo = Activo.objects.get(id=activo_id)
        activo.nombre = request.POST.get('nombre')
        activo.criticidad = request.POST.get('criticidad')
        # La IP no se suele editar para mantener integridad, se borra y crea uno nuevo
        activo.save()
        MonitoredEndpoint.objects.filter(ip=activo.ip).update(nombre=activo.nombre)
        log_security_event(request, "asset_updated", actor=request.user, details=f"Activo actualizado: {activo.nombre} (Crit: {activo.criticidad})")
        messages.success(request, "Activo actualizado correctamente.")
    except Activo.DoesNotExist:
        messages.error(request, "Error al actualizar.")
    return redirect('dashboard_activos')


@two_factor_required
@require_admin_access
@never_cache
def dashboard_suricata_config(request):
    config, created = SuricataConfig.objects.get_or_create(
        defaults={'interfaces': 'eth0', 'is_active': True}
    )
    available_interfaces = _detect_active_network_interfaces()
    configured_interfaces = _normalize_interface_list(config.interfaces or '')
    valid_interfaces = [iface for iface in configured_interfaces if iface in available_interfaces]
    suggested_interfaces = ','.join(valid_interfaces or available_interfaces)

    if request.method == "POST":
        action = request.POST.get('action', 'save')
        
        if action == 'reset':
            config.interfaces = 'eth0'
            config.is_active = True
            config.save()
            log_security_event(
                request,
                "suricata_config_reset",
                actor=request.user,
                details="Configuración Suricata reseteada a valores por defecto",
            )
            messages.success(request, "Configuración reseteada a valores por defecto.")
            return redirect('dashboard_suricata_config')
        
        interfaces = request.POST.get('interfaces', '').strip()
        is_active = request.POST.get('is_active') == 'on'
        
        if not interfaces:
            messages.error(request, "Debes especificar al menos una interfaz de red.")
            return redirect('dashboard_suricata_config')
        
        config.interfaces = interfaces
        config.is_active = is_active
        config.save()
        
        # Aplicar la configuración
        from django.core.management import call_command
        try:
            call_command('apply_suricata_config')
            messages.success(request, "✅ Configuración de Suricata aplicada correctamente. Interfaces: " + interfaces)
        except Exception as e:
            messages.warning(request, f"⚠️ Configuración guardada en BD, pero error aplicando cambios: {str(e)[:100]}")
        
        log_security_event(
            request,
            "suricata_config_updated",
            actor=request.user,
            details=f"Configuración Suricata actualizada: interfaces={interfaces}, active={is_active}",
        )
        return redirect('dashboard_suricata_config')
    
    context = _build_dashboard_context(request, "suricata_config")
    context.update({
        'config': config,
        'available_interfaces': available_interfaces,
        'suggested_interfaces': suggested_interfaces,
        'config_is_default': not valid_interfaces and bool(available_interfaces),
    })
    return render(request, "monitoreo/suricata_config.html", context)
