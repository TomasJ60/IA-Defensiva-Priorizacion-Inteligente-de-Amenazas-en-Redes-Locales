from django.db.models import Avg
from django.shortcuts import render
from django.utils import timezone
from .models import Alerta


def _build_priority_badge(score):
    if score is None:
        return {"label": "Pendiente", "tone": "neutral"}
    if score >= 90:
        return {"label": "Critica", "tone": "critical"}
    if score >= 75:
        return {"label": "Alta", "tone": "high"}
    if score >= 50:
        return {"label": "Media", "tone": "medium"}
    return {"label": "Baja", "tone": "low"}


def _build_severity_badge(severidad):
    if severidad is None:
        return {"label": "Sin dato", "tone": "neutral"}
    if severidad >= 5:
        return {"label": "Critica", "tone": "critical"}
    if severidad >= 4:
        return {"label": "Alta", "tone": "high"}
    if severidad >= 2:
        return {"label": "Media", "tone": "medium"}
    return {"label": "Baja", "tone": "low"}


def _format_alerta(alerta):
    fecha_local = timezone.localtime(alerta.fecha) if alerta.fecha else None
    prioridad = alerta.prioridad_ia or 0

    return {
        "id": alerta.id,
        "firma": alerta.firma or "Evento sin firma registrada",
        "ip_origen": alerta.ip_origen or "Sin origen",
        "ip_destino": alerta.ip_destino or "Sin destino",
        "severidad": alerta.severidad,
        "reputacion_osint": alerta.reputacion_osint,
        "prioridad_ia": alerta.prioridad_ia,
        "fecha_display": fecha_local.strftime("%d/%m/%Y") if fecha_local else "Sin fecha",
        "hora_display": fecha_local.strftime("%H:%M") if fecha_local else "--:--",
        "priority_badge": _build_priority_badge(alerta.prioridad_ia),
        "severity_badge": _build_severity_badge(alerta.severidad),
        "criticidad_resumen": "Atencion inmediata" if prioridad >= 90 else "Seguimiento recomendado" if prioridad >= 75 else "Monitoreo activo",
    }


def soc_dashboard(request):
    alertas_qs = Alerta.objects.all().order_by("-prioridad_ia", "-fecha")[:100]
    alertas = [_format_alerta(alerta) for alerta in alertas_qs]

    total_alertas = Alerta.objects.count()
    criticas = Alerta.objects.filter(prioridad_ia__gte=90).count()
    altas = Alerta.objects.filter(prioridad_ia__gte=75, prioridad_ia__lt=90).count()
    promedio = Alerta.objects.aggregate(promedio=Avg("prioridad_ia"))["promedio"] or 0
    ultima_alerta = next((alerta for alerta in alertas if alerta["prioridad_ia"] is not None), None)
    top_origenes = [alerta for alerta in alertas if alerta["ip_origen"] != "Sin origen"][:4]

    context = {
        'alertas': alertas,
        'alertas_criticas': criticas,
        'alertas_altas': altas,
        'total_alertas': total_alertas,
        'promedio_prioridad': promedio,
        'ultima_alerta': ultima_alerta,
        'top_origenes': top_origenes,
    }
    return render(request, 'dashboard/index.html', context)
