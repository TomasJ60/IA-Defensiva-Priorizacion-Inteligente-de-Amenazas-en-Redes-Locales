from django.shortcuts import render
from .models import Alerta

def soc_dashboard(request):
    # Traemos todas las alertas ordenadas por prioridad de mayor a menor
    # (Por ahora usamos la prioridad vieja que tenías, luego la mejoraremos)
    alertas = Alerta.objects.all().order_by('-prioridad_ia')[:100] # Mostrar las 100 peores
    
    # Contamos cuántas tienen prioridad de 100 para un KPI rápido
    criticas = Alerta.objects.filter(prioridad_ia__gte=100).count()

    context = {
        'alertas': alertas,
        'alertas_criticas': criticas,
    }
    return render(request, 'dashboard/index.html', context)