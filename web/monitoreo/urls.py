from django.urls import path
from . import views

urlpatterns = [
    path('', views.soc_dashboard, name='soc_dashboard'),
    path('overview/', views.soc_dashboard, name='dashboard_overview'),
    path('alertas/', views.dashboard_alertas, name='dashboard_alertas'),
    path('activos/', views.dashboard_activos, name='dashboard_activos'),
    path('osint/', views.dashboard_osint, name='dashboard_osint'),
    path('redes/', views.dashboard_redes, name='dashboard_redes'),
    path('admin/accesos/', views.admin_user_access, name='admin_user_access'),
    path('admin/security-events/', views.security_events_dashboard, name='security_events_dashboard'),
    path('agregar_activo/', views.agregar_activo, name='agregar_activo'),
    path('redes/agregar/', views.agregar_endpoint_monitoreado, name='agregar_endpoint_monitoreado'),
    path('redes/toggle/<int:endpoint_id>/', views.toggle_endpoint_monitoreado, name='toggle_endpoint_monitoreado'),
    path('redes/verificar/<int:endpoint_id>/', views.verificar_endpoint_monitoreado, name='verificar_endpoint_monitoreado'),
    path('redes/eliminar/<int:endpoint_id>/', views.eliminar_endpoint_monitoreado, name='eliminar_endpoint_monitoreado'),
    path('check-alerts/', views.check_notificaciones, name='check_alerts'), # NUEVA RUTA
    path('2fa/setup/', views.two_factor_setup, name='two_factor_setup'),
    path('2fa/verify/', views.two_factor_verify, name='two_factor_verify'),
    path('2fa/reset/', views.two_factor_reset, name='two_factor_reset'),
    path('alertas/limpiar/', views.limpiar_alertas, name='limpiar_alertas'),
    path('activos/eliminar/<int:activo_id>/', views.eliminar_activo, name='eliminar_activo'),
    path('activos/editar/<int:activo_id>/', views.editar_activo, name='editar_activo'),
    path('suricata/config/', views.dashboard_suricata_config, name='dashboard_suricata_config'),
]
