from django.urls import path
from . import views

urlpatterns = [
    path('', views.soc_dashboard, name='soc_dashboard'),
    path('admin/accesos/', views.admin_user_access, name='admin_user_access'),
    path('admin/security-events/', views.security_events_dashboard, name='security_events_dashboard'),
    path('agregar_activo/', views.agregar_activo, name='agregar_activo'),
    path('check-alerts/', views.check_notificaciones, name='check_alerts'), # NUEVA RUTA
    path('2fa/setup/', views.two_factor_setup, name='two_factor_setup'),
    path('2fa/verify/', views.two_factor_verify, name='two_factor_verify'),
    path('2fa/reset/', views.two_factor_reset, name='two_factor_reset'),
]
