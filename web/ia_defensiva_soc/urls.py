from django.contrib import admin
from django.urls import path, include

from monitoreo.views import (
    TwoFactorLoginView,
    admin_user_access,
    logout_view,
    password_change_view,
    password_help_view,
    security_events_dashboard,
    permission_denied_view,
)

urlpatterns = [
    path('admin/accesos/', admin_user_access, name='admin_user_access'),
    path('admin/security-events/', security_events_dashboard, name='security_events_dashboard'),
    path('admin/', admin.site.urls),
    path('login/', TwoFactorLoginView.as_view(), name='login'),
    path('logout/', logout_view, name='logout'),
    path('password/change/', password_change_view, name='password_change'),
    path('password/help/', password_help_view, name='password_help'),
    path('', include('monitoreo.urls')),
]

handler403 = permission_denied_view
