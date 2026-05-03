from django.contrib import admin

from .models import Activo, AuthLockout, SecurityEvent, TwoFactorDevice


@admin.register(Activo)
class ActivoAdmin(admin.ModelAdmin):
    list_display = ("nombre", "ip", "criticidad")
    search_fields = ("nombre", "ip")
    ordering = ("-criticidad", "nombre")


@admin.register(TwoFactorDevice)
class TwoFactorDeviceAdmin(admin.ModelAdmin):
    list_display = ("user", "confirmed_at", "created_at", "updated_at")
    search_fields = ("user__username", "user__email")
    readonly_fields = ("created_at", "updated_at", "confirmed_at")


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ("created_at", "event_type", "username", "target_username", "ip_address")
    search_fields = ("event_type", "username", "target_username", "ip_address", "details")
    list_filter = ("event_type", "created_at")
    readonly_fields = (
        "event_type",
        "username",
        "actor",
        "target_username",
        "ip_address",
        "user_agent",
        "details",
        "created_at",
    )


@admin.register(AuthLockout)
class AuthLockoutAdmin(admin.ModelAdmin):
    list_display = ("scope", "subject", "failed_attempts", "blocked_until", "last_attempt_at")
    list_filter = ("scope",)
    search_fields = ("subject",)
