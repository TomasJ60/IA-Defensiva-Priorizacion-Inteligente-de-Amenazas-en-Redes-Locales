from django.conf import settings
from django.db import models
from django.utils import timezone

class Alerta(models.Model):
    fecha = models.DateTimeField(null=True, blank=True)
    ip_origen = models.CharField(max_length=50, null=True, blank=True)
    ip_destino = models.CharField(max_length=50, null=True, blank=True)
    firma = models.TextField(null=True, blank=True)
    severidad = models.IntegerField(null=True, blank=True)
    reputacion_osint = models.IntegerField(null=True, blank=True)
    vt_malicious = models.IntegerField(null=True, blank=True)
    vt_suspicious = models.IntegerField(null=True, blank=True)
    vt_reputation = models.IntegerField(null=True, blank=True)
    abuse_confidence = models.IntegerField(null=True, blank=True)
    abuse_reports = models.IntegerField(null=True, blank=True)
    gn_noise = models.BooleanField(null=True, blank=True)
    gn_riot = models.BooleanField(null=True, blank=True)
    gn_classification = models.CharField(max_length=50, null=True, blank=True)
    otx_pulse_count = models.IntegerField(null=True, blank=True)
    otx_tags = models.TextField(null=True, blank=True)
    otx_malware_families = models.TextField(null=True, blank=True)
    osint_score = models.FloatField(null=True, blank=True)
    prioridad_ia = models.FloatField(null=True, blank=True)
    explicacion = models.TextField(null=True, blank=True)
    recomendacion = models.TextField(null=True, blank=True)

    class Meta:
        managed = False
        db_table = 'alertas'

class Activo(models.Model):
    ip = models.GenericIPAddressField(unique=True)
    nombre = models.CharField(max_length=100)
    criticidad = models.IntegerField(default=1) # 1 a 5

    def __str__(self):
        return f"{self.nombre} ({self.ip})"


class TwoFactorDevice(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='two_factor_device')
    secret = models.CharField(max_length=64)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def is_confirmed(self):
        return self.confirmed_at is not None

    def mark_confirmed(self):
        self.confirmed_at = timezone.now()
        self.save(update_fields=["confirmed_at", "updated_at"])

    def __str__(self):
        estado = "activo" if self.is_confirmed else "pendiente"
        return f"2FA {estado} - {self.user}"


class SecurityEvent(models.Model):
    event_type = models.CharField(max_length=80)
    username = models.CharField(max_length=150, blank=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="security_events",
    )
    target_username = models.CharField(max_length=150, blank=True)
    ip_address = models.CharField(max_length=64, blank=True)
    user_agent = models.TextField(blank=True)
    details = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.event_type} - {self.username or self.target_username or 'anonimo'}"


class AuthLockout(models.Model):
    scope = models.CharField(max_length=32)
    subject = models.CharField(max_length=150)
    failed_attempts = models.PositiveIntegerField(default=0)
    escalation_level = models.PositiveIntegerField(default=0)
    admin_unlock_required = models.BooleanField(default=False)
    blocked_until = models.DateTimeField(null=True, blank=True)
    last_attempt_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("scope", "subject")

    @property
    def is_blocked(self):
        return self.admin_unlock_required or bool(self.blocked_until and self.blocked_until > timezone.now())

    def __str__(self):
        return f"{self.scope}:{self.subject} ({self.failed_attempts})"
