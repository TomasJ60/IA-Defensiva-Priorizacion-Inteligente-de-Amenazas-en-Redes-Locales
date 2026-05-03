from datetime import timedelta

from django.utils import timezone

from .models import AuthLockout


LOCKOUT_POLICY = {
    "login": {"max_attempts": 3, "durations": [1, 3]},
    "two_factor": {"max_attempts": 3, "durations": [1, 3]},
}


def _policy(scope):
    return LOCKOUT_POLICY.get(scope, {"max_attempts": 3, "durations": [1, 3]})


def normalize_subject(value):
    return (value or "").strip().lower()


def get_lockout(scope, subject):
    subject = normalize_subject(subject)
    if not subject:
        return None
    lockout, _ = AuthLockout.objects.get_or_create(scope=scope, subject=subject)
    return lockout


def get_remaining_attempts(lockout, scope):
    policy = _policy(scope)
    used = lockout.failed_attempts if lockout else 0
    return max(policy["max_attempts"] - used, 0)


def get_block_message(lockout, scope_label):
    if not lockout:
        return ""
    if lockout.admin_unlock_required:
        return (
            f"La cuenta quedo bloqueada para {scope_label} por multiples intentos fallidos. "
            "Solo un administrador puede verificar la identidad y desbloquearla."
        )
    if lockout.blocked_until:
        until = timezone.localtime(lockout.blocked_until).strftime("%Y-%m-%d %H:%M:%S")
        return f"Demasiados intentos fallidos en {scope_label}. El acceso fue bloqueado temporalmente hasta {until}."
    return ""


def get_failure_message(lockout, scope, scope_label):
    remaining = get_remaining_attempts(lockout, scope)
    if remaining <= 0:
        return get_block_message(lockout, scope_label)
    intento_label = "intento" if remaining == 1 else "intentos"
    return f"Se ha ingresado el usuario, contrasena o codigo incorrecto. Te quedan {remaining} de 3 {intento_label} antes del bloqueo."


def register_failure(scope, subject):
    lockout = get_lockout(scope, subject)
    if not lockout:
        return None, False

    policy = _policy(scope)
    now = timezone.now()

    if lockout.admin_unlock_required:
        return lockout, False

    if lockout.blocked_until and lockout.blocked_until <= now:
        lockout.failed_attempts = 0
        lockout.blocked_until = None

    lockout.failed_attempts += 1
    triggered = False

    if lockout.failed_attempts >= policy["max_attempts"]:
        durations = policy["durations"]
        if lockout.escalation_level < len(durations):
            minutes = durations[lockout.escalation_level]
            lockout.blocked_until = now + timedelta(minutes=minutes)
            lockout.escalation_level += 1
            lockout.failed_attempts = 0
            triggered = True
        else:
            lockout.admin_unlock_required = True
            lockout.blocked_until = None
            lockout.failed_attempts = 0
            triggered = True

    lockout.save(
        update_fields=[
            "failed_attempts",
            "escalation_level",
            "admin_unlock_required",
            "blocked_until",
            "last_attempt_at",
        ]
    )
    return lockout, triggered


def clear_failures(scope, subject):
    lockout = get_lockout(scope, subject)
    if not lockout:
        return
    if (
        lockout.failed_attempts
        or lockout.blocked_until
        or lockout.admin_unlock_required
        or lockout.escalation_level
    ):
        lockout.failed_attempts = 0
        lockout.escalation_level = 0
        lockout.admin_unlock_required = False
        lockout.blocked_until = None
        lockout.save(
            update_fields=[
                "failed_attempts",
                "escalation_level",
                "admin_unlock_required",
                "blocked_until",
                "last_attempt_at",
            ]
        )
