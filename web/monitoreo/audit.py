from django.db import OperationalError, ProgrammingError

from .models import SecurityEvent


def _get_client_ip(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "") or ""


def log_security_event(request, event_type, actor=None, username="", target_username="", details=""):
    user_agent = request.META.get("HTTP_USER_AGENT", "")[:1000]
    try:
        SecurityEvent.objects.create(
            event_type=event_type,
            actor=actor,
            username=username or (actor.username if actor and getattr(actor, "username", "") else ""),
            target_username=target_username,
            ip_address=_get_client_ip(request),
            user_agent=user_agent,
            details=details,
        )
    except (ProgrammingError, OperationalError):
        # If migrations are pending or the database is temporarily unavailable,
        # auditing should not break authentication or logout flows.
        return
