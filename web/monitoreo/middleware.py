from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout as auth_logout
from django.shortcuts import redirect
from django.urls import resolve, reverse
from django.utils import timezone

from .audit import log_security_event


SESSION_LOGIN_TS_KEY = "session_login_ts"
SESSION_LAST_ACTIVITY_TS_KEY = "session_last_activity_ts"


class StrictSessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            current_url_name = None
            try:
                current_url_name = resolve(request.path_info).url_name
            except Exception:
                current_url_name = None

            exempt_names = {"login", "logout", "password_help"}
            if current_url_name not in exempt_names:
                now_ts = int(timezone.now().timestamp())
                login_ts = request.session.get(SESSION_LOGIN_TS_KEY)
                last_activity_ts = request.session.get(SESSION_LAST_ACTIVITY_TS_KEY)

                if login_ts is None:
                    request.session[SESSION_LOGIN_TS_KEY] = now_ts
                    login_ts = now_ts
                if last_activity_ts is None:
                    request.session[SESSION_LAST_ACTIVITY_TS_KEY] = now_ts
                    last_activity_ts = now_ts

                inactivity_timeout = getattr(settings, "SESSION_INACTIVITY_TIMEOUT_SECONDS", 900)
                absolute_timeout = getattr(settings, "SESSION_ABSOLUTE_TIMEOUT_SECONDS", 28800)
                expired_reason = None

                if inactivity_timeout and (now_ts - int(last_activity_ts)) > inactivity_timeout:
                    expired_reason = "La sesion expiro por inactividad. Vuelve a iniciar sesion."
                    log_security_event(
                        request,
                        "session_expired_inactivity",
                        actor=request.user,
                        details="Cierre de sesion automatico por inactividad.",
                    )
                elif absolute_timeout and (now_ts - int(login_ts)) > absolute_timeout:
                    expired_reason = "La sesion alcanzo el tiempo maximo permitido. Vuelve a iniciar sesion."
                    log_security_event(
                        request,
                        "session_expired_absolute",
                        actor=request.user,
                        details="Cierre de sesion automatico por tiempo maximo de sesion.",
                    )

                if expired_reason:
                    auth_logout(request)
                    messages.warning(request, expired_reason)
                    return redirect(reverse("login"))

                request.session[SESSION_LAST_ACTIVITY_TS_KEY] = now_ts

        return self.get_response(request)
