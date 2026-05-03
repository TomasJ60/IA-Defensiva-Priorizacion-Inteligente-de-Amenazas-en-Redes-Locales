from functools import wraps

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.sessions.models import Session
from django.contrib.auth.views import LoginView
from django.db.models import Avg, Count, Q
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from .audit import log_security_event
from .models import Activo, Alerta, AuthLockout, SecurityEvent, TwoFactorDevice
from .roles import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_VIEWER,
    assign_soc_role,
    clear_soc_roles,
    get_role_label,
    is_admin_user,
    require_admin_access,
    require_asset_management,
    require_soc_access,
    user_can_manage_assets,
    user_can_view_sensitive_data,
)
from .throttling import (
    clear_failures,
    get_block_message,
    get_failure_message,
    get_lockout,
    normalize_subject,
    register_failure,
)
from .totp import construir_otpauth_uri, construir_qr_data_uri, generar_secreto_base32, verificar_totp


SESSION_2FA_USER_KEY = "two_factor_user_id"
SESSION_2FA_PASSED_KEY = "two_factor_passed"
SESSION_POST_2FA_REDIRECT_KEY = "post_2fa_redirect"
TWO_FACTOR_ISSUER = "SOC IA Defensiva"


def _severity_badge(value):
    if value is None:
        return {"label": "Sin clasificar", "tone": "neutral"}
    if value >= 5:
        return {"label": "Critica", "tone": "critical"}
    if value >= 4:
        return {"label": "Alta", "tone": "high"}
    if value >= 3:
        return {"label": "Media", "tone": "medium"}
    return {"label": "Baja", "tone": "low"}


def _priority_badge(value):
    score = value or 0
    if score >= 95:
        return {"label": "Maxima", "tone": "critical"}
    if score >= 85:
        return {"label": "Elevada", "tone": "high"}
    if score >= 70:
        return {"label": "Vigilancia", "tone": "medium"}
    return {"label": "Reducida", "tone": "low"}


def _safe_localtime(value):
    if not value:
        return None
    if isinstance(value, str):
        parsed = parse_datetime(value)
        if parsed is None:
            parsed_date = parse_date(value)
            if parsed_date is not None:
                from datetime import datetime

                parsed = datetime.combine(parsed_date, datetime.min.time())
        value = parsed or value
    try:
        return timezone.localtime(value)
    except Exception:
        return value


def _format_alert_for_dashboard(alerta, can_view_sensitive):
    fecha_local = _safe_localtime(alerta.fecha)
    severity = _severity_badge(alerta.severidad)
    priority = _priority_badge(alerta.prioridad_ia)
    explanation = alerta.explicacion or "Sin explicacion generada todavia."
    recommendation = alerta.recomendacion or "Escalar al analista SOC para revision detallada."

    if not can_view_sensitive:
        explanation = "Detalle restringido para este rol. Revisa con un analista SOC o un administrador."
        recommendation = "Elevar la alerta a un rol con acceso ampliado para aplicar la contencion adecuada."

    if hasattr(fecha_local, "strftime"):
        fecha_display = fecha_local.strftime("%d %b %Y")
        hora_display = fecha_local.strftime("%H:%M:%S")
    elif fecha_local:
        fecha_display = str(fecha_local)
        hora_display = "--:--:--"
    else:
        fecha_display = "Sin fecha"
        hora_display = "--:--:--"

    return {
        "id": alerta.id,
        "fecha": fecha_local,
        "fecha_display": fecha_display,
        "hora_display": hora_display,
        "ip_origen": alerta.ip_origen,
        "ip_destino": alerta.ip_destino,
        "ip_origen_display": alerta.ip_origen if can_view_sensitive else "Protegida",
        "ip_destino_display": alerta.ip_destino if can_view_sensitive else "Protegida",
        "firma": alerta.firma or "Firma no disponible",
        "severidad": alerta.severidad,
        "severity_badge": severity,
        "priority_badge": priority,
        "prioridad_ia": alerta.prioridad_ia or 0,
        "osint_score": alerta.osint_score or 0,
        "reputacion_osint": alerta.reputacion_osint,
        "explicacion_display": explanation,
        "recomendacion_display": recommendation,
        "vt_malicious": alerta.vt_malicious,
        "abuse_confidence": alerta.abuse_confidence,
        "otx_pulse_count": alerta.otx_pulse_count,
    }


def _get_post_2fa_redirect(request):
    redirect_to = request.POST.get("next") or request.GET.get("next") or settings.LOGIN_REDIRECT_URL
    login_url = reverse("login")
    if redirect_to == login_url:
        return settings.LOGIN_REDIRECT_URL
    return redirect_to


def _login_subject(request):
    username = normalize_subject(request.POST.get("username") or request.GET.get("username"))
    if username:
        return username
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "") or "anon"


def _two_factor_subject(request):
    if request.user.is_authenticated:
        return normalize_subject(request.user.username)
    return normalize_subject(request.session.get(SESSION_2FA_USER_KEY, "anon"))


def _mark_2fa_pending(request, user_id, redirect_to):
    request.session[SESSION_2FA_USER_KEY] = user_id
    request.session[SESSION_2FA_PASSED_KEY] = False
    request.session[SESSION_POST_2FA_REDIRECT_KEY] = redirect_to or settings.LOGIN_REDIRECT_URL


def _mark_2fa_complete(request):
    request.session[SESSION_2FA_USER_KEY] = request.user.id
    request.session[SESSION_2FA_PASSED_KEY] = True


def _consume_post_2fa_redirect(request):
    return request.session.pop(SESSION_POST_2FA_REDIRECT_KEY, settings.LOGIN_REDIRECT_URL)


def _invalidate_other_sessions(user, current_session_key):
    active_sessions = Session.objects.filter(expire_date__gte=timezone.now())
    invalidated = 0
    for session in active_sessions:
        data = session.get_decoded()
        if str(data.get("_auth_user_id")) == str(user.pk) and session.session_key != current_session_key:
            session.delete()
            invalidated += 1
    return invalidated


def _build_2fa_setup_context(request, device, error=None):
    otpauth_uri = construir_otpauth_uri(device.secret, request.user.username, issuer=TWO_FACTOR_ISSUER)
    return {
        "secret": device.secret,
        "otpauth_uri": otpauth_uri,
        "qr_data_uri": construir_qr_data_uri(otpauth_uri),
        "issuer": TWO_FACTOR_ISSUER,
        "username": request.user.username,
        "error": error,
        "server_time": timezone.localtime(),
    }


def _needs_two_factor(request):
    if not request.user.is_authenticated:
        return False

    device = getattr(request.user, "two_factor_device", None)
    if not device or not device.is_confirmed:
        return True

    return not (
        request.session.get(SESSION_2FA_PASSED_KEY) is True
        and request.session.get(SESSION_2FA_USER_KEY) == request.user.id
    )


def two_factor_required(view_func):
    @wraps(view_func)
    @login_required
    def _wrapped(request, *args, **kwargs):
        if not _needs_two_factor(request):
            return view_func(request, *args, **kwargs)

        device = getattr(request.user, "two_factor_device", None)
        if not device or not device.is_confirmed:
            return redirect("two_factor_setup")
        return redirect("two_factor_verify")

    return _wrapped


class TwoFactorLoginView(LoginView):
    template_name = "registration/login.html"

    def post(self, request, *args, **kwargs):
        subject = _login_subject(request)
        lockout = get_lockout("login", subject)
        if lockout and lockout.is_blocked:
            form = self.get_form()
            return self.render_to_response(
                self.get_context_data(
                    form=form,
                    auth_error=get_block_message(lockout, "inicio de sesion"),
                ),
                status=429,
            )
        return super().post(request, *args, **kwargs)

    def form_valid(self, form):
        response = super().form_valid(form)
        clear_failures("login", normalize_subject(self.request.user.username))
        log_security_event(
            self.request,
            "login_success",
            actor=self.request.user,
            details="Inicio de sesion correcto. Pendiente verificacion 2FA.",
        )
        _mark_2fa_pending(self.request, self.request.user.id, _get_post_2fa_redirect(self.request))

        device = getattr(self.request.user, "two_factor_device", None)
        if not device or not device.is_confirmed:
            return redirect("two_factor_setup")
        return redirect("two_factor_verify")

    def get_success_url(self):
        return reverse("soc_dashboard")

    def form_invalid(self, form):
        username = (self.request.POST.get("username") or "").strip()
        subject = _login_subject(self.request)
        lockout, triggered = register_failure("login", subject)
        log_security_event(
            self.request,
            "login_failed",
            username=username,
            details="Credenciales invalidas en el formulario de inicio de sesion.",
        )
        if triggered:
            log_security_event(
                self.request,
                "login_lockout",
                username=username or subject,
                details="Se activo un bloqueo temporal por demasiados intentos fallidos de login.",
            )
        message = (
            get_block_message(lockout, "inicio de sesion")
            if lockout and lockout.is_blocked
            else get_failure_message(lockout, "login", "inicio de sesion")
        )
        return self.render_to_response(
            self.get_context_data(form=form, auth_error=message),
            status=429 if lockout and lockout.is_blocked else 400,
        )


@two_factor_required
@require_soc_access
@never_cache
def soc_dashboard(request):
    from datetime import timedelta
    from django.utils.dateparse import parse_datetime
    
    can_manage_assets = user_can_manage_assets(request.user)
    can_view_sensitive = user_can_view_sensitive_data(request.user)

    # Obtener TODAS las alertas críticas (sin filtro de fecha en BD)
    todas_alertas_criticas = Alerta.objects.filter(
        prioridad_ia__gte=80
    ).order_by('-fecha')[:100]
    
    # Filtrar manualmente las de últimas 24h en memoria
    hace_24h = timezone.now() - timedelta(hours=24)
    alertas_criticas_recientes = []
    
    for alerta in todas_alertas_criticas:
        try:
            fecha_str = str(alerta.fecha)
            # Intentar parsear como datetime
            fecha_obj = parse_datetime(fecha_str)
            # Si parse_datetime falla, intentar sin hora
            if not fecha_obj:
                from django.utils.dateparse import parse_date
                fecha_date = parse_date(fecha_str)
                if fecha_date:
                    from datetime import datetime
                    fecha_obj = datetime.combine(fecha_date, datetime.min.time())
            # Comparar
            if fecha_obj and fecha_obj >= hace_24h:
                alertas_criticas_recientes.append(alerta)
        except:
            # Si falla todo, incluir de todas formas
            alertas_criticas_recientes.append(alerta)
    
    alertas_criticas_recientes = alertas_criticas_recientes[:50]
    alert_cards = [
        _format_alert_for_dashboard(alerta, can_view_sensitive)
        for alerta in alertas_criticas_recientes
    ]
    
    # IPs con alertas
    ips_con_alertas = set()
    todas_alertas = Alerta.objects.all()[:1000]  # Limitar para rendimiento
    for alerta in todas_alertas:
        if alerta.ip_origen:
            ips_con_alertas.add(alerta.ip_origen)
        if alerta.ip_destino:
            ips_con_alertas.add(alerta.ip_destino)
    
    # Activos que tienen conexiones reales
    activos_con_alertas = Activo.objects.filter(ip__in=ips_con_alertas).order_by('-criticidad') if ips_con_alertas else Activo.objects.none()
    
    # Totales
    resumen = Alerta.objects.aggregate(
        total_alertas=Count('id'),
        promedio_prioridad=Avg('prioridad_ia'),
    )
    
    osint_status = settings.OSINT_PROVIDER_STATUS
    osint_configured = sum(1 for provider in osint_status if provider["configured"])
    ultima_alerta = alert_cards[0] if alert_cards else None
    criticidad_activos_alta = activos_con_alertas.filter(criticidad__gte=4).count() if ips_con_alertas else 0
    
    context = {
        'alertas_criticas_recientes': alert_cards,
        'activos_con_alertas': activos_con_alertas,
        'total_alertas': resumen['total_alertas'] or 0,
        'promedio_prioridad': resumen['promedio_prioridad'] or 0,
        'role_label': get_role_label(request.user),
        'is_admin_user': is_admin_user(request.user),
        'osint_status': osint_status,
        'osint_configured_count': osint_configured,
        'can_manage_assets': can_manage_assets,
        'can_view_sensitive_data': can_view_sensitive,
        'total_alertas_criticas': len(alert_cards),
        'ultima_alerta_critica': ultima_alerta,
        'criticidad_activos_alta': criticidad_activos_alta,
    }
    return render(request, 'monitoreo/index.html', context)

@two_factor_required
@require_asset_management
@require_POST
def agregar_activo(request):
    ip = request.POST.get('ip')
    nombre = request.POST.get('nombre', 'Activo')
    criticidad = request.POST.get('criticidad')
    Activo.objects.update_or_create(
        ip=ip,
        defaults={'nombre': nombre, 'criticidad': criticidad}
    )
    Alerta.objects.filter(ip_destino=ip).update(prioridad_ia=None)
    log_security_event(
        request,
        "asset_upsert",
        actor=request.user,
        target_username=ip,
        details=f"Activo actualizado o creado: nombre={nombre}, criticidad={criticidad}.",
    )
    return redirect('soc_dashboard')

@two_factor_required
@require_soc_access
@never_cache
@require_GET
def check_notificaciones(request):
    nueva_critica = Alerta.objects.filter(prioridad_ia__gte=80).order_by('-id').first()
    if nueva_critica:
        return JsonResponse({
            'id': nueva_critica.id,
            'firma': nueva_critica.firma,
            'score': nueva_critica.prioridad_ia,
            'ip_origen': nueva_critica.ip_origen,
            'recomendacion': nueva_critica.recomendacion,
        })
    return JsonResponse({'id': None})


@login_required
@never_cache
def two_factor_setup(request):
    device, created = TwoFactorDevice.objects.get_or_create(
        user=request.user,
        defaults={"secret": generar_secreto_base32()},
    )

    if not device.secret:
        device.secret = generar_secreto_base32()
        device.confirmed_at = None
        device.save(update_fields=["secret", "confirmed_at", "updated_at"])

    if device.is_confirmed:
        if _needs_two_factor(request):
            return redirect("two_factor_verify")
        return redirect("soc_dashboard")

    if request.method == "POST":
        subject = _two_factor_subject(request)
        lockout = get_lockout("two_factor", subject)
        if lockout and lockout.is_blocked:
            context = _build_2fa_setup_context(
                request,
                device,
                error=get_block_message(lockout, "segundo factor"),
            )
            return render(request, "registration/two_factor_setup.html", context, status=429)

        if request.POST.get("action") == "regenerate":
            device.secret = generar_secreto_base32()
            device.confirmed_at = None
            device.save(update_fields=["secret", "confirmed_at", "updated_at"])
            clear_failures("two_factor", subject)
            log_security_event(
                request,
                "two_factor_regenerated",
                actor=request.user,
                details="Se genero un nuevo secreto QR/TOTP durante la configuracion del segundo factor.",
            )
            context = _build_2fa_setup_context(
                request,
                device,
                error="Se genero un nuevo secreto. Escanea el QR actualizado y usa el nuevo codigo de la app.",
            )
            return render(request, "registration/two_factor_setup.html", context)

        code = request.POST.get("code", "")
        if verificar_totp(device.secret, code):
            device.confirmed_at = timezone.now()
            device.save(update_fields=["confirmed_at", "updated_at"])
            _mark_2fa_complete(request)
            clear_failures("two_factor", subject)
            log_security_event(
                request,
                "two_factor_setup_success",
                actor=request.user,
                details="Segundo factor configurado y verificado correctamente.",
            )
            return redirect(_consume_post_2fa_redirect(request))

        lockout, triggered = register_failure("two_factor", subject)
        log_security_event(
            request,
            "two_factor_setup_failed",
            actor=request.user,
            details="Codigo TOTP invalido durante la configuracion inicial del segundo factor.",
        )
        if triggered:
            log_security_event(
                request,
                "two_factor_lockout",
                actor=request.user,
                details="Se activo un bloqueo temporal por demasiados intentos fallidos de 2FA.",
            )
        context = _build_2fa_setup_context(
            request,
            device,
            error=(
                get_block_message(lockout, "segundo factor")
                if lockout and lockout.is_blocked
                else get_failure_message(lockout, "two_factor", "segundo factor")
            ),
        )
        return render(request, "registration/two_factor_setup.html", context, status=429 if lockout and lockout.is_blocked else 400)

    context = _build_2fa_setup_context(request, device)
    return render(request, "registration/two_factor_setup.html", context)


@login_required
@never_cache
def two_factor_verify(request):
    device = getattr(request.user, "two_factor_device", None)
    if not device or not device.is_confirmed:
        return redirect("two_factor_setup")

    if request.method == "POST":
        subject = _two_factor_subject(request)
        lockout = get_lockout("two_factor", subject)
        if lockout and lockout.is_blocked:
            return render(
                request,
                "registration/two_factor_verify.html",
                {
                    "error": get_block_message(lockout, "segundo factor"),
                    "server_time": timezone.localtime(),
                },
                status=429,
            )

        code = request.POST.get("code", "")
        if verificar_totp(device.secret, code):
            _mark_2fa_complete(request)
            clear_failures("two_factor", subject)
            log_security_event(
                request,
                "two_factor_verify_success",
                actor=request.user,
                details="Segundo factor validado correctamente.",
            )
            return redirect(_consume_post_2fa_redirect(request))

        lockout, triggered = register_failure("two_factor", subject)
        log_security_event(
            request,
            "two_factor_verify_failed",
            actor=request.user,
            details="Codigo TOTP invalido durante la verificacion del segundo factor.",
        )
        if triggered:
            log_security_event(
                request,
                "two_factor_lockout",
                actor=request.user,
                details="Se activo un bloqueo temporal por demasiados intentos fallidos de 2FA.",
            )
        return render(
            request,
            "registration/two_factor_verify.html",
            {
                "error": (
                    get_block_message(lockout, "segundo factor")
                    if lockout and lockout.is_blocked
                    else get_failure_message(lockout, "two_factor", "segundo factor")
                ),
                "server_time": timezone.localtime(),
            },
            status=429 if lockout and lockout.is_blocked else 400,
        )

    return render(request, "registration/two_factor_verify.html", {"server_time": timezone.localtime()})


@login_required
@never_cache
@require_POST
def two_factor_reset(request):
    device, _ = TwoFactorDevice.objects.get_or_create(
        user=request.user,
        defaults={"secret": generar_secreto_base32()},
    )
    device.secret = generar_secreto_base32()
    device.confirmed_at = None
    device.save(update_fields=["secret", "confirmed_at", "updated_at"])
    request.session[SESSION_2FA_PASSED_KEY] = False
    request.session[SESSION_2FA_USER_KEY] = request.user.id
    clear_failures("two_factor", _two_factor_subject(request))
    log_security_event(
        request,
        "two_factor_reset",
        actor=request.user,
        details="Se regenero el secreto del segundo factor.",
    )
    return redirect("two_factor_setup")


@two_factor_required
@require_admin_access
@never_cache
def admin_user_access(request):
    User = get_user_model()

    if request.method == "POST":
        action = request.POST.get("action")

        if action == "create_user":
            username = (request.POST.get("username") or "").strip()
            email = (request.POST.get("email") or "").strip()
            password = request.POST.get("password") or ""
            role_name = request.POST.get("role") or ROLE_VIEWER

            if not username or not password:
                messages.error(request, "Usuario y contrasena son obligatorios para crear una cuenta.")
            elif User.objects.filter(username=username).exists():
                messages.error(request, "Ese nombre de usuario ya existe.")
            elif role_name not in {ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER}:
                messages.error(request, "El rol seleccionado no es valido.")
            else:
                user = User.objects.create_user(username=username, email=email, password=password)
                assign_soc_role(user, role_name)
                log_security_event(
                    request,
                    "user_created",
                    actor=request.user,
                    target_username=user.username,
                    details=f"Usuario creado con rol inicial {get_role_label(user)}.",
                )
                messages.success(request, f"Usuario {username} creado con rol {get_role_label(user)}.")
            return redirect("admin_user_access")

        if action == "update_role":
            user_id = request.POST.get("user_id")
            role_name = request.POST.get("role")

            try:
                managed_user = User.objects.get(pk=user_id)
            except User.DoesNotExist:
                messages.error(request, "El usuario seleccionado no existe.")
                return redirect("admin_user_access")

            if managed_user.pk == request.user.pk and role_name != ROLE_ADMIN:
                messages.error(request, "No puedes quitarte a ti mismo el rol de administrador desde esta pantalla.")
                return redirect("admin_user_access")

            if role_name not in {ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER, "none"}:
                messages.error(request, "Rol no valido.")
                return redirect("admin_user_access")

            if role_name == "none":
                clear_soc_roles(managed_user)
                log_security_event(
                    request,
                    "role_removed",
                    actor=request.user,
                    target_username=managed_user.username,
                    details="Se retiraron todos los roles SOC del usuario.",
                )
                messages.success(request, f"Se retiraron los roles SOC de {managed_user.username}.")
            else:
                assign_soc_role(managed_user, role_name)
                log_security_event(
                    request,
                    "role_updated",
                    actor=request.user,
                    target_username=managed_user.username,
                    details=f"Nuevo rol asignado: {get_role_label(managed_user)}.",
                )
                messages.success(request, f"Rol actualizado para {managed_user.username}: {get_role_label(managed_user)}.")

            return redirect("admin_user_access")

        if action == "set_password":
            user_id = request.POST.get("user_id")
            new_password = request.POST.get("new_password") or ""

            try:
                managed_user = User.objects.get(pk=user_id)
            except User.DoesNotExist:
                messages.error(request, "El usuario seleccionado no existe.")
                return redirect("admin_user_access")

            if len(new_password) < 8:
                messages.error(request, "La nueva contrasena debe tener al menos 8 caracteres.")
                return redirect("admin_user_access")

            managed_user.set_password(new_password)
            managed_user.save(update_fields=["password"])
            log_security_event(
                request,
                "password_reset_by_admin",
                actor=request.user,
                target_username=managed_user.username,
                details="Contrasena actualizada desde la consola de administracion de accesos.",
            )
            messages.success(request, f"Contrasena actualizada para {managed_user.username}.")
            return redirect("admin_user_access")

        if action == "unlock_access":
            username = normalize_subject(request.POST.get("username"))
            if not username:
                messages.error(request, "No se recibio un usuario valido para desbloquear.")
                return redirect("admin_user_access")

            unlocked = AuthLockout.objects.filter(subject=username).update(
                failed_attempts=0,
                escalation_level=0,
                admin_unlock_required=False,
                blocked_until=None,
            )
            log_security_event(
                request,
                "account_unlocked_by_admin",
                actor=request.user,
                target_username=username,
                details=f"Se reiniciaron {unlocked} bloqueo(s) asociados al usuario.",
            )
            messages.success(request, f"Acceso desbloqueado para {username}.")
            return redirect("admin_user_access")

    users = User.objects.all().order_by("username")
    lockouts = {}
    for lockout in AuthLockout.objects.filter(scope__in=["login", "two_factor"]):
        if lockout.is_blocked or lockout.failed_attempts > 0:
            lockouts[lockout.subject.lower()] = lockout
            lockouts[lockout.subject] = lockout
    context = {
        "users": users,
        "lockouts": lockouts,
        "role_options": [
            (ROLE_ADMIN, "Administrador"),
            (ROLE_ANALYST, "Analista SOC"),
            (ROLE_VIEWER, "Solo lectura"),
            ("none", "Sin acceso SOC"),
        ],
        "is_admin_user": True,
    }
    return render(request, "monitoreo/admin_user_access.html", context)


@two_factor_required
@require_admin_access
@never_cache
def security_events_dashboard(request):
    query = (request.GET.get("q") or "").strip()
    event_type = (request.GET.get("event_type") or "").strip()

    events = SecurityEvent.objects.all()
    if query:
        events = events.filter(
            Q(username__icontains=query)
            | Q(target_username__icontains=query)
            | Q(ip_address__icontains=query)
            | Q(details__icontains=query)
            | Q(event_type__icontains=query)
        )
    if event_type:
        events = events.filter(event_type=event_type)

    events = events.select_related("actor")[:250]
    event_types = (
        SecurityEvent.objects.order_by()
        .values_list("event_type", flat=True)
        .distinct()
    )
    summary_events = SecurityEvent.objects.all()
    context = {
        "events": events,
        "event_types": event_types,
        "current_query": query,
        "current_event_type": event_type,
        "total_events": summary_events.count(),
        "failed_logins": summary_events.filter(event_type="login_failed").count(),
        "lockouts": summary_events.filter(event_type__icontains="lockout").count(),
        "sensitive_changes": summary_events.filter(
            event_type__in=[
                "password_changed_self",
                "password_changed_admin",
                "role_updated",
                "user_created",
                "asset_upsert",
            ]
        ).count(),
    }
    return render(request, "monitoreo/security_events.html", context)


def permission_denied_view(request, exception=None):
    return render(request, "403.html", {"role_label": get_role_label(request.user)}, status=403)


@login_required
@two_factor_required
@never_cache
def password_change_view(request):
    if request.method == "POST":
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            invalidated = _invalidate_other_sessions(request.user, request.session.session_key)
            log_security_event(
                request,
                "password_changed_self",
                actor=request.user,
                details=f"El usuario cambio su propia contrasena. Se invalidaron {invalidated} sesiones antiguas.",
            )
            messages.success(request, "Tu contrasena fue actualizada correctamente.")
            return redirect("soc_dashboard")
    else:
        form = PasswordChangeForm(request.user)

    for field in form.fields.values():
        existing = field.widget.attrs.get("class", "")
        field.widget.attrs["class"] = (existing + " form-control").strip()

    return render(request, "registration/password_change.html", {"form": form})


@never_cache
def password_help_view(request):
    return render(request, "registration/password_help.html")


@never_cache
def logout_view(request):
    if request.method == "POST":
        actor = request.user if request.user.is_authenticated else None
        username = actor.username if actor else ""
        log_security_event(
            request,
            "logout",
            actor=actor,
            username=username,
            details="Cierre de sesion solicitado por el usuario.",
        )
        auth_logout(request)
        return redirect("login")
    return render(request, "registration/logout.html")
