from functools import wraps

from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied


ROLE_ADMIN = "admin"
ROLE_ANALYST = "soc_analyst"
ROLE_VIEWER = "soc_viewer"
SOC_ACCESS_GROUPS = {ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER}
ASSET_MANAGEMENT_GROUPS = {ROLE_ADMIN, ROLE_ANALYST}
ROLE_ALIASES = {
    ROLE_ADMIN: ROLE_ADMIN,
    ROLE_ANALYST: ROLE_ANALYST,
    ROLE_VIEWER: ROLE_VIEWER,
    "Administrador": ROLE_ADMIN,
    "Analista": ROLE_ANALYST,
    "Analista SOC": ROLE_ANALYST,
    "Solo lectura": ROLE_VIEWER,
}


def _group_names(user):
    if not user.is_authenticated:
        return set()
    return set(user.groups.values_list("name", flat=True))


def get_user_role(user):
    if not user.is_authenticated:
        return None
    if user.is_superuser or user.is_staff:
        return ROLE_ADMIN

    groups = _group_names(user)
    for group_name in groups:
        canonical = ROLE_ALIASES.get(group_name)
        if canonical:
            return canonical
    return None


def get_role_label(user):
    role = get_user_role(user)
    labels = {
        ROLE_ADMIN: "Administrador",
        ROLE_ANALYST: "Analista",
        ROLE_VIEWER: "Solo lectura",
        None: "Sin rol",
    }
    return labels.get(role, "Sin rol")


def is_admin_user(user):
    return get_user_role(user) == ROLE_ADMIN


def user_has_soc_access(user):
    if not user.is_authenticated:
        return False
    if user.is_superuser or user.is_staff:
        return True
    return any(ROLE_ALIASES.get(group_name) in SOC_ACCESS_GROUPS for group_name in _group_names(user))


def user_can_manage_assets(user):
    if not user.is_authenticated:
        return False
    if user.is_superuser or user.is_staff:
        return True
    return any(ROLE_ALIASES.get(group_name) in ASSET_MANAGEMENT_GROUPS for group_name in _group_names(user))


def user_can_view_sensitive_data(user):
    role = get_user_role(user)
    return role in {ROLE_ADMIN, ROLE_ANALYST}


def assign_soc_role(user, role_name):
    role_name = ROLE_ALIASES.get(role_name, role_name)
    if role_name not in SOC_ACCESS_GROUPS:
        raise ValueError("Rol del Agente no valido.")

    groups_to_remove = list(Group.objects.filter(name__in=ROLE_ALIASES.keys()))
    if groups_to_remove:
        user.groups.remove(*groups_to_remove)
    group, _ = Group.objects.get_or_create(name=role_name)
    user.groups.add(group)


def clear_soc_roles(user):
    groups_to_remove = list(Group.objects.filter(name__in=ROLE_ALIASES.keys()))
    if groups_to_remove:
        user.groups.remove(*groups_to_remove)


def require_soc_access(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not user_has_soc_access(request.user):
            raise PermissionDenied("Tu usuario no tiene acceso a la consola del Agente.")
        return view_func(request, *args, **kwargs)

    return _wrapped


def require_asset_management(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not user_can_manage_assets(request.user):
            raise PermissionDenied("Tu rol no puede modificar activos.")
        return view_func(request, *args, **kwargs)

    return _wrapped


def require_admin_access(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not is_admin_user(request.user):
            raise PermissionDenied("Solo un administrador puede gestionar usuarios y roles.")
        return view_func(request, *args, **kwargs)

    return _wrapped
