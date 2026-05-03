from django import template

from monitoreo.roles import get_role_label, get_user_role
import ipaddress

register = template.Library()


@register.filter
def role_label(user):
    return get_role_label(user)


@register.filter
def role_key(user):
    return get_user_role(user) or "none"


@register.filter
def get_item(mapping, key):
    if mapping is None:
        return None
    return mapping.get(key)


@register.filter
def mask_ip(value):
    if not value:
        return "Oculta"
    try:
        ip_obj = ipaddress.ip_address(str(value))
    except ValueError:
        return "Oculta"

    if ip_obj.version == 4:
        parts = str(ip_obj).split(".")
        return ".".join(parts[:2] + ["xxx", "xxx"])

    exploded = ip_obj.exploded.split(":")
    return ":".join(exploded[:2] + ["xxxx", "xxxx", "xxxx", "xxxx", "xxxx", "xxxx"])
