import base64
import hashlib
import hmac
import io
import secrets
import struct
import time
from urllib.parse import quote

import qrcode
from qrcode.image.svg import SvgImage


def generar_secreto_base32(length=32):
    random_bytes = secrets.token_bytes(length)
    return base64.b32encode(random_bytes).decode("ascii").rstrip("=")


def _normalizar_secreto(secret):
    clean = (secret or "").strip().replace(" ", "").upper()
    padding = "=" * ((8 - len(clean) % 8) % 8)
    return clean + padding


def generar_totp(secret, timestamp=None, step=30, digits=6):
    if timestamp is None:
        timestamp = time.time()

    counter = int(timestamp // step)
    key = base64.b32decode(_normalizar_secreto(secret), casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    token = code % (10 ** digits)
    return str(token).zfill(digits)


def verificar_totp(secret, token, window=6, step=30, digits=6):
    normalized = "".join(ch for ch in str(token or "") if ch.isdigit())
    if len(normalized) != digits:
        return False

    now = time.time()
    for offset in range(-window, window + 1):
        candidate = generar_totp(secret, timestamp=now + (offset * step), step=step, digits=digits)
        if hmac.compare_digest(candidate, normalized):
            return True
    return False


def construir_otpauth_uri(secret, username, issuer="Agente IA"):
    label = quote(f"{issuer}:{username}")
    issuer_param = quote(issuer)
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer_param}"


def construir_qr_data_uri(payload):
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    image = qr.make_image(image_factory=SvgImage)
    buffer = io.BytesIO()
    image.save(buffer)
    svg_base64 = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{svg_base64}"
