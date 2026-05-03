import os
from pathlib import Path


def _load_env_file():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    values = {}
    if not env_path.exists():
        return values

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


_ENV_FILE = _load_env_file()


def _get_setting(name, default=""):
    return os.getenv(name) or _ENV_FILE.get(name, default)


DB_CONFIG = {
    "dbname": _get_setting("DB_NAME", ""),
    "user": _get_setting("DB_USER", ""),
    "password": _get_setting("DB_PASSWORD", ""),
    "host": _get_setting("DB_HOST", "localhost"),
    "port": _get_setting("DB_PORT", "5432"),
}

VT_API_KEY = _get_setting("VT_API_KEY", "")
ABUSEIPDB_API_KEY = _get_setting("ABUSEIPDB_API_KEY", "")
GREYNOISE_API_KEY = _get_setting("GREYNOISE_API_KEY", "")
OTX_API_KEY = _get_setting("OTX_API_KEY", "")
