"""
Minimal local dotenv loader to avoid external dependency during local tests.
It implements `load_dotenv(dotenv_path=None)` used by config.py.
This is for local/runtime convenience in this workspace only.
"""
import os
from pathlib import Path

def load_dotenv(dotenv_path=None):
    path = Path(dotenv_path) if dotenv_path else Path(__file__).parent / ".env"
    if not path.exists():
        return False
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
        return True
    except Exception:
        return False
