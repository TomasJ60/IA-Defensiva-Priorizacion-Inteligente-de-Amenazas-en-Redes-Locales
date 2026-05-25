#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if [ ! -d ".venv" ]; then
  echo "No se encontró el entorno virtual. Ejecuta primero ./install.sh"
  exit 1
fi

source .venv/bin/activate

echo "Iniciando servidor Django en http://0.0.0.0:8000"
python web/manage.py runserver 0.0.0.0:8000

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open http://127.0.0.1:8000 || true
fi
