#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

OUTPUT="agente-ia-release-$(date +%Y%m%d%H%M%S).tar.gz"

earliest=".git .venv __pycache__ */__pycache__ *.tar.gz"

echo "Creando paquete de lanzamiento: $OUTPUT"

tar --exclude='./.git' \
    --exclude='./.venv' \
    --exclude='./__pycache__' \
    --exclude='*.tar.gz' \
    -czf "$OUTPUT" .

echo "Paquete creado en: $PROJECT_DIR/$OUTPUT"
exit 0
