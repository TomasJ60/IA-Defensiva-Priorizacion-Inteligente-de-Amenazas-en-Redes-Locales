#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$PROJECT_DIR/scripts/iniciar_todo.sh"
