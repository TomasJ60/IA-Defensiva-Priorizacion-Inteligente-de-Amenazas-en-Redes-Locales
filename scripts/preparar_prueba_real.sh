#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

DB_NAME="${DB_NAME:-agente_ia}"
DB_USER="${DB_USER:-postgres}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"

echo "Preparando entorno de prueba real..."
echo "Proyecto: $PROJECT_DIR"
echo "Base de datos: $DB_NAME"
echo ""
echo "Este script eliminara todas las alertas actuales y resembrara dos activos criticos."
read -r -p "Escribe LIMPIAR para continuar: " CONFIRM

if [[ "$CONFIRM" != "LIMPIAR" ]]; then
    echo "Operacion cancelada."
    exit 1
fi

psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -d "$DB_NAME" <<'SQL'
BEGIN;
TRUNCATE TABLE alertas RESTART IDENTITY;
TRUNCATE TABLE monitoreo_activo RESTART IDENTITY CASCADE;

INSERT INTO monitoreo_activo (ip, nombre, criticidad)
VALUES
    ('192.168.1.50', 'Servidor ERP', 5),
    ('192.168.1.93', 'Servidor Web Critico', 4);
COMMIT;
SQL

echo ""
echo "Estado limpio y activos cargados."
psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -d "$DB_NAME" -c "SELECT id, ip, nombre, criticidad FROM monitoreo_activo ORDER BY criticidad DESC, id ASC;"
