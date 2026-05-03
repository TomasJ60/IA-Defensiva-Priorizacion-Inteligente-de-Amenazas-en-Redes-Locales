#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

DB_NAME="${DB_NAME:-agente_ia}"
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-admin123}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "Instalando entorno de laboratorio para SOC IA Defensiva"
echo "Proyecto: $PROJECT_DIR"

sudo apt-get update
sudo apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    postgresql \
    postgresql-contrib \
    libpq-dev \
    net-tools

if [[ ! -d ".venv" ]]; then
    "$PYTHON_BIN" -m venv .venv
fi

source .venv/bin/activate
python3 -m pip install --upgrade pip
pip install -r requirements.txt

sudo systemctl enable postgresql
sudo systemctl start postgresql

sudo -u postgres psql <<SQL
DO \$\$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_USER}') THEN
      CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASSWORD}';
   ELSE
      ALTER ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASSWORD}';
   END IF;
END
\$\$;
SQL

sudo -u postgres psql <<SQL
DO \$\$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DB_NAME}') THEN
      CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};
   END IF;
END
\$\$;
SQL

psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -d "$DB_NAME" <<'SQL'
CREATE TABLE IF NOT EXISTS alertas (
    id SERIAL PRIMARY KEY,
    fecha TIMESTAMP NULL,
    ip_origen VARCHAR(50) NULL,
    ip_destino VARCHAR(50) NULL,
    firma TEXT NULL,
    severidad INTEGER NULL,
    reputacion_osint INTEGER NULL,
    prioridad_ia DOUBLE PRECISION NULL,
    explicacion TEXT NULL,
    recomendacion TEXT NULL
);
SQL

psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -d "$DB_NAME" -f scripts/alter_alertas_osint.sql

cd web
../.venv/bin/python3 manage.py migrate
cd ..

mkdir -p /var/log/suricata || true
sudo touch /var/log/suricata/eve.json
sudo chmod 666 /var/log/suricata/eve.json

if [[ ! -f ".env" ]]; then
    cat > .env <<EOF
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}
DB_HOST=${DB_HOST}
DB_PORT=${DB_PORT}
VT_API_KEY=
ABUSEIPDB_API_KEY=
GREYNOISE_API_KEY=
OTX_API_KEY=
EOF
fi

echo ""
echo "Instalacion terminada."
echo "1. Completa las API keys en .env"
echo "2. Activa el entorno: source .venv/bin/activate"
echo "3. Lanza el stack con tus scripts de prueba o con scripts/iniciar_todo.sh"
