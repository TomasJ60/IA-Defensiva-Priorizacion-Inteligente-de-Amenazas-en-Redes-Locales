#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

function fail() {
  echo "ERROR: $1" >&2
  exit 1
}

function command_exists() {
  command -v "$1" >/dev/null 2>&1
}

function detect_package_manager() {
  if command_exists apt-get; then
    echo "apt"
  elif command_exists dnf; then
    echo "dnf"
  elif command_exists yum; then
    echo "yum"
  else
    echo ""
  fi
}

function install_packages_apt() {
  apt-get update
  apt-get install -y python3 python3-venv python3-pip postgresql postgresql-contrib suricata
}

function install_packages_dnf() {
  dnf install -y python3 python3-venv python3-pip postgresql-server postgresql-contrib suricata
}

function install_packages_yum() {
  yum install -y python3 python3-venv python3-pip postgresql-server postgresql-contrib suricata
}

function ensure_root() {
  if [ "$EUID" -ne 0 ]; then
    fail "Ejecuta este instalador con sudo o como root."
  fi
}

function ensure_linux() {
  if [ "$(uname -s)" != "Linux" ]; then
    fail "Este instalador solo es compatible con Linux."
  fi
}

function install_systemd_service() {
  if ! command_exists systemctl; then
    echo "systemd no está disponible; no se instalará servicio de arranque automático."
    return
  fi

  local run_user="${SUDO_USER:-root}"
  local service_path="/etc/systemd/system/agente-ia-defensiva.service"
  cat > "$service_path" <<EOF
[Unit]
Description=Agente IA Defensiva Django Service
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=$run_user
WorkingDirectory=$PROJECT_DIR
Environment=PATH=$PROJECT_DIR/.venv/bin
Environment=DJANGO_SETTINGS_MODULE=ia_defensiva_soc.settings
ExecStart=$PROJECT_DIR/.venv/bin/python $PROJECT_DIR/web/manage.py runserver 0.0.0.0:8000
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now agente-ia-defensiva >/dev/null 2>&1 || true
  echo "Servicio systemd registrado en: $service_path"
}

ensure_root
ensure_linux

PACKAGE_MANAGER=$(detect_package_manager)
if [ -z "$PACKAGE_MANAGER" ]; then
  fail "No se detectó un gestor de paquetes compatible. Se recomienda usar apt, dnf o yum."
fi

case "$PACKAGE_MANAGER" in
  apt) install_packages_apt ;;
  dnf) install_packages_dnf ;;
  yum) install_packages_yum ;;
  *) fail "Gestor de paquetes no compatible: $PACKAGE_MANAGER" ;;
 esac

if [ ! -f ".env" ]; then
  if [ -f ".env.example" ]; then
    cp .env.example .env
    chmod 640 .env
    echo "Se creó .env a partir de .env.example"
  else
    fail ".env.example no existe. Crea un archivo .env con la configuración de entorno."
  fi
fi

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

parse_env() {
  local key="$1"
  grep -E "^${key}=" .env | tail -n 1 | cut -d'=' -f2- | tr -d '"' | tr -d "'"
}

DB_NAME=$(parse_env DB_NAME)
DB_USER=$(parse_env DB_USER)
DB_PASSWORD=$(parse_env DB_PASSWORD)
DB_HOST=$(parse_env DB_HOST)
DB_PORT=$(parse_env DB_PORT)
ADMIN_USERNAME=$(parse_env ADMIN_USERNAME)
ADMIN_PASSWORD=$(parse_env ADMIN_PASSWORD)
ADMIN_EMAIL=$(parse_env ADMIN_EMAIL)

DB_NAME=${DB_NAME:-agente_ia}
DB_USER=${DB_USER:-postgres}
DB_PASSWORD=${DB_PASSWORD:-admin123}
DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-admin123}
ADMIN_EMAIL=${ADMIN_EMAIL:-admin@example.com}
export ADMIN_USERNAME ADMIN_PASSWORD ADMIN_EMAIL

if command_exists psql; then
  systemctl enable --now postgresql >/dev/null 2>&1 || true
  sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';" >/dev/null 2>&1 || true
  sudo -u postgres psql -c "ALTER USER $DB_USER WITH PASSWORD '$DB_PASSWORD';" >/dev/null 2>&1 || true
  sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" >/dev/null 2>&1 || true
  echo "Base de datos PostgreSQL preparada: $DB_NAME"
else
  echo "Advertencia: psql no está disponible. Si usas PostgreSQL, verifica la instalación manualmente."
fi

if [ -f "web/manage.py" ]; then
  python3 web/manage.py migrate
  python3 web/manage.py shell <<'PY'
import os
from django.contrib.auth import get_user_model

User = get_user_model()
username = os.environ.get('ADMIN_USERNAME', 'admin')
password = os.environ.get('ADMIN_PASSWORD', 'admin123')
email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')

if username and password:
    if not User.objects.filter(username=username).exists():
        User.objects.create_superuser(username=username, email=email, password=password)
        print(f'Usuario administrador creado: {username}')
    else:
        print(f'Usuario administrador ya existe: {username}')
PY
else
  fail "No se encontró web/manage.py. Asegúrate de ejecutar el instalador desde la carpeta del proyecto."
fi

RULES_PATH="/etc/suricata/rules"
sudo mkdir -p "$RULES_PATH"
if [ -f "suricata/local.rules" ]; then
  sudo cp suricata/local.rules "$RULES_PATH/local.rules"
  echo "Reglas locales copiadas a $RULES_PATH/local.rules"
fi

if command_exists suricata-update; then
  sudo suricata-update || echo "Advertencia: suricata-update falló, revisa el estado de Suricata."
fi

SURICATA_CONFIG="/etc/suricata/suricata.yaml"
if [ -f "$SURICATA_CONFIG" ]; then
  sudo python3 - <<'PY'
import pathlib
path = pathlib.Path('/etc/suricata/suricata.yaml')
text = path.read_text()
text = '\n'.join(line if not line.strip().startswith('default-rule-path:') else 'default-rule-path: /etc/suricata/rules' for line in text.splitlines())
if 'rule-files:' not in text:
    text += '\nrule-files:\n  - local.rules\n'
elif 'local.rules' not in text:
    lines = text.splitlines()
    new_lines = []
    inserted = False
    for line in lines:
        new_lines.append(line)
        if line.strip() == 'rule-files:' and not inserted:
            new_lines.append('  - local.rules')
            inserted = True
    text = '\n'.join(new_lines)
path.write_text(text)
PY
  sudo systemctl enable --now suricata >/dev/null 2>&1 || true
  echo "Configuración de Suricata actualizada y servicio habilitado."
else
  echo "No se encontró /etc/suricata/suricata.yaml. Instala Suricata y configura el archivo manualmente."
fi

install_systemd_service

echo "\nInstalación completada."
echo "Si el servicio systemd se instaló, el dashboard se iniciará automáticamente en http://127.0.0.1:8000"
echo "También puedes iniciar manualmente con ./start.sh"
exit 0
