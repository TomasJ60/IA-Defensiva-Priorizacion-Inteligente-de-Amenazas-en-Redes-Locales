#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="agente-ia"
WORK_DIR="$(mktemp -d)"
DEST_DIR="$HOME/$PROJECT_NAME"
ARCHIVE=""
DOWNLOAD_URL=""

function fail() {
  echo "ERROR: $1" >&2
  rm -rf "$WORK_DIR" || true
  exit 1
}

function usage() {
  cat <<EOF
Uso: $0 [--archive <archivo.tar.gz>] [--url <url>] [--dest <directorio>]

Opciones:
  --archive PATH   Usa un archivo tar.gz local con el proyecto.
  --url URL        Descarga el proyecto desde una URL pública.
  --dest DIR       Directorio destino donde se instalará el proyecto. Por defecto: $HOME/$PROJECT_NAME
  --help           Muestra esta ayuda.

Ejemplos:
  sudo ./bootstrap.sh --archive agente-ia-release.tar.gz
  sudo ./bootstrap.sh --url https://example.com/agente-ia-release.tar.gz --dest /opt/agente-ia
EOF
}

function command_exists() {
  command -v "$1" >/dev/null 2>&1
}

function download_archive() {
  local url="$1"
  local output="$WORK_DIR/project.tar.gz"

  if command_exists curl; then
    curl -L --fail -o "$output" "$url"
  elif command_exists wget; then
    wget -O "$output" "$url"
  else
    fail "Necesitas curl o wget para descargar el proyecto desde URL."
  fi

  ARCHIVE="$output"
}

function extract_archive() {
  local archive="$1"
  mkdir -p "$DEST_DIR"
  tar -xzf "$archive" -C "$DEST_DIR"

  local topdir
  topdir="$(tar -tzf "$archive" | head -n 1 | cut -f1 -d/ | tr -d '\n')"
  if [ -f "$DEST_DIR/$topdir/install.sh" ]; then
    echo "$DEST_DIR/$topdir"
  elif [ -f "$DEST_DIR/install.sh" ]; then
    echo "$DEST_DIR"
  else
    fail "No se encontró install.sh dentro del paquete." 
  fi
}

function ensure_linux() {
  if [ "$(uname -s)" != "Linux" ]; then
    fail "Este bootstrap solo funciona en Linux."
  fi
}

function ensure_root() {
  if [ "$EUID" -ne 0 ]; then
    fail "Ejecuta este script con sudo o como root."
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive)
      ARCHIVE="$2"
      shift 2
      ;;
    --url)
      DOWNLOAD_URL="$2"
      shift 2
      ;;
    --dest)
      DEST_DIR="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "Opción desconocida: $1"
      ;;
  esac
done

ensure_linux
ensure_root

if [ -n "$DOWNLOAD_URL" ]; then
  download_archive "$DOWNLOAD_URL"
fi

if [ -n "$ARCHIVE" ]; then
  if [ ! -f "$ARCHIVE" ]; then
    fail "Archivo de paquete no encontrado: $ARCHIVE"
  fi
  PROJECT_DIR="$(extract_archive "$ARCHIVE")"
  echo "Proyecto extraído en: $PROJECT_DIR"
else
  if [ -f "./install.sh" ]; then
    PROJECT_DIR="$(pwd)"
    echo "Usando el proyecto local en $PROJECT_DIR"
  else
    fail "No se encontró proyecto local ni archivo paquete. Usa --archive o --url."
  fi
fi

cd "$PROJECT_DIR"
chmod +x install.sh

if [ ! -f "install.sh" ]; then
  fail "install.sh no se encontró en el directorio del proyecto: $PROJECT_DIR"
fi

if [ ! -f "web/manage.py" ]; then
  fail "No se encontró web/manage.py en $PROJECT_DIR. Comprueba el contenido del proyecto." 
fi

./install.sh

rm -rf "$WORK_DIR"

echo "\nBootstrap completo. Si el servicio systemd se instaló correctamente, el dashboard estará disponible en http://127.0.0.1:8000"
if command_exists systemctl && systemctl is-active --quiet agente-ia; then
  echo "Servicio 'agente-ia' activo. Usa: sudo systemctl status agente-ia"
fi
exit 0
