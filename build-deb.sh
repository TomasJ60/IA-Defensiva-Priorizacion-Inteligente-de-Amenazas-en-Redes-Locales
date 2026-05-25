#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_DIR/debbuild"
PKG_DIR="$BUILD_DIR/opt/agente-ia"
DEB_DIR="$BUILD_DIR/DEBIAN"
OUTPUT="agente-ia_1.0.0_all.deb"

function fail() {
  echo "ERROR: $1" >&2
  exit 1
}

function command_exists() {
  command -v "$1" >/dev/null 2>&1
}

if ! command_exists dpkg-deb; then
  fail "dpkg-deb no está instalado. Instala dpkg-dev."
fi

rm -rf "$BUILD_DIR"
mkdir -p "$PKG_DIR"
mkdir -p "$BUILD_DIR/etc/systemd/system"
mkdir -p "$DEB_DIR"

rsync -a --exclude='.git' --exclude='.venv' --exclude='debbuild' --exclude='*.deb' --exclude='*.tar.gz' --exclude='__pycache__' --exclude='debian' --exclude='dist' --exclude='*.pyc' --exclude='.env' --exclude='.env.local' --exclude='bootstrap.sh' --exclude='package-release.sh' --exclude='build-deb.sh' ./ "$PKG_DIR/"

cp "$PROJECT_DIR/debian/control" "$DEB_DIR/control"
cp "$PROJECT_DIR/debian/postinst" "$DEB_DIR/postinst"
cp "$PROJECT_DIR/debian/prerm" "$DEB_DIR/prerm"
cp "$PROJECT_DIR/debian/postrm" "$DEB_DIR/postrm"
chmod 755 "$DEB_DIR/postinst" "$DEB_DIR/prerm" "$DEB_DIR/postrm"

cp "$PROJECT_DIR/debian/agente-ia-web.service" "$BUILD_DIR/etc/systemd/system/agente-ia-web.service"
cp "$PROJECT_DIR/debian/agente-ia-agent.service" "$BUILD_DIR/etc/systemd/system/agente-ia-agent.service"
cp "$PROJECT_DIR/debian/agente-ia-ia.service" "$BUILD_DIR/etc/systemd/system/agente-ia-ia.service"

# Remove .env if accidentally copied from project root
rm -f "$PKG_DIR/.env"

fakeroot dpkg-deb --build "$BUILD_DIR" "$PROJECT_DIR/$OUTPUT"

echo "Paquete generado: $PROJECT_DIR/$OUTPUT"
exit 0
