#!/bin/bash
set -e

echo "╔════════════════════════════════════════════════════════╗"
echo "║     INSTALACIÓN COMPLETA - AGENTE DE IA DEFENSIVA      ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Solicitar contraseña una sola vez
echo "📝 Se necesitarán permisos sudo. Introduce tu contraseña:"
sudo -v

# 1. Actualizar repositorios
echo "📦 [1/5] Actualizando repositorios..."
sudo apt-get update -y > /dev/null 2>&1

# 2. Instalar PostgreSQL
echo "🗄️  [2/5] Instalando PostgreSQL..."
sudo apt-get install -y postgresql postgresql-contrib > /dev/null 2>&1

# 3. Iniciar PostgreSQL
echo "▶️  [3/5] Iniciando PostgreSQL..."
sudo systemctl start postgresql
sudo systemctl enable postgresql

# 4. Crear base de datos y tabla
echo "📊 [4/5] Configurando base de datos..."
sudo -u postgres psql <<EOF
CREATE DATABASE IF NOT EXISTS ia_defensiva;
\c ia_defensiva
CREATE TABLE IF NOT EXISTS alertas (
    id SERIAL PRIMARY KEY,
    timestamp VARCHAR(50),
    ip_origen VARCHAR(50),
    ip_destino VARCHAR(50),
    firma TEXT,
    severidad VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
EOF

# 5. Crear directorio de logs de Suricata
echo "📁 [5/5] Creando directorios necesarios..."
sudo mkdir -p /var/log/suricata
sudo chmod 755 /var/log/suricata
sudo touch /var/log/suricata/eve.json
sudo chmod 666 /var/log/suricata/eve.json

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║              ✅ ¡INSTALACIÓN COMPLETADA!               ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Estado de PostgreSQL:"
sudo systemctl status postgresql --no-pager | head -3
echo ""
echo "✨ El programa está listo para ejecutarse:"
echo "   python lector.py"
echo ""
