#!/bin/bash
# Quick Start - Script de arranque rápido

cd "$(dirname "$0")"

echo "🚀 Iniciando Agente IA..."
echo ""

# Activar entorno virtual
source .venv/bin/activate

echo "✓ Entorno virtual activado"
echo ""

# Configurar usuario si es necesario
echo "📝 Configurando usuario de prueba..."
python setup_user.py
echo ""

# Iniciar servidor
echo "🔌 Iniciando servidor Django..."
echo ""
echo "⏳ El servidor estará disponible en:"
echo "   → http://127.0.0.1:8000/login/"
echo ""
echo "📋 Credenciales de prueba:"
echo "   → Usuario: admin"
echo "   → Contraseña: AdminPassword123!"
echo ""
echo "⚠️  Presiona Ctrl+C para detener el servidor"
echo ""

cd web
python manage.py runserver 0.0.0.0:8000
