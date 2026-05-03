#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VENV_ACTIVATE="$PROJECT_DIR/.venv/bin/activate"
LOG_DIR="$PROJECT_DIR/log"

mkdir -p "$LOG_DIR"

if [[ ! -f "$VENV_ACTIVATE" ]]; then
    echo "No se encontro el entorno virtual en: $VENV_ACTIVATE"
    echo "Crea el entorno primero o ejecuta scripts/instalar_laboratorio.sh"
    exit 1
fi

run_in_terminal() {
    local title="$1"
    local command="$2"

    if command -v gnome-terminal >/dev/null 2>&1; then
        gnome-terminal --title="$title" -- bash -lc "$command; echo; echo 'Ventana lista. Puedes seguir revisando aqui.'; exec bash" &
        return
    fi

    if command -v x-terminal-emulator >/dev/null 2>&1; then
        x-terminal-emulator -T "$title" -e bash -lc "$command; echo; echo 'Ventana lista. Puedes seguir revisando aqui.'; exec bash" &
        return
    fi

    if command -v xfce4-terminal >/dev/null 2>&1; then
        xfce4-terminal --title="$title" --hold -e "bash -lc \"$command\"" &
        return
    fi

    if command -v konsole >/dev/null 2>&1; then
        konsole --new-tab -p tabtitle="$title" -e bash -lc "$command; echo; echo 'Ventana lista. Puedes seguir revisando aqui.'; exec bash" &
        return
    fi

    echo "No se encontro un emulador de terminal compatible."
    echo "Instala gnome-terminal o x-terminal-emulator."
    exit 1
}

cleanup() {
    echo
    echo "Deteniendo servicios..."
    pkill -f "python3 src/agente.py" || true
    pkill -f "python3 src/ia_motor.py" || true
    pkill -f "manage.py runserver" || true
    sleep 1
    echo "Servicios detenidos."
}

trap cleanup SIGINT SIGTERM

clear
echo "============================================================"
echo "  INICIANDO SOC IA DEFENSIVA"
echo "============================================================"
echo "Proyecto: $PROJECT_DIR"
echo

AGENTE_CMD="cd \"$PROJECT_DIR\" && source \"$VENV_ACTIVATE\" && python3 src/agente.py 2>> \"$LOG_DIR/agente_error.log\""
MOTOR_CMD="cd \"$PROJECT_DIR\" && source \"$VENV_ACTIVATE\" && python3 src/ia_motor.py 2>> \"$LOG_DIR/motor_error.log\""
WEB_CMD="cd \"$PROJECT_DIR/web\" && source \"$VENV_ACTIVATE\" && python3 manage.py runserver 0.0.0.0:8000 2>> \"$LOG_DIR/web_error.log\""

run_in_terminal "Agente Suricata" "$AGENTE_CMD"
sleep 1
run_in_terminal "Motor IA" "$MOTOR_CMD"
sleep 1
run_in_terminal "Dashboard Django" "$WEB_CMD"

echo "Servicios lanzados en ventanas independientes."
echo "Dashboard: http://127.0.0.1:8000"
echo "Logs de error: $LOG_DIR"
echo
echo "Pulsa ENTER en esta ventana para detener todo."
read -r

cleanup