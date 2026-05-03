#!/bin/bash
set -euo pipefail

SRC_IP="${1:-8.8.8.8}"
DEST_IP="${2:-192.168.1.50}"
SEVERITY="${3:-1}"
SIGNATURE="${4:-PRUEBA REAL SURICATA}"
EVE_FILE="${EVE_FILE:-/var/log/suricata/eve.json}"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

JSON_PAYLOAD=$(printf '{"timestamp":"%s","event_type":"alert","src_ip":"%s","dest_ip":"%s","alert":{"signature":"%s","severity":%s}}' \
    "$TIMESTAMP" "$SRC_IP" "$DEST_IP" "$SIGNATURE" "$SEVERITY")

echo "Inyectando evento en $EVE_FILE"
echo "$JSON_PAYLOAD" | sudo tee -a "$EVE_FILE" >/dev/null
echo "Evento enviado:"
echo "$JSON_PAYLOAD"
