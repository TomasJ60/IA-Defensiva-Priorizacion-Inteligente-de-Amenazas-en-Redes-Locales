#!/bin/bash
set -euo pipefail

DB_NAME="${DB_NAME:-agente_ia}"
DB_USER="${DB_USER:-postgres}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"

psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -d "$DB_NAME" <<'SQL'
SELECT
    id,
    ip_origen,
    ip_destino,
    firma,
    severidad,
    vt_malicious,
    vt_reputation,
    abuse_confidence,
    abuse_reports,
    gn_noise,
    gn_riot,
    gn_classification,
    otx_pulse_count,
    osint_score,
    prioridad_ia,
    explicacion,
    recomendacion
FROM alertas
ORDER BY id DESC
LIMIT 10;
SQL
