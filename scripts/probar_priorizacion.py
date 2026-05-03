#!/usr/bin/env python3
from pathlib import Path
import sys

BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

from osint import enriquecer_ip
from utils import get_db_connection


CASOS = [
    {
        "firma": "PRUEBA BENIGNA GOOGLE DNS",
        "src_ip": "8.8.8.8",
        "dest_ip": "192.168.1.50",
        "severidad": 2,
    },
    {
        "firma": "PRUEBA BENIGNA CLOUDFLARE DNS",
        "src_ip": "1.1.1.1",
        "dest_ip": "192.168.1.50",
        "severidad": 2,
    },
]


def insertar_alerta(cur, caso, enriquecimiento):
    cur.execute(
        """
        INSERT INTO alertas (
            fecha,
            ip_origen,
            ip_destino,
            firma,
            severidad,
            reputacion_osint,
            vt_malicious,
            vt_suspicious,
            vt_reputation,
            abuse_confidence,
            abuse_reports,
            gn_noise,
            gn_riot,
            gn_classification,
            otx_pulse_count,
            otx_tags,
            otx_malware_families,
            osint_score
        )
        VALUES (
            NOW(), %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        RETURNING id
        """,
        (
            caso["src_ip"],
            caso["dest_ip"],
            caso["firma"],
            caso["severidad"],
            enriquecimiento["vt_malicious"],
            enriquecimiento["vt_malicious"],
            enriquecimiento["vt_suspicious"],
            enriquecimiento["vt_reputation"],
            enriquecimiento["abuse_confidence"],
            enriquecimiento["abuse_reports"],
            enriquecimiento["gn_noise"],
            enriquecimiento["gn_riot"],
            enriquecimiento["gn_classification"],
            enriquecimiento["otx_pulse_count"],
            enriquecimiento["otx_tags"],
            enriquecimiento["otx_malware_families"],
            enriquecimiento["osint_score"],
        ),
    )
    return cur.fetchone()[0]


def main():
    print("Iniciando prueba controlada de priorizacion...")
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        for caso in CASOS:
            enriquecimiento = enriquecer_ip(caso["src_ip"])
            alerta_id = insertar_alerta(cur, caso, enriquecimiento)
            print(
                f"Alerta {alerta_id} insertada para {caso['src_ip']} | "
                f"VT+={enriquecimiento['vt_malicious']} | "
                f"AbuseReports={enriquecimiento['abuse_reports']} | "
                f"GN={enriquecimiento['gn_classification']} | "
                f"OTX={enriquecimiento['otx_pulse_count']} | "
                f"OSINT={enriquecimiento['osint_score']}"
            )
        conn.commit()
    finally:
        cur.close()
        conn.close()
    print("Prueba insertada. Ahora ejecuta el motor o espera a que la procese.")


if __name__ == "__main__":
    main()
