import json, time
from osint import enriquecer_ip
from utils import get_db_connection

log_file = "/var/log/suricata/eve.json"

def procesar():
    conn = get_db_connection()
    cursor = conn.cursor()
    print("🎧 Escuchando Suricata...")
    
    with open(log_file, "r") as f:
        f.seek(0, 2)
        while True:
            linea = f.readline()
            if not linea:
                time.sleep(0.5)
                continue
            try:
                data = json.loads(linea)
                if data.get("event_type") == "alert":
                    ip = data.get("src_ip")
                    osint = enriquecer_ip(ip)
                    cursor.execute("""
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
                            %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s
                        )
                    """, (
                        data.get("timestamp"),
                        ip,
                        data.get("dest_ip"),
                        data["alert"].get("signature"),
                        data["alert"].get("severity", 3),
                        osint["vt_malicious"],
                        osint["vt_malicious"],
                        osint["vt_suspicious"],
                        osint["vt_reputation"],
                        osint["abuse_confidence"],
                        osint["abuse_reports"],
                        osint["gn_noise"],
                        osint["gn_riot"],
                        osint["gn_classification"],
                        osint["otx_pulse_count"],
                        osint["otx_tags"],
                        osint["otx_malware_families"],
                        osint["osint_score"],
                    ))
                    conn.commit()
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    procesar()
