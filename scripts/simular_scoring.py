#!/usr/bin/env python3
"""
Simulación directa del cálculo del motor para verificar la fórmula
"""

print("="*70)
print("SIMULACIÓN DEL ALGORITMO DE SCORING")
print("="*70)

casos = [
    {"ip": "192.168.1.50", "severidad": 1, "osint": 15, "criticidad": 5, "prob_mal": 0.9, "desc": "🔴 CRÍTICO"},
    {"ip": "192.168.1.50", "severidad": 1, "osint": 0, "criticidad": 5, "prob_mal": 0.8, "desc": "🔴 CRÍTICO"},
    {"ip": "192.168.1.100", "severidad": 1, "osint": 8, "criticidad": 4, "prob_mal": 0.7, "desc": "🟠 ALTO RIESGO"},
    {"ip": "192.168.1.150", "severidad": 0, "osint": 5, "criticidad": 2, "prob_mal": 0.5, "desc": "🟡 MEDIO"},
    {"ip": "192.168.1.200", "severidad": 0, "osint": 0, "criticidad": 1, "prob_mal": 0.3, "desc": "🟢 BAJO"},
    {"ip": "10.0.0.1", "severidad": 1, "osint": 10, "criticidad": 1, "prob_mal": 0.6, "desc": "⚠️ EXTERNO"},
]

for caso in casos:
    sev = caso["severidad"]
    rep = caso["osint"]
    crit = caso["criticidad"]
    prob_mal = caso["prob_mal"]
    
    # FÓRMULA ACTUALIZADA
    score_crit = crit * 10                      # Máx 50 puntos (1-5 -> 10-50)
    score_ia = prob_mal * 25                    # Máx 25 puntos
    score_sev = (15 if sev == 1 else 3)         # Máx 15 puntos
    score_osint = min(rep, 5) * 3               # Máx 15 puntos
    
    score_final = float(round(score_ia + score_osint + score_sev + score_crit, 1))
    
    # Clasificación
    if score_final >= 75:
        nivel = "🔥 URGENTE: Aislar host"
        emoji = "🔴"
    elif score_final >= 50:
        nivel = "⚠️ PRECAUCIÓN: Monitorear"
        emoji = "🟠"
    elif score_final >= 25:
        nivel = "⛔ ALERTA: Revisar"
        emoji = "🟡"
    else:
        nivel = "✅ NORMAL"
        emoji = "🟢"
    
    print(f"\n{emoji} {caso['desc']}")
    print(f"   IP: {caso['ip']} | Severidad: {sev} | OSINT: {rep} | Criticidad: {crit}/5")
    print(f"   Probabilidad ML: {int(prob_mal*100)}%")
    print(f"   Desglose de score:")
    print(f"      • Criticidad:  {score_crit:5.1f} puntos")
    print(f"      • ML (IA):     {score_ia:5.1f} puntos")
    print(f"      • Severidad:   {score_sev:5.1f} puntos")
    print(f"      • OSINT:       {score_osint:5.1f} puntos")
    print(f"   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"   📊 SCORE TOTAL: {score_final:5.1f}/105")
    print(f"   {nivel}")

print("\n" + "="*70)
print("RANGOS DE CLASIFICACIÓN:")
print("  🔴 CRÍTICO:     ≥ 75 (URGENTE)")
print("  🟠 ALTO:        50-74 (PRECAUCIÓN)")
print("  🟡 MEDIO:       25-49 (ALERTA)")
print("  🟢 BAJO:        < 25 (NORMAL)")
print("="*70 + "\n")
