import os
import sys

IS_WINDOWS = sys.platform.startswith("win")
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# Umbrales de puntuación que determinan el nivel de riesgo de una conexión/proceso
RISK_THRESHOLDS = [
    (0, "LOW"),
    (25, "MEDIUM"),
    (50, "HIGH"),
    (75, "CRITICAL"),
]

# Nombres de procesos que activan un factor de sospecha por comportamiento
RISKY_PROCESS_NAMES = [
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "taskmgr.exe",
]

def get_risk_level(score: int) -> str:
    """
    Mapea una puntuación numérica (0-100) a un nivel cualitativo de riesgo.
    """
    level = "LOW"
    for threshold, name in sorted(RISK_THRESHOLDS, key=lambda x: x[0]):
        if score >= threshold:
            level = name
    return level

def compute_connection_risk(connection: dict, threat_info: dict = None) -> dict:
    """
    Calcula el score de riesgo (0-100) de una conexión de red detectada.

    Factores considerados:
      - IP remota maliciosa reportada por Threat Intelligence (AbuseIPDB): +60.
      - Puntaje de abuso alto (heurística): hasta +40.
      - Conexión saliente a una IP pública (no privada): +5.
      - Servicio en escucha (LISTEN) sobre IP pública: +15 (exposición).
      - Proceso sospechoso por nombre (cmd, powershell, etc.): +10.

    Retorna un dict con 'risk_score', 'risk_level', 'risk_reasons',
    'threat_malicious' y 'abuse_score'.
    """
    if threat_info is None:
        threat_info = {}
        
    score = 0
    reasons = []
    abuse_score = int(threat_info.get("abuse_score") or 0)
    is_malicious = bool(threat_info.get("is_malicious") or False)
    vt_score = int(threat_info.get("vt_score") or 0)
    otx_pulse = int(threat_info.get("otx_pulse") or 0)
    malicious_sources = threat_info.get("malicious_sources") or []
    
    remote_ip = connection.get("remote_ip") or ""
    is_private = connection.get("is_private", True)
    status = connection.get("status") or ""
    proc_name = connection.get("process_name") or ""
    
    # 1. Threat Intelligence unificada: IP maliciosa confirmada por alguna fuente (AbuseIPDB / VirusTotal / OTX)
    if is_malicious:
        source_str = ", ".join(malicious_sources) if malicious_sources else threat_info.get("source", "desconocido")
        score += 70
        reasons.append(f"IP maliciosa confirmada por Threat Intelligence ({source_str})")
    elif abuse_score:
        contribution = min(40, int(abuse_score * 0.5))
        score += contribution
        if contribution > 0:
            reasons.append(f"Puntaje de abuso elevado en Threat Intelligence ({abuse_score})")
    
    # 2. Señales complementarias de amenaza (detecciones en VirusTotal / OTX)
    if vt_score or otx_pulse:
        contribution = min(15, int(max(vt_score, otx_pulse) * 5))
        score += contribution
        if contribution > 0:
            reasons.append(f"Se detectaron coincidencias de amenaza en Threat Intelligence (VirusTotal/OTX)")
    
    # 3. Conexión saliente hacia IP pública (tráfico externo)
    if not is_private:
        score += 5
        if status == "LISTEN":
            score += 15
            reasons.append("Servicio en escucha sobre IP pública")
    
    # 3. Proceso sospechoso por nombre
    if proc_name and proc_name != "N/A":
        proc_clean = proc_name.lower().replace(" ", "")
        if any(risky in proc_clean for risky in RISKY_PROCESS_NAMES):
            score += 10
            reasons.append(f"Proceso potencialmente riesgoso: {proc_name}")
    
    risk_score = min(100, int(score))
    risk_level = get_risk_level(risk_score)
    
    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_reasons": reasons,
        "threat_malicious": is_malicious,
        "abuse_score": abuse_score,
        "vt_score": vt_score,
        "otx_pulse": otx_pulse,
    }
