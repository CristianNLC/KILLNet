import os
import sys
import threading
import requests

IS_WINDOWS = sys.platform.startswith("win")
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

# Cachés en memoria por fuente para evitar redundancia en peticiones
_VT_CACHE = {}
_VT_CACHE_LOCK = threading.Lock()
_OTX_CACHE = {}
_OTX_CACHE_LOCK = threading.Lock()

_LOCAL_THOUGHT = {
    "ip": "-",
    "abuse_score": 0,
    "abuse_category": None,
    "is_malicious": False,
    "malicious_sources": [],
    "vt_score": 0,
    "vt_malicious": False,
    "otx_pulse": 0,
    "otx_general": False,
    "suspicious": False,
    "source": "local",
}


def _is_private_ip(ip_address: str) -> bool:
    """Verifica si la IP pertenece a rangos privados, loopback o link-local."""
    if not ip_address or ip_address in ("-", "*", "0.0.0.0", "127.0.0.1", "::1"):
        return True
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip_address)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        )
    except Exception:
        return True


def lookup_virustotal(ip_address: str, timeout: float = 3.0) -> dict:
    """
    Consulta VirusTotal (v3 API) el análisis de reputación de una IP.
    Retorna el score de detecciones (maliciosas + sospechosas) y si hubo detección.
    Sin API key configurada o ante fallos, retorna un resultado seguro.
    """
    result = {
        "ip": ip_address,
        "vt_score": 0,
        "vt_malicious": False,
        "source": "none",
    }
    
    if not VIRUSTOTAL_API_KEY:
        return result
    if _is_private_ip(ip_address):
        return result
        
    with _VT_CACHE_LOCK:
        if ip_address in _VT_CACHE:
            return _VT_CACHE[ip_address]
        
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip/{ip_address}/analysis",
            headers=headers,
            timeout=timeout
        )
        if response.status_code == 200:
            data = response.json().get("data") or {}
            attrs = data.get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious") or 0)
            suspicious = int(stats.get("suspicious") or 0)
            result["vt_score"] = malicious + suspicious
            result["vt_malicious"] = malicious > 0
            result["source"] = "VirusTotal"
    except Exception:
        pass
        
    with _VT_CACHE_LOCK:
        _VT_CACHE[ip_address] = result
    return result


def lookup_otx(ip_address: str, timeout: float = 3.0) -> dict:
    """
    Consulta AlienVault OTX (OTX) las pulsos de amenaza asociadas a una IP.
    Retorna el conteo de pulsos (pulse count) y si la IP está reportada.
    Sin API key configurada o ante fallos, retorna un resultado seguro.
    """
    result = {
        "ip": ip_address,
        "otx_pulse": 0,
        "otx_general": False,
        "source": "none",
    }
    
    if not OTX_API_KEY:
        return result
    if _is_private_ip(ip_address):
        return result
        
    with _OTX_CACHE_LOCK:
        if ip_address in _OTX_CACHE:
            return _OTX_CACHE[ip_address]
        
    try:
        response = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/ipaddr/{ip_address}/general",
            headers={"Authorization": f"Bearer {OTX_API_KEY}"},
            timeout=timeout
        )
        if response.status_code == 200:
            data = response.json().get("response") or {}
            pulse_info = data.get("pulse_info") or {}
            count = int(pulse_info.get("count") or 0)
            result["otx_pulse"] = count
            result["otx_general"] = count > 0
            result["source"] = "OTX"
    except Exception:
        pass
        
    with _OTX_CACHE_LOCK:
        _OTX_CACHE[ip_address] = result
    return result


def lookup_ip_threat(ip_address: str) -> dict:
    """
    Consulta la Threat Intelligence unificada contra múltiples fuentes:
    AbuseIPDB (score de abuso), VirusTotal (detecciones) y AlienVault OTX (pulsos).
    Retorna un resumen consolidado con flags de maliciosidad y fuentes activas.
    """
    if _is_private_ip(ip_address):
        return dict(_LOCAL_THOUGHT)
        
    from core.ip_reputation import lookup_abuse_ip
    
    abuse = lookup_abuse_ip(ip_address)
    vt = lookup_virustotal(ip_address)
    otx = lookup_otx(ip_address)
    
    malicious_sources = []
    if abuse.get("is_malicious"):
        malicious_sources.append("AbuseIPDB")
    if vt.get("vt_malicious"):
        malicious_sources.append("VirusTotal")
    if otx.get("otx_general"):
        malicious_sources.append("OTX")
    
    is_malicious = len(malicious_sources) > 0
    
    return {
        "ip": ip_address,
        "abuse_score": abuse.get("abuse_score") or 0,
        "abuse_category": abuse.get("abuse_category"),
        "is_malicious": is_malicious,
        "malicious_sources": malicious_sources,
        "vt_score": vt.get("vt_score") or 0,
        "vt_malicious": vt.get("vt_malicious") or False,
        "otx_pulse": otx.get("otx_pulse") or 0,
        "otx_general": otx.get("otx_general") or False,
        "suspicious": bool(is_malicious or vt.get("vt_score") or otx.get("otx_pulse")),
        "source": ", ".join(malicious_sources) if malicious_sources else "none",
    }


def clear_threat_intel_caches() -> None:
    """Limpia las cachés en memoria de Threat Intelligence."""
    with _VT_CACHE_LOCK:
        _VT_CACHE.clear()
    with _OTX_CACHE_LOCK:
        _OTX_CACHE.clear()
