import os
import requests
import threading
from core.network_monitor import is_private_ip

# Caché en memoria para evitar redundancia en peticiones GeoIP
_IP_CACHE = {}
_CACHE_LOCK = threading.Lock()

# Clave API opcional para AbuseIPDB (Threat Intelligence). Sin clave configurada,
# la suite opera en modo heurístico (solo GeoIP + flags internos).
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

# Caché en memoria para Threat Intelligence (AbuseIPDB)
_ABUSE_CACHE = {}
_ABUSE_CACHE_LOCK = threading.Lock()

# Puntaje de abuso a partir del cual una IP se considera "maliciosa"
MALICIOUS_ABUSE_THRESHOLD = 50

def lookup_ip(ip_address: str, timeout: float = 4.0) -> dict:
    """
    Consulta la reputación y geolocalización de una IP remota.
    Si la IP es privada/local, retorna metadatos LAN directamente.
    Para IPs públicas utiliza http://ip-api.com con caché en memoria.
    """
    if not ip_address or ip_address in ("-", "*", "0.0.0.0", "127.0.0.1", "::1"):
        return {
            "ip": ip_address or "-",
            "country": "Local / LAN",
            "city": "Red Privada",
            "isp": "N/A",
            "suspicious": False
        }
    
    if is_private_ip(ip_address):
        return {
            "ip": ip_address,
            "country": "Local / LAN",
            "city": "Red Privada",
            "isp": "N/A",
            "suspicious": False
        }
        
    # Verificar en caché thread-safe
    with _CACHE_LOCK:
        if ip_address in _IP_CACHE:
            return _IP_CACHE[ip_address]
            
    # Realizar petición si es IP pública y no está en caché
    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,city,isp,query"
    
    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                result = {
                    "ip": ip_address,
                    "country": data.get("country", "Desconocido"),
                    "city": data.get("city", "Desconocido"),
                    "isp": data.get("isp", "Desconocido"),
                    "suspicious": False
                }
            else:
                result = {
                    "ip": ip_address,
                    "country": "Error CTI",
                    "city": data.get("message", "Consulta Fallida"),
                    "isp": "N/A",
                    "suspicious": False
                }
        else:
            result = {
                "ip": ip_address,
                "country": "HTTP Error",
                "city": f"Código {response.status_code}",
                "isp": "N/A",
                "suspicious": False
            }
    except requests.exceptions.Timeout:
        result = {
            "ip": ip_address,
            "country": "Timeout",
            "city": "Sin Respuesta (4s)",
            "isp": "N/A",
            "suspicious": False
        }
    except Exception as e:
        result = {
            "ip": ip_address,
            "country": "Error Conexión",
            "city": str(e)[:30],
            "isp": "N/A",
            "suspicious": False
        }
        
    # Guardar en caché
    with _CACHE_LOCK:
        _IP_CACHE[ip_address] = result
        
    return result

def clear_ip_cache():
    """Limpia la caché de GeoIP en memoria."""
    with _CACHE_LOCK:
        _IP_CACHE.clear()

def lookup_abuse_ip(ip_address: str, timeout: float = 3.0) -> dict:
    """
    Consulta la base de datos de Threat Intelligence de AbuseIPDB para una IP.
    Retorna el score de abuso (0-100), la categoría de amenaza reportada y si la IP
    está marcada como maliciosa. Si no hay API key configurada o falla la consulta,
    retorna un resultado seguro (score 0, no maliciosa, origen 'none').
    """
    result = {
        "ip": ip_address,
        "abuse_score": 0,
        "abuse_category": None,
        "is_malicious": False,
        "source": "none",
    }
    
    if not ABUSEIPDB_API_KEY:
        return result
        
    if not ip_address or ip_address in ("-", "*", "0.0.0.0", "127.0.0.1", "::1") or is_private_ip(ip_address):
        return result
        
    with _ABUSE_CACHE_LOCK:
        if ip_address in _ABUSE_CACHE:
            return _ABUSE_CACHE[ip_address]
        
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
        headers = {"Authorization": f"Bearer {ABUSEIPDB_API_KEY}"}
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code == 200:
            data = response.json().get("data") or {}
            score = int(data.get("abuseScore") or 0)
            category = data.get("category") or {}
            category_value = category.get("value") if isinstance(category, dict) else category
            result.update({
                "abuse_score": score,
                "abuse_category": category_value,
                "is_malicious": bool(data.get("isAbuseIPDBReported") or score >= MALICIOUS_ABUSE_THRESHOLD),
                "source": "AbuseIPDB"
            })
    except Exception:
        # En caso de fallo de red o respuesta inválida, operar en modo seguro
        pass
        
    with _ABUSE_CACHE_LOCK:
        _ABUSE_CACHE[ip_address] = result
        
    return result

def lookup_threat_summary(ip_address: str) -> dict:
    """
    Combina el resultado de GeoIP (ip-api.com) con Threat Intelligence (AbuseIPDB)
    para exponer un resumen unificado de la reputación de una IP.
    Retorna: { ip, country, city, isp, suspicious, abuse_score, abuse_category, is_malicious, source }
    """
    geo = lookup_ip(ip_address)
    abuse = lookup_abuse_ip(ip_address)
    
    return {
        "ip": ip_address,
        "country": geo.get("country", "Desconocido"),
        "city": geo.get("city", "Desconocido"),
        "isp": geo.get("isp", "N/A"),
        "suspicious": geo.get("suspicious", False),
        "abuse_score": abuse.get("abuse_score", 0),
        "abuse_category": abuse.get("abuse_category"),
        "is_malicious": abuse.get("is_malicious", False),
        "source": abuse.get("source", "none")
    }

def clear_threat_cache():
    """Limpia la caché de Threat Intelligence (AbuseIPDB) en memoria."""
    with _ABUSE_CACHE_LOCK:
        _ABUSE_CACHE.clear()
