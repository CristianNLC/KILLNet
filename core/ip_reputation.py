import requests
import threading
from core.network_monitor import is_private_ip

# Caché en memoria para evitar redundancia en peticiones GeoIP
_IP_CACHE = {}
_CACHE_LOCK = threading.Lock()

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
