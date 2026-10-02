import os
import sys
import socket
import ssl
import urllib.request
import urllib.error
import subprocess
from concurrent.futures import ThreadPoolExecutor

IS_WINDOWS = sys.platform.startswith("win")
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"

TEST_SERVICES = [
    {"category": "YouTube / Video", "domain": "youtube.com"},
    {"category": "YouTube / Video", "domain": "googlevideo.com"},
    {"category": "Redes Sociales", "domain": "instagram.com"},
    {"category": "Redes Sociales", "domain": "twitter.com"},
    {"category": "Redes Sociales", "domain": "x.com"},
    {"category": "Redes Sociales", "domain": "tiktok.com"},
    {"category": "Mensajería / Streaming", "domain": "netflix.com"},
    {"category": "Mensajería / Streaming", "domain": "discord.com"},
    {"category": "Prueba Conectividad", "domain": "google.com"},
    {"category": "Prueba Conectividad", "domain": "1.1.1.1"},
]

def check_single_service(service_info: dict) -> dict:
    """
    Evalúa resolución DNS y conexión HTTP/HTTPS para un dominio/servicio específico.
    """
    category = service_info["category"]
    domain = service_info["domain"]
    
    is_ip = False
    try:
        socket.inet_aton(domain)
        is_ip = True
    except Exception:
        is_ip = False
        
    resolved_ip = domain if is_ip else "-"
    
    # Step a) DNS Resolution
    if not is_ip:
        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(2.0)
            resolved_ip = socket.gethostbyname(domain)
            if resolved_ip in ("127.0.0.1", "0.0.0.0"):
                return {
                    "category": category,
                    "target": domain,
                    "status": "BLOQUEADO / INTERCEPTADO",
                    "cause": "DNS (Sinkhole / Local loopback)",
                    "ip": resolved_ip,
                    "details": f"DNS resolvió a {resolved_ip} (Redirección de bloqueo detectada)."
                }
        except socket.gaierror as ex:
            return {
                "category": category,
                "target": domain,
                "status": "BLOQUEADO / INTERCEPTADO",
                "cause": "DNS (Falla de Resolución)",
                "ip": "-",
                "details": f"Imposible resolver dominio por DNS: {str(ex)}"
            }
        except Exception as ex:
            return {
                "category": category,
                "target": domain,
                "status": "BLOQUEADO / INTERCEPTADO",
                "cause": "DNS Error",
                "ip": "-",
                "details": f"Error DNS: {str(ex)}"
            }
        finally:
            socket.setdefaulttimeout(old_timeout)
            
    # Step b) Connection HTTP / HTTPS
    url = f"https://{domain}" if not domain.startswith("http") else domain
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) KILLNet/1.0 NetworkChecker"}
    req = urllib.request.Request(url, headers=headers)
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        with urllib.request.urlopen(req, timeout=3.0, context=ctx) as resp:
            code = resp.getcode()
            final_url = resp.geturl().lower()
            
            # Verificar si hubo redirección a un portal cautivo o página de bloqueo ISP
            if any(term in final_url for term in ["portal", "bloqueo", "block", "denied", "captive", "login"]):
                return {
                    "category": category,
                    "target": domain,
                    "status": "BLOQUEADO / INTERCEPTADO",
                    "cause": "Portal Cautivo / ISP Firewall",
                    "ip": resolved_ip,
                    "details": f"Redirigido a portal de bloqueo ({final_url})"
                }
                
            if code in (200, 301, 302, 303, 307, 308):
                return {
                    "category": category,
                    "target": domain,
                    "status": "ACCESIBLE",
                    "cause": "Ninguna",
                    "ip": resolved_ip,
                    "details": f"Conexión HTTP/HTTPS exitosa (Código {code})."
                }
    except urllib.error.HTTPError as ex:
        # Respuestas HTTP como 200, 301, 302, 403, 404 provenientes del servidor original significan que el puerto no está bloqueado por firewall
        if ex.code in (200, 301, 302, 303, 307, 308, 403, 404):
            return {
                "category": category,
                "target": domain,
                "status": "ACCESIBLE",
                "cause": "Ninguna",
                "ip": resolved_ip,
                "details": f"Servidor remoto respondió HTTP {ex.code}."
            }
        return {
            "category": category,
            "target": domain,
            "status": "BLOQUEADO / INTERCEPTADO",
            "cause": f"HTTP Error {ex.code}",
            "ip": resolved_ip,
            "details": f"Respuesta de error HTTP {ex.code}: {ex.reason}"
        }
    except (urllib.error.URLError, TimeoutError, ConnectionRefusedError, socket.timeout) as ex:
        err_msg = str(ex)
        if "refused" in err_msg.lower():
            cause = "Conexión Rechazada (Firewall)"
        elif "timed out" in err_msg.lower() or "timeout" in err_msg.lower():
            cause = "Timeout / Firewall Drop"
        else:
            cause = "Conexión Interceptada"
            
        return {
            "category": category,
            "target": domain,
            "status": "BLOQUEADO / INTERCEPTADO",
            "cause": cause,
            "ip": resolved_ip,
            "details": f"Falla de conexión: {err_msg}"
        }
    except Exception as ex:
        return {
            "category": category,
            "target": domain,
            "status": "BLOQUEADO / INTERCEPTADO",
            "cause": "Error General",
            "ip": resolved_ip,
            "details": f"Excepción de red: {str(ex)}"
        }

def run_restriction_diagnostics() -> list[dict]:
    """Evalúa concurrentemente todos los servicios de prueba."""
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(check_single_service, TEST_SERVICES))
    return results

def check_hosts_file() -> list[dict]:
    """Inspecciona C:\\Windows\\System32\\drivers\\etc\\hosts en busca de redirecciones a 127.0.0.1 o 0.0.0.0."""
    blocked_entries = []
    if not os.path.exists(HOSTS_PATH):
        return blocked_entries
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                ip, domain = parts[0], parts[1]
                if ip in ("127.0.0.1", "0.0.0.0"):
                    blocked_entries.append({"ip": ip, "domain": domain})
    except Exception as e:
        print(f"[ERROR] No se pudo leer archivo hosts: {e}")
    return blocked_entries

def clean_hosts_file(domains_to_clean: list[str] = None) -> tuple[bool, str]:
    """Elimina las redirecciones de bloqueo del archivo hosts."""
    if not os.path.exists(HOSTS_PATH):
        return False, "El archivo C:\\Windows\\System32\\drivers\\etc\\hosts no existe."
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            
        new_lines = []
        removed_count = 0
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                new_lines.append(line)
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                ip, domain = parts[0], parts[1]
                if ip in ("127.0.0.1", "0.0.0.0"):
                    if domains_to_clean is None or domain.lower() in [d.lower() for d in domains_to_clean]:
                        removed_count += 1
                        continue
            new_lines.append(line)
            
        if removed_count == 0:
            return True, "No se detectaron entradas de bloqueo en el archivo hosts."
            
        # Crear copia de respaldo
        backup_path = HOSTS_PATH + ".bak"
        with open(backup_path, "w", encoding="utf-8") as bf:
            bf.writelines(lines)
            
        with open(HOSTS_PATH, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
            
        return True, f"Se eliminaron {removed_count} reglas de bloqueo del archivo hosts (Copia .bak creada)."
    except PermissionError:
        return False, "Acceso Denegado al archivo hosts. Debe ejecutar KILLNet como Administrador."
    except Exception as e:
        return False, f"Excepción al limpiar archivo hosts: {str(e)}"

def get_active_network_adapter() -> str:
    """Detecta el nombre de la interfaz de red activa en Windows (e.g., 'Wi-Fi', 'Ethernet')."""
    if not IS_WINDOWS:
        return "eth0"
    try:
        cmd = ["powershell", "-NoProfile", "-Command", "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name"]
        res = subprocess.run(cmd, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW, timeout=3.0)
        if res.returncode == 0 and res.stdout.strip():
            adapters = [a.strip() for a in res.stdout.strip().splitlines() if a.strip()]
            if adapters:
                return adapters[0]
    except Exception:
        pass
    return "Wi-Fi"

def apply_secure_dns(adapter_name: str = None, dns_servers: tuple[str, str] = ("1.1.1.1", "1.0.0.1")) -> tuple[bool, str]:
    """
    Cambia los servidores DNS de la interfaz dada a DNS públicos limpios (Default Cloudflare 1.1.1.1 / 1.0.0.1)
    usando netsh y realiza un ipconfig /flushdns.
    """
    if not IS_WINDOWS:
        return False, "Operación no soportada en este sistema operativo."
        
    if not adapter_name:
        adapter_name = get_active_network_adapter()
        
    primary, secondary = dns_servers
    
    cmd_primary = f'netsh interface ip set dns name="{adapter_name}" source=static addr={primary}'
    cmd_secondary = f'netsh interface ip add dns name="{adapter_name}" addr={secondary} index=2'
    
    try:
        res1 = subprocess.run(cmd_primary, capture_output=True, text=True, shell=True, creationflags=CREATE_NO_WINDOW)
        if res1.returncode != 0:
            err = res1.stderr.strip() or res1.stdout.strip()
            return False, f"Fallo al asignar DNS primario en '{adapter_name}': {err} (¿Faltan privilegios de Administrador?)"
            
        res2 = subprocess.run(cmd_secondary, capture_output=True, text=True, shell=True, creationflags=CREATE_NO_WINDOW)
        
        # Purgar caché DNS
        subprocess.run("ipconfig /flushdns", capture_output=True, shell=True, creationflags=CREATE_NO_WINDOW)
        
        return True, f"✅ DNS públicos seguros ({primary}, {secondary}) aplicados correctamente en '{adapter_name}'. Caché DNS purgada."
    except Exception as e:
        return False, f"Excepción al cambiar configuración DNS: {str(e)}"

def reset_dns_dhcp(adapter_name: str = None) -> tuple[bool, str]:
    """Restaura la configuración de DNS a automática (DHCP)."""
    if not IS_WINDOWS:
        return False, "Operación no soportada en este sistema operativo."
        
    if not adapter_name:
        adapter_name = get_active_network_adapter()
        
    cmd = f'netsh interface ip set dns name="{adapter_name}" source=dhcp'
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, shell=True, creationflags=CREATE_NO_WINDOW)
        if res.returncode == 0:
            subprocess.run("ipconfig /flushdns", capture_output=True, shell=True, creationflags=CREATE_NO_WINDOW)
            return True, f"✅ Configuración DNS restaurada a DHCP automático en '{adapter_name}'."
        else:
            err = res.stderr.strip() or res.stdout.strip()
            return False, f"Error al restaurar DNS DHCP: {err}"
    except Exception as e:
        return False, f"Excepción al restaurar DNS: {str(e)}"
