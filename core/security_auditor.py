import os
import sys
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

IS_WINDOWS = sys.platform.startswith("win")
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

DEFAULT_AUDIT_PORTS = [21, 22, 23, 80, 135, 139, 443, 445, 554, 3389, 5000, 8080]

SERVICE_MAP = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Remote Terminal)",
    80: "HTTP (Web Server)",
    135: "RPC (Remote Procedure Call)",
    139: "NetBIOS-SSN",
    443: "HTTPS (Secure Web Server)",
    445: "SMB (Microsoft File Sharing)",
    554: "RTSP (Real Time Streaming / Camera)",
    3389: "RDP (Remote Desktop Protocol)",
    5000: "UPnP (Universal Plug and Play)",
    8080: "Web Proxy / Alt-HTTP"
}

def _check_port_banner(target_ip: str, port: int, timeout: float) -> dict:
    service_name = SERVICE_MAP.get(port, f"TCP/{port}")
    is_open = False
    banner = "Sin respuesta de banner"
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        res = s.connect_ex((target_ip, port))
        if res == 0:
            is_open = True
            # Intento de banner grabbing no invasivo
            try:
                if port in (80, 8080):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
                data = s.recv(512)
                if data:
                    raw_text = data.decode("utf-8", errors="ignore").strip()
                    first_line = raw_text.splitlines()[0] if raw_text else ""
                    banner = first_line[:90] if first_line else "Conectado (Servicio activo)"
                else:
                    banner = "Conectado (Sin banner retornado)"
            except Exception:
                banner = "Conectado (Puerto ABIERTO)"
        s.close()
    except Exception:
        is_open = False
        
    return {
        "port": port,
        "service": service_name,
        "status": "ABIERTO" if is_open else "CERRADO",
        "is_open": is_open,
        "banner": banner
    }

def scan_device_security(target_ip: str, port_list: list = None, timeout: float = 0.6, progress_callback=None) -> list[dict]:
    """
    Audita los puertos TCP comunes de un host objetivo para diagnóstico de exposición
    y captura básica de banners de versión.
    """
    if not port_list:
        port_list = DEFAULT_AUDIT_PORTS
        
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(_check_port_banner, target_ip, p, timeout) for p in port_list]
        for f in futures:
            try:
                r = f.result()
                results.append(r)
            except Exception:
                pass
                
    results.sort(key=lambda x: x["port"])
    return results

def audit_cleartext_protocols(target_ip: str, open_ports: list[dict]) -> list[dict]:
    """
    Evalúa los puertos abiertos del host objetivo en busca de protocolos inseguros en texto plano
    y retorna recomendaciones de hardening.
    """
    warnings = []
    
    for item in open_ports:
        if not item.get("is_open"):
            continue
            
        port = item["port"]
        if port == 23:
            warnings.append({
                "port": 23,
                "severity": "CRÍTICO",
                "title": "Telnet en Texto Plano",
                "desc": f"El puerto 23 ({target_ip}) tiene el servicio Telnet abierto. Todas las credenciales y comandos viajan en texto plano sin cifrado.",
                "recommendation": "Deshabilitar Telnet y migrar a SSH (Puerto 22) con cifrado SSL/TLS."
            })
        elif port == 21:
            warnings.append({
                "port": 21,
                "severity": "ALTO",
                "title": "FTP Sin Cifrar",
                "desc": f"Servicio FTP tradicional abierto en puerto 21. Transmisión de archivos e inicio de sesión expuesto a sniffing en la LAN.",
                "recommendation": "Migrar a SFTP (SSH) o habilitar FTP sobre TLS (FTPS)."
            })
        elif port in (80, 8080):
            warnings.append({
                "port": port,
                "severity": "MEDIO",
                "title": "Servidor HTTP Plano",
                "desc": f"Puerto Web {port} abierto en texto plano sin certificado HTTPS.",
                "recommendation": "Habilitar cifrado SSL/TLS y forzar redirección a HTTPS (Puerto 443)."
            })
        elif port in (139, 445):
            warnings.append({
                "port": port,
                "severity": "ALTO",
                "title": "SMB / NetBIOS Expuesto",
                "desc": f"Servicios de compartición de archivos Windows SMB ({port}) expuestos en la red.",
                "recommendation": "Asegurar que SMBv1 esté deshabilitado y verificar permisos de acceso anónimo."
            })
        elif port == 5000:
            warnings.append({
                "port": 5000,
                "severity": "MEDIO",
                "title": "UPnP Web Expuesto",
                "desc": f"Servicio UPnP en puerto 5000 detectado.",
                "recommendation": "Verificar la necesidad de UPnP y deshabilitarlo si no es requerido por el dispositivo."
            })
            
    return warnings

def isolate_host_local_firewall(target_ip: str) -> tuple[bool, str]:
    """
    Aplica reglas en el Firewall de Windows nativo para aislar el host en este equipo,
    bloqueando todo el tráfico entrante y saliente hacia y desde esa IP.
    """
    if not target_ip or target_ip in ("-", "*", "127.0.0.1", "0.0.0.0"):
        return False, "No se puede aislar una IP local, nula o de loopback."
        
    rule_name = f"KILLNet_Isolate_{target_ip.replace(':', '_')}"
    
    cmd_in = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f'name="{rule_name}"',
        "dir=in",
        "action=block",
        f"remoteip={target_ip}"
    ]
    cmd_out = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f'name="{rule_name}"',
        "dir=out",
        "action=block",
        f"remoteip={target_ip}"
    ]
    
    try:
        res_in = subprocess.run(
            " ".join(cmd_in), capture_output=True, text=True, shell=True,
            creationflags=CREATE_NO_WINDOW if IS_WINDOWS else 0
        )
        res_out = subprocess.run(
            " ".join(cmd_out), capture_output=True, text=True, shell=True,
            creationflags=CREATE_NO_WINDOW if IS_WINDOWS else 0
        )
        
        if res_in.returncode == 0 and res_out.returncode == 0:
            return True, f"🛑 HOST AISLADO: Se crearon reglas de Firewall de Windows (Entrada/Salida) bloqueando la IP {target_ip} en este equipo."
        else:
            err = res_in.stderr.strip() or res_out.stderr.strip() or res_in.stdout.strip()
            return False, f"Fallo al agregar reglas de aislamiento netsh: {err}. ¿Ejecutando como Administrador?"
    except Exception as e:
        return False, f"Excepción al aislar host en el cortafuegos: {str(e)}"
