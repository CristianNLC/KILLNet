import os
import sys
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

IS_WINDOWS = sys.platform.startswith("win")
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

CRITICAL_ROUTER_PORTS = [
    {"port": 21, "service": "FTP", "risk_if_open": "MEDIO", "info": "Servicio FTP en texto plano sin cifrar."},
    {"port": 22, "service": "SSH", "risk_if_open": "BAJO/MEDIO", "info": "Consola remota segura SSH."},
    {"port": 23, "service": "Telnet", "risk_if_open": "CRÍTICO", "info": "Telnet inseguro en texto plano. Vulnerabilidad grave."},
    {"port": 80, "service": "HTTP", "risk_if_open": "MEDIO", "info": "Panel de administración Web no cifrado."},
    {"port": 443, "service": "HTTPS", "risk_if_open": "BAJO", "info": "Panel de administración Web SSL/TLS cifrado."},
    {"port": 445, "service": "SMB", "risk_if_open": "ALTO", "info": "Compartición de archivos Windows SMB expuesto."},
    {"port": 1900, "service": "UPnP SSDP", "risk_if_open": "CRÍTICO", "info": "Vulnerabilidad UPnP. Permite redirecciones de puertos no autorizadas."},
    {"port": 5000, "service": "UPnP Web", "risk_if_open": "ALTO", "info": "Servicio UPnP / Control remoto HTTP."},
    {"port": 8080, "service": "HTTP-Alt", "risk_if_open": "MEDIO", "info": "Panel Web secundario de administración."}
]

def format_mac(mac_raw: str) -> str:
    """Normaliza la dirección MAC al formato XX:XX:XX:XX:XX:XX en mayúsculas."""
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac_raw).upper()
    if len(clean) == 12:
        return ":".join(clean[i:i+2] for i in range(0, 12, 2))
    return mac_raw.upper().replace("-", ":")

def get_gateway_ip() -> str:
    """Detecta la IP del Gateway predeterminado en Windows."""
    if not IS_WINDOWS:
        return "192.168.1.1"
    try:
        cmd = ["powershell", "-NoProfile", "-Command", "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop)"]
        res = subprocess.run(cmd, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW, timeout=3.0)
        if res.returncode == 0 and res.stdout.strip():
            ips = [i.strip() for i in res.stdout.strip().splitlines() if i.strip() and i.strip() != "0.0.0.0"]
            if ips:
                return ips[0]
    except Exception:
        pass
        
    # Fallback usando ipconfig
    try:
        res = subprocess.run(["ipconfig"], capture_output=True, text=True, creationflags=CREATE_NO_WINDOW, timeout=3.0)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if "Puerta de enlace predeterminada" in line or "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[1].strip():
                        ip_found = parts[1].strip()
                        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_found):
                            return ip_found
    except Exception:
        pass
        
    return "192.168.1.1"

def get_mac_for_ip(target_ip: str) -> str:
    """Resolución de dirección MAC para una IP en la tabla ARP de Windows."""
    if not target_ip or target_ip == "-":
        return "Desconocida"
    try:
        # Enviar un ping ultracorto para refrescar la tabla ARP
        subprocess.run(["ping", "-n", "1", "-w", "200", target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
        
        output = subprocess.check_output(["arp", "-a"], text=True, creationflags=CREATE_NO_WINDOW)
        pattern = re.compile(
            rf"{re.escape(target_ip)}\s+([0-9a-fa-f]{{2}}[:-][0-9a-fa-f]{{2}}[:-][0-9a-fa-f]{{2}}[:-][0-9a-fa-f]{{2}}[:-][0-9a-fa-f]{{2}}[:-][0-9a-fa-f]{{2}})"
        )
        match = pattern.search(output)
        if match:
            return format_mac(match.group(1))
    except Exception:
        pass
    return "Desconocida"

def get_wifi_interface_details() -> dict:
    """Obtiene datos de la interfaz Wi-Fi activa (SSID, BSSID, Canal, Señal, Autenticación)."""
    details = {
        "ssid": "No conectado",
        "bssid": "N/A",
        "signal": "N/A",
        "channel": "N/A",
        "auth": "N/A",
        "interface": "Wi-Fi"
    }
    if not IS_WINDOWS:
        return details
    try:
        res = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, creationflags=CREATE_NO_WINDOW, timeout=3.0)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if ":" not in line:
                    continue
                k, v = [x.strip() for x in line.split(":", 1)]
                k_low = k.lower()
                if k_low == "ssid":
                    details["ssid"] = v if v else "Red no identificada"
                elif k_low == "bssid":
                    details["bssid"] = format_mac(v) if v else "N/A"
                elif k_low in ("señal", "signal"):
                    details["signal"] = v
                elif k_low in ("canal", "channel"):
                    details["channel"] = v
                elif k_low in ("autenticación", "authentication"):
                    details["auth"] = v
                elif k_low in ("nombre", "name") and details["interface"] == "Wi-Fi":
                    details["interface"] = v
    except Exception:
        pass
    return details

def get_gateway_info() -> dict:
    """
    Detecta la IP del Gateway predeterminado y su MAC física asociada,
    junto con la telemetría Wi-Fi de la conexión activa.
    """
    gw_ip = get_gateway_ip()
    gw_mac = get_mac_for_ip(gw_ip)
    wifi_meta = get_wifi_interface_details()
    
    return {
        "gateway_ip": gw_ip,
        "gateway_mac": gw_mac,
        "ssid": wifi_meta["ssid"],
        "bssid": wifi_meta["bssid"],
        "signal": wifi_meta["signal"],
        "channel": wifi_meta["channel"],
        "auth": wifi_meta["auth"],
        "interface": wifi_meta["interface"]
    }

def start_arp_guard(alert_callback, stop_event, auto_fix: bool = False):
    """
    Hilo en segundo plano que sondea cada 2s la IP y MAC del gateway.
    Si la MAC cambia de repente o se detectan duplicados ARP, dispara una alerta inmediata.
    """
    initial_info = get_gateway_info()
    gateway_ip = initial_info["gateway_ip"]
    baseline_mac = initial_info["gateway_mac"]
    adapter_name = initial_info["interface"]
    
    # Si la MAC inicial no se pudo obtener, reintentar durante los primeros 4 segundos
    retry_count = 0
    while (baseline_mac == "Desconocida" or not baseline_mac) and retry_count < 2 and not stop_event.is_set():
        time.sleep(2)
        baseline_mac = get_mac_for_ip(gateway_ip)
        retry_count += 1
        
    while not stop_event.is_set():
        try:
            current_mac = get_mac_for_ip(gateway_ip)
            
            # Verificar si la MAC cambió repentinamente
            if current_mac != "Desconocida" and baseline_mac != "Desconocida" and current_mac != baseline_mac:
                alert_msg = f"¡ALERTA DE MITM / ARP SPOOFING DETECTADA! La IP del router ({gateway_ip}) cambió de MAC legítima {baseline_mac} a MAC sospechosa: {current_mac}."
                alert_callback(alert_msg, current_mac)
                
                # Fijación estática de entrada ARP de autoprotección si está activada
                if auto_fix and IS_WINDOWS:
                    try:
                        # Intentar fijar entrada estática con netsh
                        fix_cmd = f'netsh interface ip add neighbors "{adapter_name}" "{gateway_ip}" "{baseline_mac.replace(":", "-")}"'
                        subprocess.run(fix_cmd, capture_output=True, shell=True, creationflags=CREATE_NO_WINDOW)
                    except Exception:
                        pass
                        
            # Verificar si hay duplicados sospechosos en la salida de arp -a
            try:
                output = subprocess.check_output(["arp", "-a"], text=True, creationflags=CREATE_NO_WINDOW)
                lines = [l.strip() for l in output.splitlines() if gateway_ip in l]
                if len(lines) > 1:
                    alert_msg = f"¡ADVERTENCIA ARP! Se detectaron entradas duplicadas para la IP del Gateway {gateway_ip} en la tabla ARP."
                    alert_callback(alert_msg, current_mac)
            except Exception:
                pass
                
        except Exception as ex:
            pass
            
        # Esperar 2 segundos antes del siguiente sondeó
        for _ in range(20):
            if stop_event.is_set():
                break
            time.sleep(0.1)

def detect_evil_twin() -> list[dict]:
    """
    Ejecuta 'netsh wlan show networks mode=bssid' para auditar la presencia
    de redes clonadas (Evil Twin / Rogue AP) con SSIDs duplicados pero BSSIDs o autenticaciones distintas.
    """
    findings = []
    if not IS_WINDOWS:
        return findings
        
    try:
        res = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, creationflags=CREATE_NO_WINDOW, timeout=5.0)
        if res.returncode != 0 or not res.stdout:
            return findings
            
        output = res.stdout
        networks_map = {}
        current_ssid = None
        current_auth = "N/A"
        
        for line in output.splitlines():
            line_str = line.strip()
            if line_str.startswith("SSID"):
                parts = line_str.split(":", 1)
                if len(parts) == 2:
                    current_ssid = parts[1].strip()
                    if current_ssid and current_ssid not in networks_map:
                        networks_map[current_ssid] = []
            elif "Autenticación" in line_str or "Authentication" in line_str:
                parts = line_str.split(":", 1)
                if len(parts) == 2:
                    current_auth = parts[1].strip()
            elif line_str.startswith("BSSID"):
                parts = line_str.split(":", 1)
                if len(parts) == 2 and current_ssid:
                    bssid_val = format_mac(parts[1].strip())
                    networks_map[current_ssid].append({
                        "bssid": bssid_val,
                        "auth": current_auth,
                        "raw_line": line_str
                    })

        # Analizar clonación de SSIDs
        for ssid, bssid_list in networks_map.items():
            count = len(bssid_list)
            is_suspicious = False
            details_str = f"Detectados {count} BSSIDs para el SSID '{ssid}'."
            
            if count > 1:
                # Comprobar si hay variaciones en el esquema de seguridad entre los BSSIDs
                auths = set(b["auth"] for b in bssid_list)
                if len(auths) > 1:
                    is_suspicious = True
                    details_str = f"🚨 ALERTA CRÍTICA: Mismo SSID '{ssid}' emitiendo con diferentes niveles de seguridad ({', '.join(auths)}). Posible Evil Twin / Rogue AP."
                else:
                    details_str = f"⚠️ ATENCIÓN: Red Mesh o repetidores con múltiples BSSIDs ({count}). Verificar MACs legítimas."
                    
            for b in bssid_list:
                findings.append({
                    "ssid": ssid,
                    "bssid": b["bssid"],
                    "auth": b["auth"],
                    "bssids_count": count,
                    "is_suspicious": is_suspicious,
                    "status": "🚨 SOSPECHOSO (Evil Twin)" if is_suspicious else ("⚠️ Múltiple AP" if count > 1 else "✅ Normal"),
                    "details": details_str
                })
    except Exception as e:
        print(f"[SENTINEL] Error en detect_evil_twin: {e}")
        
    return findings

def _check_port(ip: str, port_info: dict) -> dict:
    port = port_info["port"]
    service = port_info["service"]
    risk = port_info["risk_if_open"]
    info = port_info["info"]
    
    is_open = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        res = s.connect_ex((ip, port))
        s.close()
        is_open = (res == 0)
    except Exception:
        is_open = False
        
    if is_open:
        status_str = "ABIERTO 🚨" if risk in ("CRÍTICO", "ALTO") else "ABIERTO"
        rec = f"Riesgo {risk}: {info} Se recomienda desactivar o aislar este puerto en el router."
    else:
        status_str = "CERRADO ✅"
        rec = f"Puerto seguro. {info}"
        risk = "SEGURO"
        
    return {
        "port": port,
        "service": service,
        "status": status_str,
        "is_open": is_open,
        "risk_level": risk,
        "recommendation": rec
    }

def audit_gateway_security(gateway_ip: str = None, progress_callback=None) -> list[dict]:
    """
    Audita los puertos críticos del router (21, 22, 23 Telnet, 80, 443, 445, 1900 UPnP, 5000, 8080).
    Retorna el diagnóstico de seguridad y recomendaciones de hardening.
    """
    if not gateway_ip:
        gateway_ip = get_gateway_ip()
        
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_check_port, gateway_ip, p) for p in CRITICAL_ROUTER_PORTS]
        for f in futures:
            try:
                res = f.result()
                results.append(res)
            except Exception:
                pass
                
    # Ordenar resultados por número de puerto
    results.sort(key=lambda x: x["port"])
    return results

def emergency_wifi_disconnect() -> tuple[bool, str]:
    """
    Ejecuta 'netsh wlan disconnect' y deshabilita la interfaz Wi-Fi ante una amenaza activa de ciberseguridad.
    """
    if not IS_WINDOWS:
        return False, "Comando no soportado en este sistema operativo."
        
    try:
        # 1. Desconectar de la red Wi-Fi actual
        res_disc = subprocess.run(["netsh", "wlan", "disconnect"], capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        
        # 2. Intentar deshabilitar la interfaz de red Wi-Fi
        wifi_info = get_wifi_interface_details()
        adapter_name = wifi_info.get("interface", "Wi-Fi")
        
        disable_cmd = f'netsh interface set interface name="{adapter_name}" admin=disable'
        res_dis = subprocess.run(disable_cmd, capture_output=True, text=True, shell=True, creationflags=CREATE_NO_WINDOW)
        
        msg = f"🛑 AISLAMIENTO WI-FI COMPLETADO: Se ejecutó la desconexión de red y se deshabilitó el adaptador '{adapter_name}'."
        return True, msg
    except Exception as e:
        return False, f"Excepción al ejecutar aislamiento Wi-Fi: {str(e)}"
