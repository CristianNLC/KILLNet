import os
import sys
import re
import socket
import subprocess
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor

IS_WINDOWS = sys.platform.startswith("win")
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# Cache en memoria para OUI de fabricantes
VENDOR_CACHE: dict[str, str] = {}

# Diccionario offline básico de fabricantes conocidos (OUI Prefix 6/8 caracteres en mayúsculas)
OFFLINE_VENDORS = {
    # Apple
    "00:03:93": "Apple, Inc.", "00:05:02": "Apple, Inc.", "00:0A:27": "Apple, Inc.",
    "00:0C:29": "Apple, Inc.", "00:1C:B3": "Apple, Inc.", "00:23:12": "Apple, Inc.",
    "00:25:00": "Apple, Inc.", "00:26:08": "Apple, Inc.", "00:26:BB": "Apple, Inc.",
    "00:50:56": "VMware / Apple", "AC:BC:32": "Apple, Inc.", "D8:9E:3F": "Apple, Inc.",
    "F4:D4:88": "Apple, Inc.", "BC:D2:95": "Apple, Inc.", "A4:83:E7": "Apple, Inc.",
    # Samsung
    "00:07:AB": "Samsung Electronics", "00:12:FB": "Samsung Electronics",
    "00:15:99": "Samsung Electronics", "00:1A:8A": "Samsung Electronics",
    "00:21:D1": "Samsung Electronics", "00:23:D7": "Samsung Electronics",
    "18:3B:D2": "Samsung Electronics", "28:18:78": "Samsung Electronics",
    "7C:91:22": "Samsung Electronics", "B0:C4:E7": "Samsung Electronics",
    "E4:E7:C5": "Samsung Electronics", "50:85:69": "Samsung Electronics",
    # Xiaomi
    "00:EC:0A": "Xiaomi Communications", "18:59:36": "Xiaomi Communications",
    "28:6C:07": "Xiaomi Communications", "34:80:B3": "Xiaomi Communications",
    "64:09:80": "Xiaomi Communications", "74:23:44": "Xiaomi Communications",
    "AC:F7:F3": "Xiaomi Communications", "C8:D3:FF": "Xiaomi Communications",
    "D4:F5:47": "Xiaomi Communications", "F4:60:E2": "Xiaomi Communications",
    # Motorola
    "00:0A:28": "Motorola Mobility", "00:0C:E5": "Motorola Mobility",
    "00:14:9A": "Motorola Mobility", "00:1E:5A": "Motorola Mobility",
    "00:24:7E": "Motorola Mobility", "00:26:5F": "Motorola Mobility",
    "04:4B:ED": "Motorola Mobility", "68:C4:4D": "Motorola Mobility",
    "E0:75:0A": "Motorola Mobility", "F8:CF:C5": "Motorola Mobility",
    # Intel
    "00:02:B3": "Intel Corporation", "00:03:47": "Intel Corporation",
    "00:04:23": "Intel Corporation", "00:0E:0C": "Intel Corporation",
    "00:13:02": "Intel Corporation", "00:1B:21": "Intel Corporation",
    "00:1E:64": "Intel Corporation", "00:21:6B": "Intel Corporation",
    "00:22:FB": "Intel Corporation", "00:27:0E": "Intel Corporation",
    "3C:FD:FE": "Intel Corporation", "80:86:F2": "Intel Corporation",
    # Realtek / Raspberry Pi
    "00:00:21": "Realtek Semiconductor", "00:07:40": "Realtek Semiconductor",
    "00:10:A4": "Realtek Semiconductor", "00:1A:4D": "Realtek Semiconductor",
    "00:24:1D": "Realtek Semiconductor", "00:E0:4C": "Realtek Semiconductor",
    "10:7B:44": "Realtek Semiconductor", "40:16:9F": "Realtek Semiconductor",
    "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    # TP-Link
    "00:0A:EB": "TP-Link Technologies", "00:14:78": "TP-Link Technologies",
    "00:19:66": "TP-Link Technologies", "00:1D:0F": "TP-Link Technologies",
    "00:21:27": "TP-Link Technologies", "00:23:CD": "TP-Link Technologies",
    "00:27:19": "TP-Link Technologies", "14:CF:92": "TP-Link Technologies",
    "50:C7:BF": "TP-Link Technologies", "74:EA:3A": "TP-Link Technologies",
    "98:DA:C4": "TP-Link Technologies", "A0:F3:C1": "TP-Link Technologies",
    "C0:25:E9": "TP-Link Technologies", "E8:94:F6": "TP-Link Technologies",
    # Cisco
    "00:00:0C": "Cisco Systems", "00:01:42": "Cisco Systems",
    "00:01:43": "Cisco Systems", "00:01:96": "Cisco Systems",
    "00:01:C7": "Cisco Systems", "00:02:16": "Cisco Systems",
    "00:02:4B": "Cisco Systems", "00:02:7D": "Cisco Systems",
    "00:02:FC": "Cisco Systems", "00:03:31": "Cisco Systems",
    "00:03:6B": "Cisco Systems", "00:03:E3": "Cisco Systems",
    # Huawei
    "00:0B:45": "Huawei Technologies", "00:0E:5E": "Huawei Technologies",
    "00:18:82": "Huawei Technologies", "00:1E:10": "Huawei Technologies",
    "00:22:A1": "Huawei Technologies", "00:25:9E": "Huawei Technologies",
    "00:46:4B": "Huawei Technologies", "04:F9:38": "Huawei Technologies",
    "08:63:61": "Huawei Technologies", "20:F3:A3": "Huawei Technologies",
    "48:46:FB": "Huawei Technologies", "70:54:F5": "Huawei Technologies"
}

def get_local_ip() -> str:
    """Detecta la IP local activa abriendo un socket UDP a 8.8.8.8."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_gateway_ip(local_ip: str) -> str:
    """Intenta determinar la IP de la puerta de enlace (Gateway)."""
    parts = local_ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    return "192.168.1.1"

def get_subnet_ips(local_ip: str) -> list[str]:
    """Genera la lista de direcciones IP de la subred /24 local."""
    if not local_ip or local_ip.startswith("127."):
        return []
    try:
        ip_obj = ipaddress.ip_interface(f"{local_ip}/24")
        return [str(ip) for ip in ip_obj.network.hosts()]
    except Exception:
        parts = local_ip.split(".")
        if len(parts) == 4:
            base = ".".join(parts[:3])
            return [f"{base}.{i}" for i in range(1, 255)]
        return []

def _ping_ip(ip: str):
    """Envía un ping corto (150ms timeout) sin ventana para refrescar la tabla ARP de Windows."""
    try:
        if IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", "150", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
            
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW if IS_WINDOWS else 0,
            timeout=0.6
        )
    except Exception:
        pass

def refresh_arp_table(ips: list[str]):
    """Ejecuta barrido rápido concurrente con ThreadPoolExecutor(max_workers=50)."""
    with ThreadPoolExecutor(max_workers=50) as executor:
        list(executor.map(_ping_ip, ips))

def format_mac(mac_raw: str) -> str:
    """Normaliza la dirección MAC al formato XX:XX:XX:XX:XX:XX en mayúsculas."""
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac_raw).upper()
    if len(clean) == 12:
        return ":".join(clean[i:i+2] for i in range(0, 12, 2))
    return mac_raw.upper().replace("-", ":")

def is_random_private_mac(mac: str) -> bool:
    """
    Verifica si la MAC utiliza un bit de administración local (MAC privada/aleatoria).
    El bit de administración local está en la posición 1 del primer octeto (0x02).
    Los caracteres hex finales del primer byte son 2, 6, A, E.
    """
    try:
        clean_mac = format_mac(mac)
        first_byte_hex = clean_mac.split(":")[0]
        first_byte_val = int(first_byte_hex, 16)
        return (first_byte_val & 0x02) != 0
    except Exception:
        return False

def lookup_mac_vendor(mac: str, is_private_mac: bool = False) -> str:
    """
    Identifica el fabricante por OUI con caché en memoria y fallback
    a diccionario offline y api.macvendors.com con timeout estricto.
    """
    if is_private_mac:
        return "Móvil (MAC Privada / Aleatoria)"
        
    formatted = format_mac(mac)
    prefix = formatted[:8]  # "XX:XX:XX"
    
    if prefix in VENDOR_CACHE:
        return VENDOR_CACHE[prefix]
        
    # Búsqueda en diccionario offline
    offline_match = OFFLINE_VENDORS.get(prefix)
    if offline_match:
        VENDOR_CACHE[prefix] = offline_match
        return offline_match
        
    # Consulta externa de fallback a api.macvendors.com
    try:
        res = requests.get(f"https://api.macvendors.com/{formatted}", timeout=1.5)
        if res.status_code == 200 and res.text:
            vendor = res.text.strip()
            VENDOR_CACHE[prefix] = vendor
            return vendor
    except Exception:
        pass
        
    fallback = "Fabricante Desconocido"
    VENDOR_CACHE[prefix] = fallback
    return fallback

def resolve_hostname(ip: str) -> str:
    """Obtiene el nombre de host DNS/NetBIOS con timeout corto."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(0.4)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return "Desconocido"
    finally:
        socket.setdefaulttimeout(old_timeout)

def estimate_device_type(ip: str, mac: str, vendor: str, hostname: str, is_local: bool, gateway_ip: str) -> str:
    """Clasifica el tipo de dispositivo estimado según patrones de IP, MAC y Fabricante."""
    if is_local:
        return "PC / Notebook"
    if ip == gateway_ip or ip.endswith(".1") or ip.endswith(".254"):
        return "Router / Access Point"
        
    vendor_lower = vendor.lower()
    host_lower = hostname.lower()
    
    if "mac privada" in vendor_lower or "móvil" in vendor_lower:
        return "Smartphone / Móvil"
        
    mobile_vendors = ["apple", "samsung", "xiaomi", "motorola", "huawei", "oppo", "vivo", "realme", "oneplus"]
    pc_vendors = ["intel", "realtek", "dell", "hp", "lenovo", "asus", "acer", "msi", "gigabyte", "microsoft"]
    network_vendors = ["cisco", "tp-link", "netgear", "mikrotik", "ubiquiti", "d-link", "tenda", "technicolor", "zte"]
    
    if any(v in vendor_lower for v in network_vendors):
        return "Router / Access Point"
        
    if any(v in vendor_lower for v in mobile_vendors):
        if any(pc_term in host_lower for pc_term in ["pc", "laptop", "desktop", "win", "macbook"]):
            return "PC / Notebook"
        return "Smartphone / Móvil"
        
    if any(v in vendor_lower for v in pc_vendors) or any(pc_term in host_lower for pc_term in ["pc", "laptop", "desktop", "win", "macbook", "workstation"]):
        return "PC / Notebook"
        
    return "Equipo de Red"

def scan_lan_devices() -> list[dict]:
    """
    Escanea la subred local, refresca la tabla ARP, parsea dispositivos activos
    y retorna la información estructurada de cada uno.
    """
    local_ip = get_local_ip()
    gateway_ip = get_gateway_ip(local_ip)
    subnet_ips = get_subnet_ips(local_ip)
    
    # 1. Refrescar tabla ARP mediante ping sweep
    if subnet_ips:
        refresh_arp_table(subnet_ips)
        
    devices = []
    found_ips = set()
    
    # 2. Leer salida de arp -a
    try:
        output = subprocess.check_output(
            ["arp", "-a"],
            text=True,
            creationflags=CREATE_NO_WINDOW if IS_WINDOWS else 0
        )
    except Exception:
        output = ""
        
    # Regex para extraer IP y MAC de arp -a
    arp_pattern = re.compile(
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2})"
    )

    for line in output.splitlines():
        match = arp_pattern.search(line)
        if not match:
            continue
            
        ip, mac_raw = match.group(1), match.group(2)
        
        # Ignorar IPs de multicast / broadcast o inválidas
        if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255") or ip == "255.255.255.255":
            continue
            
        mac = format_mac(mac_raw)
        if mac.lower() == "ff:ff:ff:ff:ff:ff":
            continue
            
        found_ips.add(ip)
        is_local = (ip == local_ip)
        is_private_mac = is_random_private_mac(mac)
        vendor = lookup_mac_vendor(mac, is_private_mac=is_private_mac)
        hostname = resolve_hostname(ip)
        device_type = estimate_device_type(ip, mac, vendor, hostname, is_local, gateway_ip)
        
        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "device_type": device_type,
            "is_local": is_local,
            "is_private_mac": is_private_mac,
            "is_gateway": (ip == gateway_ip)
        })

    # Si la IP local no apareció en arp -a, añadirla explícitamente
    if local_ip not in found_ips and local_ip != "127.0.0.1":
        hostname = resolve_hostname(local_ip)
        devices.append({
            "ip": local_ip,
            "mac": "N/A (Equipo Local)",
            "hostname": hostname,
            "vendor": "Interface Local",
            "device_type": "PC / Notebook",
            "is_local": True,
            "is_private_mac": False,
            "is_gateway": False
        })
        
    return devices
