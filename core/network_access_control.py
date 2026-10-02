import os
import sys
import json
import subprocess

IS_WINDOWS = sys.platform.startswith("win")
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "access_rules.json"
)

def load_access_rules() -> dict:
    """Carga la configuración de control de acceso desde data/access_rules.json."""
    if os.path.exists(RULES_PATH):
        try:
            with open(RULES_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "mode" in data and "devices" in data:
                    return data
        except Exception:
            pass
            
    # Estructura por defecto
    default_data = {
        "mode": "blacklist",
        "devices": []
    }
    save_access_rules(default_data)
    return default_data

def save_access_rules(rules_dict: dict) -> bool:
    """Guarda las reglas de control de acceso en data/access_rules.json."""
    try:
        os.makedirs(os.path.dirname(RULES_PATH), exist_ok=True)
        with open(RULES_PATH, "w", encoding="utf-8") as f:
            json.dump(rules_dict, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[ERROR] No se pudo guardar access_rules.json: {e}")
        return False

def set_access_control_mode(mode: str) -> bool:
    """Establece el modo de control de acceso ('blacklist' o 'whitelist')."""
    if mode not in ("blacklist", "whitelist"):
        return False
    rules = load_access_rules()
    rules["mode"] = mode
    return save_access_rules(rules)

def block_ip_host(ip: str, alias: str = "") -> tuple[bool, str]:
    """
    Aplica regla de bloqueo en el Firewall de Windows para entrada y salida
    usando netsh advfirewall.
    """
    if not ip or ip in ("-", "*", "127.0.0.1", "0.0.0.0"):
        return False, "No se puede bloquear una IP local, nula o de loopback."
        
    rule_name = f"KILLNet_Block_{ip.replace(':', '_')}"
    
    # Crear reglas de entrada y salida
    cmd_in = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f'name="{rule_name}"',
        "dir=in",
        "action=block",
        f"remoteip={ip}"
    ]
    cmd_out = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f'name="{rule_name}"',
        "dir=out",
        "action=block",
        f"remoteip={ip}"
    ]
    
    try:
        res_in = subprocess.run(
            " ".join(cmd_in),
            capture_output=True,
            text=True,
            shell=True,
            creationflags=CREATE_NO_WINDOW if IS_WINDOWS else 0
        )
        res_out = subprocess.run(
            " ".join(cmd_out),
            capture_output=True,
            text=True,
            shell=True,
            creationflags=CREATE_NO_WINDOW if IS_WINDOWS else 0
        )
        
        if res_in.returncode == 0 and res_out.returncode == 0:
            alias_str = f" ({alias})" if alias else ""
            return True, f"Reglas de Firewall de Windows creadas (In/Out): Tráfico con IP {ip}{alias_str} bloqueado."
        else:
            err = res_in.stderr.strip() or res_out.stderr.strip() or res_in.stdout.strip()
            return False, f"Error netsh advfirewall ({err}). ¿Faltan permisos de Administrador?"
    except Exception as e:
        return False, f"Excepción al ejecutar comando netsh: {str(e)}"

def unblock_ip_host(ip: str) -> tuple[bool, str]:
    """Remueve las reglas de cortafuegos asociadas a la IP especificada."""
    if not ip or ip in ("-", "*", "127.0.0.1", "0.0.0.0"):
        return False, "IP no válida para desbloquear."
        
    rule_name = f"KILLNet_Block_{ip.replace(':', '_')}"
    cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f'name="{rule_name}"'
    ]
    
    try:
        res = subprocess.run(
            " ".join(cmd),
            capture_output=True,
            text=True,
            shell=True,
            creationflags=CREATE_NO_WINDOW if IS_WINDOWS else 0
        )
        if res.returncode == 0:
            return True, f"Regla de Firewall eliminada para la IP {ip}."
        else:
            err = res.stderr.strip() or res.stdout.strip()
            return False, f"Error al eliminar regla Firewall: {err}"
    except Exception as e:
        return False, f"Excepción al remover regla: {str(e)}"

def add_or_update_device_rule(mac: str, ip: str, alias: str, status: str) -> tuple[bool, str]:
    """Añade o actualiza una regla de dispositivo en access_rules.json y gestiona Firewall si aplica."""
    if status not in ("allowed", "blocked"):
        return False, "Estado inválido. Debe ser 'allowed' o 'blocked'."
        
    rules = load_access_rules()
    devices = rules.get("devices", [])
    
    mac_clean = mac.strip().upper()
    ip_clean = ip.strip()
    
    # Buscar si ya existe por MAC o por IP
    existing = None
    for d in devices:
        if (mac_clean and mac_clean != "N/A" and d.get("mac", "").upper() == mac_clean) or (ip_clean and d.get("ip") == ip_clean):
            existing = d
            break
            
    if existing:
        existing["mac"] = mac_clean
        existing["ip"] = ip_clean
        existing["alias"] = alias or existing.get("alias", "")
        existing["status"] = status
    else:
        devices.append({
            "mac": mac_clean,
            "ip": ip_clean,
            "alias": alias or "Dispositivo",
            "status": status
        })
        
    rules["devices"] = devices
    save_access_rules(rules)
    
    # Aplicar o remover regla en el Firewall si se especificó una IP
    if ip_clean and ip_clean not in ("-", "*", "127.0.0.1", "0.0.0.0"):
        if status == "blocked":
            block_ip_host(ip_clean, alias)
        else:
            unblock_ip_host(ip_clean)
            
    return True, f"Dispositivo '{alias or mac_clean}' guardado como '{status.upper()}'."

def remove_device_rule(mac_or_ip: str) -> tuple[bool, str]:
    """Elimina una regla de dispositivo de la lista y libera su cortafuegos si estaba bloqueado."""
    rules = load_access_rules()
    devices = rules.get("devices", [])
    target = mac_or_ip.strip().upper()
    
    new_devices = []
    removed_device = None
    for d in devices:
        if d.get("mac", "").upper() == target or d.get("ip", "").upper() == target:
            removed_device = d
        else:
            new_devices.append(d)
            
    if not removed_device:
        return False, "Dispositivo no encontrado en las reglas."
        
    rules["devices"] = new_devices
    save_access_rules(rules)
    
    # Si estaba bloqueado por IP, remover regla de firewall
    ip = removed_device.get("ip")
    if ip and ip not in ("-", "*", "127.0.0.1", "0.0.0.0"):
        unblock_ip_host(ip)
        
    return True, f"Regla removida para '{removed_device.get('alias', target)}'."

def is_device_allowed(mac: str, ip: str) -> tuple[bool, str]:
    """
    Verifica si un dispositivo cumple con la política activa (blacklist/whitelist).
    """
    rules = load_access_rules()
    mode = rules.get("mode", "blacklist")
    devices = rules.get("devices", [])
    
    mac_clean = mac.strip().upper()
    ip_clean = ip.strip()
    
    matched_device = None
    for d in devices:
        d_mac = d.get("mac", "").upper()
        d_ip = d.get("ip", "")
        if (mac_clean and mac_clean != "N/A" and d_mac == mac_clean) or (ip_clean and d_ip == ip_clean):
            matched_device = d
            break
            
    if mode == "blacklist":
        if matched_device and matched_device.get("status") == "blocked":
            return False, f"Bloqueado por Blacklist (Regla: {matched_device.get('alias', 'Sin Alias')})"
        return True, "Permitido (Política Blacklist activa)"
    else:  # mode == "whitelist"
        if matched_device and matched_device.get("status") == "allowed":
            return True, f"Autorizado en Whitelist ({matched_device.get('alias', 'Sin Alias')})"
        return False, "Bloqueado por Whitelist (No figura como autorizado)"
