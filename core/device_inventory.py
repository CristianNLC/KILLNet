import os
import re
import json
import datetime

from core.paths import data_path

INVENTORY_FILE = data_path("known_devices.json")

def normalize_mac(mac: str) -> str:
    """Normaliza cualquier dirección MAC a formato estándar XX:XX:XX:XX:XX:XX."""
    if not mac or "N/A" in str(mac).upper():
        return ""
    clean = re.sub(r"[^0-9A-Fa-f]", "", str(mac)).upper()
    if len(clean) == 12:
        return ":".join(clean[i:i+2] for i in range(0, 12, 2))
    return str(mac).strip().upper()

def load_inventory() -> dict:
    """
    Carga de forma segura el inventario de dispositivos conocidos desde data/known_devices.json.
    Maneja excepciones de JSON corrupto o archivo inexistente.
    """
    if os.path.exists(INVENTORY_FILE):
        try:
            with open(INVENTORY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except (json.JSONDecodeError, OSError, Exception):
            pass
    return {}

def save_inventory(inventory: dict):
    """Guarda atómicamente el inventario de dispositivos en data/known_devices.json."""
    try:
        os.makedirs(os.path.dirname(INVENTORY_FILE), exist_ok=True)
        tmp_file = INVENTORY_FILE + ".tmp"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(inventory, f, indent=2, ensure_ascii=False)
        if os.path.exists(INVENTORY_FILE):
            os.replace(tmp_file, INVENTORY_FILE)
        else:
            os.rename(tmp_file, INVENTORY_FILE)
    except Exception as e:
        # Fallback a guardado directo
        try:
            with open(INVENTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(inventory, f, indent=2, ensure_ascii=False)
        except Exception as ex:
            print(f"[INVENTORY] Error guardando inventario: {ex}")

def process_devices(devices_list: list[dict]) -> list[dict]:
    """
    Recibe la lista de diccionarios detectados en el barrido ARP/LAN.
    Para cada host:
      - Si la MAC no existe en known_devices.json: la registra con la marca de tiempo actual,
        guarda sus datos y añade 'is_new: True' al diccionario del dispositivo para la UI.
      - Si la MAC ya existe: actualiza 'last_seen' y 'last_ip', preservando el alias previo
        y marcando 'is_new: False'.
    Retorna la lista de dispositivos procesada.
    """
    if not isinstance(devices_list, list):
        return devices_list

    inventory = load_inventory()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    modified = False

    for dev in devices_list:
        raw_mac = dev.get("mac", "")
        norm_mac = normalize_mac(raw_mac)
        
        # Si no tiene MAC válida o es un host local sin MAC física resoluble
        if not norm_mac:
            dev["is_new"] = False
            continue

        ip = dev.get("ip", "")
        vendor = dev.get("vendor", "Desconocido")
        alias = dev.get("alias", "")

        if norm_mac not in inventory:
            # Nuevo dispositivo descubierto en la red
            dev["is_new"] = True
            inventory[norm_mac] = {
                "first_seen": now_str,
                "last_seen": now_str,
                "alias": alias,
                "vendor": vendor,
                "last_ip": ip
            }
            modified = True
        else:
            # Dispositivo previamente conocido
            dev["is_new"] = False
            rec = inventory[norm_mac]
            rec["last_seen"] = now_str
            rec["last_ip"] = ip
            if not rec.get("vendor") or rec.get("vendor") == "Desconocido":
                if vendor and vendor != "Desconocido":
                    rec["vendor"] = vendor
            # Sincronizar alias si existe en el inventario
            if rec.get("alias") and not dev.get("alias"):
                dev["alias"] = rec["alias"]
            elif dev.get("alias") and dev["alias"] != rec.get("alias"):
                rec["alias"] = dev["alias"]
            modified = True

    if modified:
        save_inventory(inventory)

    return devices_list

def set_alias(mac: str, new_alias: str):
    """Actualiza el alias de un dispositivo en known_devices.json."""
    norm_mac = normalize_mac(mac)
    if not norm_mac:
        return
        
    inventory = load_inventory()
    clean_alias = new_alias.strip() if new_alias else ""
    
    if norm_mac in inventory:
        inventory[norm_mac]["alias"] = clean_alias
    else:
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        inventory[norm_mac] = {
            "first_seen": now_str,
            "last_seen": now_str,
            "alias": clean_alias,
            "vendor": "Desconocido",
            "last_ip": ""
        }
    save_inventory(inventory)
