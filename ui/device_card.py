import os
import re
import json
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk

from ui.theme import (
    BG_CARD, BG_CARD_HOVER, TEXT_PRIMARY, TEXT_MUTED,
    ACCENT_CYAN, ACCENT_GREEN, ACCENT_RED, ACCENT_GOLD,
    COLOR_BORDER, COLOR_CARD_INNER, FONT_BADGE, FONT_BODY
)

ALIASES_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "device_aliases.json"
)

def load_device_aliases() -> dict:
    """Carga los alias personalizados de los dispositivos desde disco."""
    if os.path.exists(ALIASES_FILE):
        try:
            with open(ALIASES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_device_alias(mac: str, alias: str):
    """Guarda o actualiza un alias personalizado para una dirección MAC."""
    if not mac or mac == "N/A (Equipo Local)":
        return
    aliases = load_device_aliases()
    if alias.strip():
        aliases[mac.upper()] = alias.strip()
    else:
        aliases.pop(mac.upper(), None)
    try:
        os.makedirs(os.path.dirname(ALIASES_FILE), exist_ok=True)
        with open(ALIASES_FILE, "w", encoding="utf-8") as f:
            json.dump(aliases, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Error guardando alias: {e}")

    try:
        from core.device_inventory import set_alias as set_inv_alias
        set_inv_alias(mac, alias)
    except Exception:
        pass

def get_device_icon_and_category(device_type: str, vendor: str, hostname: str, is_gateway: bool, is_local: bool) -> tuple[str, str]:
    """Determina el icono y categoría estilizada del dispositivo."""
    if is_gateway or "router" in str(device_type).lower():
        return "🌐", "Router / Gateway"
    if is_local:
        return "💻", "PC Local (Este Equipo)"
        
    dtype_low = str(device_type).lower()
    vendor_low = str(vendor).lower()
    host_low = str(hostname).lower()
    
    if any(k in dtype_low for k in ["smartphone", "móvil", "movil", "phone"]) or any(k in vendor_low for k in ["apple", "samsung", "xiaomi", "motorola", "oppo", "vivo", "huawei"]):
        if any(pc in host_low for pc in ["pc", "laptop", "desktop", "macbook"]):
            return "💻", "PC / Portátil"
        return "📱", "Móvil / Smartphone"
        
    if any(k in dtype_low for k in ["pc", "notebook", "laptop", "desktop"]) or any(k in vendor_low for k in ["intel", "dell", "hp", "lenovo", "asus", "acer", "msi", "microsoft"]):
        return "💻", "PC / Computadora"
        
    if any(k in host_low or k in vendor_low for k in ["tv", "chromecast", "roku", "bravia", "smarttv", "lg electronics"]):
        return "📺", "Smart TV / Multimedia"
        
    if any(k in host_low or k in vendor_low for k in ["printer", "epson", "canon", "hp-print"]):
        return "🖨️", "Impresora de Red"
        
    if any(k in vendor_low for k in ["raspberry", "espressif", "tuya", "sonoff", "arduino"]):
        return "🔌", "IoT / Domótica"
        
    if any(k in vendor_low for k in ["cisco", "tp-link", "netgear", "d-link", "ubiquiti", "mikrotik"]):
        return "🖧", "Infraestructura de Red"
        
    return "🔌", "Dispositivo de Red"

def clean_vendor_name(vendor: str) -> str:
    """Simplifica el nombre del fabricante para la etiqueta badge sin recortar palabras."""
    v = str(vendor or "").strip()
    if not v or v.lower() in ["desconocido", "n/a", "no identificado", "interface local"]:
        return "Genérico"
    # Reemplazos y simplificaciones directas
    replacements = {
        "Apple, Inc.": "Apple",
        "Samsung Electronics": "Samsung",
        "Xiaomi Communications": "Xiaomi",
        "Motorola Mobility": "Motorola",
        "Intel Corporation": "Intel",
        "TP-Link Technologies": "TP-Link",
        "Realtek Semiconductor": "Realtek",
        "Huawei Technologies": "Huawei",
        "Cisco Systems": "Cisco",
        "Raspberry Pi Foundation": "Raspberry Pi",
        "LG Electronics": "LG",
        "Sony Corporation": "Sony",
        "Microsoft Corporation": "Microsoft",
        "Liteon Technology Corporation": "LiteOn",
        "Arcadyan Technology Corporation": "Arcadyan",
        "Sagemcom Broadband SAS": "Sagemcom",
        "ZTE Corporation": "ZTE"
    }
    for old, new in replacements.items():
        if old.lower() in v.lower():
            return new
            
    # Limpieza de sufijos corporativos sin recortar de forma arbitraria
    clean = re.sub(r",?\s*(Inc\.?|Corporation|Corp\.?|Ltd\.?|LLC|GmbH|SAS|Technologies|Technology)\b.*", "", v, flags=re.IGNORECASE).strip()
    return clean if clean else v

class DeviceCard(ctk.CTkFrame):
    """
    Tarjeta interactiva de dispositivo de red estilo Fing.
    Incluye icono temático, alias editable, detalles IP/MAC, badges de estado
    y fabricante, y botones de acción rápida.
    """
    def __init__(
        self,
        master,
        device: dict,
        is_blocked: bool = False,
        risk_level: str = "LOW",
        on_audit=None,
        on_isolate=None,
        on_copy=None,
        on_alias_saved=None,
        on_card_click=None,
        **kwargs
    ):
        super().__init__(
            master,
            fg_color=BG_CARD,
            corner_radius=12,
            border_width=1,
            border_color=COLOR_BORDER,
            **kwargs
        )
        self.device = device
        self.is_blocked = is_blocked
        self.risk_level = str(risk_level or "LOW").upper()
        self.on_audit = on_audit
        self.on_isolate = on_isolate
        self.on_copy = on_copy
        self.on_alias_saved = on_alias_saved
        self.on_card_click = on_card_click
        
        self.ip = device.get("ip", "")
        self.mac = device.get("mac", "")
        self.hostname = device.get("hostname", "Desconocido")
        self.vendor = device.get("vendor", "Desconocido")
        self.device_type = device.get("device_type", "Equipo")
        self.is_local = device.get("is_local", False)
        self.is_gateway = device.get("is_gateway", False)
        self.is_new = device.get("is_new", False)
        
        # Cargar alias si existe
        aliases = load_device_aliases()
        self.alias = device.get("alias") or aliases.get(self.mac.upper(), "")
        
        self._build_card()
        self._bind_hover_effects()

    def _build_card(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        icon, category = get_device_icon_and_category(
            self.device_type, self.vendor, self.hostname, self.is_gateway, self.is_local
        )
        vendor_short = clean_vendor_name(self.vendor)
        
        # Priorizar siempre rol de Red para la Puerta de Enlace (Router)
        if self.is_gateway:
            category = "Router / Gateway"
            if any(k in str(self.vendor).lower() for k in ["móvil", "movil", "mac privada", "smartphone"]):
                self.vendor = "Router / Gateway"
                vendor_short = "Router"
            elif vendor_short == "Genérico":
                vendor_short = "Router"
        
        # 1. ICONO DEL DISPOSITIVO (Contenedor cuadrado redondeado)
        icon_bg = ("#e0f2fe", "#0f2338") if self.is_local else COLOR_CARD_INNER
        icon_frame = ctk.CTkFrame(self, width=50, height=50, corner_radius=10, fg_color=icon_bg)
        icon_frame.grid(row=0, column=0, padx=(14, 12), pady=12, sticky="ns")
        icon_frame.grid_propagate(False)
        
        lbl_icon = ctk.CTkLabel(
            icon_frame, text=icon, font=("Segoe UI Emoji", 22)
        )
        lbl_icon.place(relx=0.5, rely=0.5, anchor="center")
        
        # 2. INFORMACIÓN CENTRAL
        info_frame = ctk.CTkFrame(self, fg_color="transparent")
        info_frame.grid(row=0, column=1, padx=(0, 10), pady=10, sticky="nsew")
        info_frame.grid_columnconfigure(0, weight=1)
        self.info_frame = info_frame
        
        # Fila 1: Título principal (Alias o Hostname) + Badges
        top_row = ctk.CTkFrame(info_frame, fg_color="transparent")
        top_row.pack(fill="x", expand=True, anchor="w", pady=(0, 3))
        
        display_title = self.alias if self.alias else (
            self.hostname if self.hostname and self.hostname != "Desconocido" else f"Dispositivo ({self.ip})"
        )
        if self.is_gateway and not self.alias:
            display_title = "Puerta de Enlace (Router)"
            
        self.lbl_title = ctk.CTkLabel(
            top_row, text=display_title, font=("Segoe UI", 12, "bold"), text_color=TEXT_PRIMARY, anchor="w"
        )
        self.lbl_title.pack(side="left", padx=(0, 6))
        
        # Botón de edición de alias (lápiz)
        self.btn_edit_alias = ctk.CTkButton(
            top_row, text="✏️", width=22, height=22, font=("Segoe UI", 10),
            fg_color="transparent", hover_color=BG_CARD_HOVER, text_color=TEXT_MUTED,
            command=self._prompt_edit_alias
        )
        self.btn_edit_alias.pack(side="left", padx=(0, 6))
        
        # Badge de Fabricante con auto-ajuste y padding holgado
        badge_vendor = ctk.CTkLabel(
            top_row, text=f"🏷️ {vendor_short}", font=FONT_BADGE,
            fg_color=("#e2e8f0", "#1e293b"), text_color=TEXT_PRIMARY,
            corner_radius=6, height=24, padx=10, pady=2
        )
        badge_vendor.pack(side="left", padx=(0, 6))
        
        # Badge de Estado con auto-ajuste y padding holgado
        if self.is_local:
            status_text = "💻 Host Local / Tu PC"
            status_bg = ("#cffafe", "#083344")
            status_fg = ACCENT_CYAN
        elif self.is_blocked:
            status_text = "🚫 Bloqueado"
            status_bg = ("#fee2e2", "#450a0a")
            status_fg = ACCENT_RED
        elif self.is_gateway:
            status_text = "🌐 Gateway Activo"
            status_bg = ("#fef3c7", "#78350f")
            status_fg = ("#92400e", "#fde68a")
        else:
            status_text = "● En Línea"
            status_bg = ("#dcfce7", "#052e16")
            status_fg = ACCENT_GREEN
            
        self.badge_status = ctk.CTkLabel(
            top_row, text=status_text, font=FONT_BADGE,
            fg_color=status_bg, text_color=status_fg,
            corner_radius=6, height=24, padx=10, pady=2
        )
        self.badge_status.pack(side="left", padx=(0, 6))
        
        # Badge de Riesgo de red (Threat Intelligence / Risk Engine)
        risk_badge_cfg = {
            "CRITICAL": ("🚨 CRÍTICO", ("#fee2e2", "#450a0a"), ACCENT_RED),
            "HIGH": ("⚠️ RIESGO ALTO", ("#fee2e2", "#450a0a"), ACCENT_RED),
            "MEDIUM": ("🟡 RIESGO MEDIO", ("#fef3c7", "#78350f"), ACCENT_GOLD),
            "LOW": ("🛡️ RIESGO BAJO", ("#dcfce7", "#052e16"), ACCENT_GREEN),
        }
        risk_text, risk_bg, risk_fg = risk_badge_cfg.get(self.risk_level, risk_badge_cfg["LOW"])
        self.badge_risk = ctk.CTkLabel(
            top_row, text=risk_text, font=FONT_BADGE,
            fg_color=risk_bg, text_color=risk_fg,
            corner_radius=6, height=24, padx=10, pady=2
        )
        self.badge_risk.pack(side="left", padx=(0, 6))

        # Badge de Dispositivo Nuevo detectado por el inventario
        if self.is_new:
            badge_new = ctk.CTkLabel(
                top_row, text="⚠️ NUEVO", font=FONT_BADGE,
                fg_color=("#fee2e2", "#450a0a"), text_color=ACCENT_RED,
                corner_radius=6, height=24, padx=10, pady=2
            )
            badge_new.pack(side="left", padx=(0, 6))
        
        # Fila 2: Subtítulo con IP, MAC, y Tipo
        sub_row = ctk.CTkFrame(info_frame, fg_color="transparent")
        sub_row.pack(fill="x", expand=True, anchor="w")
        
        sub_text = f"IP: {self.ip}   •   MAC: {self.mac}   •   Categoría: {category}"
        if self.alias and self.hostname and self.hostname != "Desconocido":
            sub_text += f"   •   Host: {self.hostname}"
            
        lbl_subtitle = ctk.CTkLabel(
            sub_row, text=sub_text, font=("Segoe UI", 10), text_color=TEXT_MUTED, anchor="w"
        )
        lbl_subtitle.pack(side="left")
        
        # 3. BOTONES DE ACCIÓN RÁPIDA (Derecha)
        actions_frame = ctk.CTkFrame(self, fg_color="transparent")
        actions_frame.grid(row=0, column=2, padx=(0, 14), pady=10, sticky="e")
        
        # Botón Copiar IP/MAC
        self.btn_copy = ctk.CTkButton(
            actions_frame, text="📋 Copiar", width=80, height=28, font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY,
            border_width=1, border_color=COLOR_BORDER, command=self._on_copy_clicked
        )
        self.btn_copy.pack(side="left", padx=4)
        
        # Botón Auditar Puertos
        self.btn_audit = ctk.CTkButton(
            actions_frame, text="🔍 Auditar Puertos", width=115, height=28, font=("Segoe UI", 9, "bold"),
            fg_color=ACCENT_CYAN, hover_color=("#0891b2", "#0e7490"), text_color="#ffffff",
            command=self._on_audit_clicked
        )
        self.btn_audit.pack(side="left", padx=4)
        
        # Botón Aislar en Firewall
        if self.is_blocked:
            isolate_txt = "✅ Desbloquear"
            isolate_bg = ("#dcfce7", "#052e16")
            isolate_fg = ACCENT_GREEN
            isolate_hover = ("#bbf7d0", "#14532d")
        else:
            isolate_txt = "🚫 Aislar en Firewall"
            isolate_bg = ("#fee2e2", "#3b1111")
            isolate_fg = ACCENT_RED
            isolate_hover = ("#fecaca", "#4c1d1d")
            
        self.btn_isolate = ctk.CTkButton(
            actions_frame, text=isolate_txt, width=125, height=28, font=("Segoe UI", 9, "bold"),
            fg_color=isolate_bg, hover_color=isolate_hover, text_color=isolate_fg,
            command=self._on_isolate_clicked
        )
        if not self.is_local:
            self.btn_isolate.pack(side="left", padx=4)

        # Vincular el evento de clic en todos los contenedores de la tarjeta
        for w in (self, icon_frame, info_frame, top_row, sub_row, actions_frame):
            try:
                w.bind("<Button-1>", self._on_card_click)
            except Exception:
                pass

    def _bind_hover_effects(self):
        """Añade efecto hover sutil al pasar el cursor sobre la tarjeta."""
        def on_enter(e):
            self.configure(border_color=ACCENT_CYAN, fg_color=BG_CARD_HOVER)
        def on_leave(e):
            self.configure(border_color=COLOR_BORDER, fg_color=BG_CARD)
            
        self.bind("<Enter>", on_enter)
        self.bind("<Leave>", on_leave)

    def _on_card_click(self, event):
        """Notifica al contenedor que se clickeó la tarjeta para abrir el detalle."""
        if self.on_card_click:
            self.on_card_click(self.device, self.is_blocked)

    def _prompt_edit_alias(self):
        """Muestra un modal o diálogo para editar el alias amigable del dispositivo."""
        dialog = ctk.CTkInputDialog(
            text=f"Introduce un alias o nombre descriptivo para {self.ip} ({self.mac}):\n(Deja vacío para usar el nombre de host original)",
            title="Editar Alias de Dispositivo"
        )
        # Centrar diálogo sobre el widget principal
        try:
            dialog.geometry("+%d+%d" % (self.winfo_rootx() + 50, self.winfo_rooty() + 20))
        except Exception:
            pass
            
        new_alias = dialog.get_input()
        if new_alias is not None:
            clean_alias = new_alias.strip()
            save_device_alias(self.mac, clean_alias)
            self.alias = clean_alias
            
            display_title = self.alias if self.alias else (
                self.hostname if self.hostname and self.hostname != "Desconocido" else f"Dispositivo ({self.ip})"
            )
            self.lbl_title.configure(text=display_title)
            
            if self.on_alias_saved:
                self.on_alias_saved(self.mac, clean_alias)

    def _on_copy_clicked(self):
        """Copia la IP y MAC al portapapeles y da feedback visual."""
        clipboard_text = f"IP: {self.ip} | MAC: {self.mac}"
        try:
            self.clipboard_clear()
            self.clipboard_append(clipboard_text)
            self.update()
        except Exception:
            pass
            
        # Feedback temporal
        self.btn_copy.configure(text="✓ Copiado", text_color=ACCENT_GREEN)
        self.after(1600, lambda: self.btn_copy.configure(text="📋 Copiar", text_color=TEXT_PRIMARY))
        
        if self.on_copy:
            self.on_copy(clipboard_text, self.ip)

    def _on_audit_clicked(self):
        if self.on_audit:
            self.on_audit(self.ip)

    def _on_isolate_clicked(self):
        if self.on_isolate:
            self.on_isolate(self.ip, self.alias or self.hostname, self.is_blocked)
