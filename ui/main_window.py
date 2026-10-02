import os
import sys
import time
import datetime
import threading
import json
import csv
import webbrowser
import requests
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk

# Módulos Core de KILLNet
from core.network_monitor import get_active_connections
from core.ip_reputation import lookup_ip
from core.network_blocker import is_admin, kill_process_by_pid, block_remote_ip, toggle_panic_mode
from core.lan_scanner import scan_lan_devices, get_local_ip
from core.network_access_control import (
    load_access_rules, set_access_control_mode, block_ip_host, unblock_ip_host,
    add_or_update_device_rule, remove_device_rule, is_device_allowed
)
from core.restriction_checker import (
    run_restriction_diagnostics, check_hosts_file, clean_hosts_file,
    apply_secure_dns, reset_dns_dhcp, get_active_network_adapter
)
from core.wifi_sentinel import (
    get_gateway_info, start_arp_guard, detect_evil_twin,
    audit_gateway_security, emergency_wifi_disconnect
)
from core.security_auditor import (
    scan_device_security, audit_cleartext_protocols, isolate_host_local_firewall
)

from ui.theme import (
    COLOR_BG, COLOR_BG_DARK, COLOR_SIDEBAR, COLOR_CARD, COLOR_CARD_INNER, COLOR_ACCENT, COLOR_CYAN,
    COLOR_DANGER, COLOR_SUCCESS, COLOR_WARNING, COLOR_TEXT_PRIMARY, COLOR_TEXT_MAIN, COLOR_TEXT_MUTED,
    COLOR_BORDER, COLOR_HOVER, FONT_TITLE, FONT_SUBTITLE, FONT_CARD_NUM,
    FONT_CARD_LABEL, FONT_BODY, FONT_MANUAL_HEADER, FONT_MANUAL_BODY, FONT_CONSOLE, configure_treeview_style
)

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "config.json")

def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "app_name": "KILLNet",
        "version": "2.0.0",
        "theme": "Dark",
        "auto_refresh_seconds": 3,
        "geoip_timeout_seconds": 4,
        "emergency_isolated": False
    }

def save_config(config_dict):
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(config_dict, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Error al guardar config.json: {e}")

class KILLNetMainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Cargar configuración persistente
        self.config = load_config()
        saved_theme = self.config.get("theme", "Dark")
        
        # Aplicar modo de apariencia inicial
        ctk.set_appearance_mode(saved_theme)
        ctk.set_default_color_theme("blue")
        
        # Configuración de ventana centrándola en 1180x800
        self.title("KILLNet v2.0 - Suite Forense, Auditoría & Hardening de Red Local")
        self.geometry("1180x800")
        self.minsize(1060, 700)
        self.configure(fg_color=COLOR_BG)
        self._center_window(1180, 800)
        
        # Iconos nativos
        base_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        ico_path = os.path.join(base_dir, "assets", "icon.ico")
        png_path = os.path.join(base_dir, "assets", "icon.png")

        try:
            if os.path.exists(ico_path):
                self.iconbitmap(ico_path)
            elif os.path.exists("assets/icon.ico"):
                self.iconbitmap("assets/icon.ico")
        except Exception:
            pass

        try:
            if os.path.exists(png_path):
                self.iconphoto(False, tk.PhotoImage(file=png_path))
            elif os.path.exists("assets/icon.png"):
                self.iconphoto(False, tk.PhotoImage(file="assets/icon.png"))
        except Exception:
            pass
        
        # Estado interno
        self.is_admin_user = is_admin()
        self.is_auto_monitoring = False
        self.is_emergency_isolated = False
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        # Estado Centinela Wi-Fi / IDS
        self.arp_guard_active = False
        self.arp_guard_stop_event = threading.Event()
        self.arp_guard_thread = None
        self.gateway_cache = {}
        
        # Datos de telemetría de sockets
        self.current_connections = []
        self.active_status_filter = "ALL"
        self.search_query = ""
        
        # Datos de Red Local / LAN
        self.lan_devices = []
        
        # Datos de Restricciones
        self.restriction_results = []
        
        # Resolver modo efectivo
        effective_mode = ctk.get_appearance_mode()
        configure_treeview_style(effective_mode)
        
        # Construcción de la interfaz
        self._build_layout(saved_theme)
        self._update_all_treeview_tags(effective_mode)
        
        # Configuración del tag rojo especial para alertas
        self.txt_console.tag_config("DANGER", foreground="#ef4444")
        
        # Logs de bienvenida
        self.log_message(f"=== KILLNet v2.0 Suite Inicializada [{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ===")
        self.log_message(f"[CONFIG] Tema cargado: '{saved_theme}' (Efectivo: '{effective_mode}').", "INFO")
        if self.is_admin_user:
            self.log_message("[ENTORNO] Privilegios de Administrador ACTIVOS (IDS, Hardening, Firewall y Kill habilitados).", "SUCCESS")
        else:
            self.log_message("[ADVERTENCIA] Ejecutándose SIN privilegios de Administrador. Funciones netsh requerirán elevación.", "WARNING")
            
        # Escaneo inicial automático de sockets
        self.start_scan_async()
        
        # Cargar reglas iniciales de acceso e información del gateway
        self.refresh_access_control_ui()
        self.refresh_sentinel_gateway_info_async()

    def _center_window(self, width: int = 1180, height: int = 800):
        self.update_idletasks()
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = max(0, (screen_w - width) // 2)
        y = max(0, (screen_h - height) // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _center_modal(self, modal, width: int, height: int):
        modal.update_idletasks()
        p_x = self.winfo_x()
        p_y = self.winfo_y()
        p_w = self.winfo_width()
        p_h = self.winfo_height()
        x = max(0, p_x + (p_w - width) // 2)
        y = max(0, p_y + (p_h - height) // 2)
        modal.geometry(f"{width}x{height}+{max(0, x)}+{max(0, y)}")

    def _build_layout(self, current_theme: str):
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # -------------------------------------------------------------
        # 1. SIDEBAR LATERAL IZQUIERDO
        # -------------------------------------------------------------
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color=COLOR_SIDEBAR)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(18, weight=1)
        
        # Header Sidebar
        self.lbl_title = ctk.CTkLabel(
            self.sidebar, text="⚡ KILLNet v2.0", font=("Segoe UI", 22, "bold"), text_color=COLOR_CYAN
        )
        self.lbl_title.grid(row=0, column=0, padx=20, pady=(16, 0), sticky="w")
        
        self.lbl_subtitle = ctk.CTkLabel(
            self.sidebar, text="Network Forensics & Security Suite", font=("Segoe UI", 9), text_color=COLOR_TEXT_MUTED
        )
        self.lbl_subtitle.grid(row=1, column=0, padx=20, pady=(0, 8), sticky="w")
        
        # Badge de privilegios Admin
        admin_text = "🛡️ Modo Admin (Elevado)" if self.is_admin_user else "⚠️ Modo Usuario (Limitado)"
        admin_color = COLOR_SUCCESS if self.is_admin_user else COLOR_WARNING
        self.lbl_admin_badge = ctk.CTkLabel(
            self.sidebar, text=admin_text, font=("Segoe UI", 9, "bold"), text_color=admin_color,
            fg_color=COLOR_CARD, corner_radius=6, height=24
        )
        self.lbl_admin_badge.grid(row=2, column=0, padx=15, pady=(0, 8), sticky="ew")
        
        sep1 = ctk.CTkFrame(self.sidebar, height=2, fg_color=COLOR_BORDER)
        sep1.grid(row=3, column=0, padx=15, pady=(0, 6), sticky="ew")
        
        # NAV BUTTONS
        self.lbl_nav_title = ctk.CTkLabel(
            self.sidebar, text="MÓDULOS DE AUDITORÍA & DEFENSA:", font=("Segoe UI", 8, "bold"), text_color=COLOR_TEXT_MUTED, anchor="w"
        )
        self.lbl_nav_title.grid(row=4, column=0, padx=15, pady=(0, 4), sticky="w")

        self.btn_nav_sockets = ctk.CTkButton(
            self.sidebar, text="📊 Telemetría de Sockets", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_ACCENT, hover_color=COLOR_HOVER, text_color="#ffffff", anchor="w",
            command=lambda: self.switch_tab("sockets")
        )
        self.btn_nav_sockets.grid(row=5, column=0, padx=15, pady=2, sticky="ew")

        self.btn_nav_sentinel = ctk.CTkButton(
            self.sidebar, text="🚨 Centinela Wi-Fi (IDS)", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD, hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MAIN, anchor="w",
            command=lambda: self.switch_tab("sentinel")
        )
        self.btn_nav_sentinel.grid(row=6, column=0, padx=15, pady=2, sticky="ew")

        self.btn_nav_auditor = ctk.CTkButton(
            self.sidebar, text="🛡️ Auditoría & Hardening", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD, hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MAIN, anchor="w",
            command=lambda: self.switch_tab("auditor")
        )
        self.btn_nav_auditor.grid(row=7, column=0, padx=15, pady=2, sticky="ew")

        self.btn_nav_lan = ctk.CTkButton(
            self.sidebar, text="📡 Red Local / Wi-Fi", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD, hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MAIN, anchor="w",
            command=lambda: self.switch_tab("lan")
        )
        self.btn_nav_lan.grid(row=8, column=0, padx=15, pady=2, sticky="ew")

        self.btn_nav_access = ctk.CTkButton(
            self.sidebar, text="🛡️ Filtro de Red (Access)", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD, hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MAIN, anchor="w",
            command=lambda: self.switch_tab("access")
        )
        self.btn_nav_access.grid(row=9, column=0, padx=15, pady=2, sticky="ew")

        self.btn_nav_restrictions = ctk.CTkButton(
            self.sidebar, text="🌐 Diagnóstico de Bloqueos", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD, hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MAIN, anchor="w",
            command=lambda: self.switch_tab("restrictions")
        )
        self.btn_nav_restrictions.grid(row=10, column=0, padx=15, pady=2, sticky="ew")

        sep2 = ctk.CTkFrame(self.sidebar, height=2, fg_color=COLOR_BORDER)
        sep2.grid(row=11, column=0, padx=15, pady=(6, 6), sticky="ew")
        
        # ACCIONES RÁPIDAS
        self.btn_auto_monitor = ctk.CTkButton(
            self.sidebar, text="📡 Monitoreo En Vivo [OFF]", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD, hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MAIN, anchor="w",
            command=self.toggle_auto_monitor
        )
        self.btn_auto_monitor.grid(row=12, column=0, padx=15, pady=2, sticky="ew")
        
        self.btn_emergency = ctk.CTkButton(
            self.sidebar, text="🚨 Modo Pánico (Aislamiento)", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_DANGER, hover_color="#c0392b", text_color="#ffffff", anchor="w",
            command=self.on_toggle_emergency_isolation
        )
        self.btn_emergency.grid(row=13, column=0, padx=15, pady=(4, 6), sticky="ew")

        sep3 = ctk.CTkFrame(self.sidebar, height=2, fg_color=COLOR_BORDER)
        sep3.grid(row=14, column=0, padx=15, pady=(0, 6), sticky="ew")

        # BOTONES SECUNDARIOS Y SOPORTE
        self.btn_donate = ctk.CTkButton(
            self.sidebar, text="☕ Apoyar el Proyecto", font=("Segoe UI", 10, "bold"),
            fg_color="#eab308", hover_color="#ca8a04", text_color="#1c1917", anchor="w",
            command=self.open_donation_modal
        )
        self.btn_donate.grid(row=15, column=0, padx=15, pady=2, sticky="ew")
        
        self.btn_feedback = ctk.CTkButton(
            self.sidebar, text="💬 Soporte & Dudas", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD, hover_color=COLOR_HOVER, text_color=COLOR_CYAN, anchor="w",
            command=self.open_feedback_modal
        )
        self.btn_feedback.grid(row=16, column=0, padx=15, pady=2, sticky="ew")
        
        self.btn_manual = ctk.CTkButton(
            self.sidebar, text="📖 Manual de Usuario", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD, hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MAIN, anchor="w",
            command=self.open_manual_modal
        )
        self.btn_manual.grid(row=17, column=0, padx=15, pady=2, sticky="ew")
        
        spacer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        spacer.grid(row=18, column=0, sticky="nsew")
        
        # Selector de Tema
        self.lbl_theme = ctk.CTkLabel(
            self.sidebar, text="🎨 Modo de Tema:", font=("Segoe UI", 9, "bold"), text_color=COLOR_TEXT_MUTED, anchor="w"
        )
        self.lbl_theme.grid(row=19, column=0, padx=15, pady=(4, 2), sticky="w")
        
        self.option_theme = ctk.CTkOptionMenu(
            self.sidebar, values=["Dark", "Light", "System"], command=self._on_theme_changed,
            fg_color=COLOR_CARD, button_color=COLOR_BORDER, button_hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MAIN,
            dropdown_fg_color=COLOR_CARD, dropdown_hover_color=COLOR_HOVER, dropdown_text_color=COLOR_TEXT_MAIN, height=26
        )
        self.option_theme.set(current_theme)
        self.option_theme.grid(row=20, column=0, padx=15, pady=(0, 10), sticky="ew")

        # -------------------------------------------------------------
        # 2. PANEL CENTRAL PRINCIPAL CON TABVIEW
        # -------------------------------------------------------------
        self.main_panel = ctk.CTkFrame(self, fg_color=COLOR_BG, corner_radius=0)
        self.main_panel.grid(row=0, column=1, sticky="nsew", padx=12, pady=12)
        self.main_panel.grid_columnconfigure(0, weight=1)
        self.main_panel.grid_rowconfigure(0, weight=1)
        self.main_panel.grid_rowconfigure(1, weight=0)
        
        self.tabview = ctk.CTkTabview(self.main_panel, fg_color="transparent", corner_radius=8, command=self._on_tab_changed)
        self.tabview.grid(row=0, column=0, sticky="nsew")
        
        # Pestañas principales
        self.tab_sockets = self.tabview.add("📊 Sockets & Telemetría")
        self.tab_sentinel = self.tabview.add("🚨 Centinela Wi-Fi (IDS)")
        self.tab_auditor = self.tabview.add("🛡️ Auditoría & Hardening")
        self.tab_lan = self.tabview.add("📡 Red Local / Wi-Fi")
        self.tab_access = self.tabview.add("🛡️ Filtro de Red")
        self.tab_restrictions = self.tabview.add("🌐 Diagnóstico de Bloqueos")
        
        self._build_sockets_tab()
        self._build_sentinel_tab()
        self._build_auditor_tab()
        self._build_lan_tab()
        self._build_access_tab()
        self._build_restrictions_tab()

        # CONSOLA DE AUDITORIA INFERIOR
        self.console_container = ctk.CTkFrame(self.main_panel, fg_color=COLOR_CARD, corner_radius=8, height=120)
        self.console_container.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        self.console_container.grid_columnconfigure(0, weight=1)
        self.console_container.grid_rowconfigure(1, weight=1)
        
        console_bar = ctk.CTkFrame(self.console_container, fg_color="transparent", height=24)
        console_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(4, 0))
        console_bar.grid_columnconfigure(0, weight=1)
        
        lbl_console_title = ctk.CTkLabel(
            console_bar, text="💻 Consola Global de Auditoría y Eventos CTI", font=("Segoe UI", 10, "bold"), text_color=COLOR_TEXT_MUTED
        )
        lbl_console_title.grid(row=0, column=0, sticky="w")
        
        btn_clear_console = ctk.CTkButton(
            console_bar, text="Limpiar Logs", width=70, height=20, font=("Segoe UI", 9),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MAIN, command=self.clear_log_console
        )
        btn_clear_console.grid(row=0, column=1, sticky="e", padx=5)

        self.txt_console = ctk.CTkTextbox(
            self.console_container, font=FONT_CONSOLE, fg_color=COLOR_CARD_INNER, text_color=COLOR_TEXT_MAIN, height=80, corner_radius=4
        )
        self.txt_console.grid(row=1, column=0, sticky="nsew", padx=10, pady=(4, 6))

    # -------------------------------------------------------------
    # CONSTRUCCIÓN PESTAÑA AUDITORÍA & HARDENING DE RED
    # -------------------------------------------------------------
    def _build_auditor_tab(self):
        self.tab_auditor.grid_columnconfigure(0, weight=1)
        self.tab_auditor.grid_rowconfigure(2, weight=1)
        
        # 1. BANNER INFORMATIVO DE DISCLAIMER TÉCNICO
        banner_box = ctk.CTkFrame(self.tab_auditor, fg_color=COLOR_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        banner_box.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        
        lbl_disclaimer = ctk.CTkLabel(
            banner_box,
            text="🛡️ MÓDULO DE AUDITORÍA Y HARDENING PERIMETRAL LOCAL\n"
                 "Herramienta de diagnóstico defensivo para identificar la exposición de servicios en hosts de la red local "
                 "y aplicar reglas de aislamiento nativas mediante el Firewall de Windows. Utilizar únicamente sobre dispositivos de tu propiedad o bajo expresa autorización.",
            font=("Segoe UI", 9),
            text_color=COLOR_TEXT_MUTED,
            justify="center",
            wraplength=850
        )
        lbl_disclaimer.pack(padx=16, pady=8)

        # 2. CONTROLES Y SELECCIÓN DE TARGET IP
        target_box = ctk.CTkFrame(self.tab_auditor, fg_color=COLOR_CARD, corner_radius=8)
        target_box.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        target_box.grid_columnconfigure(1, weight=1)
        
        lbl_target = ctk.CTkLabel(target_box, text="Host / IP Objetivo:", font=("Segoe UI", 11, "bold"), text_color=COLOR_CYAN)
        lbl_target.grid(row=0, column=0, padx=(12, 6), pady=10, sticky="w")
        
        self.entry_audit_target = ctk.CTkEntry(
            target_box, placeholder_text="192.168.1.50", font=FONT_BODY, height=30,
            fg_color=COLOR_CARD_INNER, text_color=COLOR_TEXT_MAIN, border_color=COLOR_BORDER
        )
        self.entry_audit_target.grid(row=0, column=1, padx=6, pady=10, sticky="ew")
        
        self.btn_paste_lan_ip = ctk.CTkButton(
            target_box, text="📋 Usar Mi IP Local", font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MAIN, height=30, command=self.on_load_my_local_ip
        )
        self.btn_paste_lan_ip.grid(row=0, column=2, padx=6, pady=10)

        self.btn_start_audit = ctk.CTkButton(
            target_box, text="🔍 Iniciar Auditoría de Puertos y Servicios", font=("Segoe UI", 11, "bold"),
            fg_color=COLOR_ACCENT, hover_color=COLOR_HOVER, text_color="#ffffff", height=30, command=self.start_device_audit_async
        )
        self.btn_start_audit.grid(row=0, column=3, padx=(6, 12), pady=10)

        # 3. TABLA DE RESULTADOS DE AUDITORÍA Y ACCIONES
        audit_table_box = ctk.CTkFrame(self.tab_auditor, fg_color=COLOR_CARD, corner_radius=8)
        audit_table_box.grid(row=2, column=0, sticky="nsew")
        audit_table_box.grid_columnconfigure(0, weight=1)
        audit_table_box.grid_rowconfigure(0, weight=1)
        
        columns = ("port", "service", "status", "banner")
        self.tree_auditor = ttk.Treeview(audit_table_box, columns=columns, show="headings", style="Cyber.Treeview", selectmode="browse")
        
        self.tree_auditor.heading("port", text="Puerto TCP", anchor="center")
        self.tree_auditor.heading("service", text="Servicio Asociado", anchor="w")
        self.tree_auditor.heading("status", text="Estado Puerto", anchor="center")
        self.tree_auditor.heading("banner", text="Identificación / Banner de Servicio", anchor="w")
        
        self.tree_auditor.column("port", width=90, minwidth=70, anchor="center")
        self.tree_auditor.column("service", width=200, minwidth=140, anchor="w")
        self.tree_auditor.column("status", width=120, minwidth=90, anchor="center")
        self.tree_auditor.column("banner", width=460, minwidth=260, anchor="w")
        
        scrollbar_aud = ttk.Scrollbar(audit_table_box, orient="vertical", command=self.tree_auditor.yview)
        self.tree_auditor.configure(yscrollcommand=scrollbar_aud.set)
        
        self.tree_auditor.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
        scrollbar_aud.grid(row=0, column=1, sticky="ns", padx=(0, 10), pady=10)
        
        # Acciones de Mitigación en el Host
        audit_actions = ctk.CTkFrame(audit_table_box, fg_color="transparent")
        audit_actions.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 8))
        
        btn_isolate_target = ctk.CTkButton(
            audit_actions, text="🚫 Aislar Host en este Equipo (Regla de Firewall)", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_DANGER, hover_color="#c0392b", text_color="#ffffff", height=30, command=self.on_isolate_target_clicked
        )
        btn_isolate_target.pack(side="left")

    # -------------------------------------------------------------
    # CONSTRUCCIÓN PESTAÑA CENTINELA WI-FI (IDS DEFENSIVO)
    # -------------------------------------------------------------
    def _build_sentinel_tab(self):
        self.tab_sentinel.grid_columnconfigure(0, weight=1)
        self.tab_sentinel.grid_rowconfigure(2, weight=1)
        
        sentinel_top = ctk.CTkFrame(self.tab_sentinel, fg_color="transparent")
        sentinel_top.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        for i in range(3):
            sentinel_top.grid_columnconfigure(i, weight=1)
            
        card_gw = ctk.CTkFrame(sentinel_top, fg_color=COLOR_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        card_gw.grid(row=0, column=0, padx=(0, 4), sticky="ew")
        
        ctk.CTkLabel(card_gw, text="🌐 PUERTA DE ENLACE (ROUTER)", font=FONT_CARD_LABEL, text_color=COLOR_TEXT_MUTED).pack(anchor="w", padx=10, pady=(8, 2))
        self.lbl_sentinel_gw_ip = ctk.CTkLabel(card_gw, text="Gateway IP: 192.168.1.1", font=("Segoe UI", 11, "bold"), text_color=COLOR_CYAN)
        self.lbl_sentinel_gw_ip.pack(anchor="w", padx=10, pady=1)
        self.lbl_sentinel_gw_mac = ctk.CTkLabel(card_gw, text="MAC: 00:00:00:00:00:00", font=("Segoe UI", 10), text_color=COLOR_TEXT_MAIN)
        self.lbl_sentinel_gw_mac.pack(anchor="w", padx=10, pady=(0, 8))
        
        card_wifi = ctk.CTkFrame(sentinel_top, fg_color=COLOR_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        card_wifi.grid(row=0, column=1, padx=4, sticky="ew")
        
        ctk.CTkLabel(card_wifi, text="📡 TELEMETRÍA WI-FI / BSSID", font=FONT_CARD_LABEL, text_color=COLOR_TEXT_MUTED).pack(anchor="w", padx=10, pady=(8, 2))
        self.lbl_sentinel_ssid = ctk.CTkLabel(card_wifi, text="SSID: No conectado", font=("Segoe UI", 11, "bold"), text_color=COLOR_ACCENT)
        self.lbl_sentinel_ssid.pack(anchor="w", padx=10, pady=1)
        self.lbl_sentinel_bssid = ctk.CTkLabel(card_wifi, text="BSSID: N/A | Canal: N/A", font=("Segoe UI", 10), text_color=COLOR_TEXT_MAIN)
        self.lbl_sentinel_bssid.pack(anchor="w", padx=10, pady=(0, 8))
        
        card_shield = ctk.CTkFrame(sentinel_top, fg_color=COLOR_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        card_shield.grid(row=0, column=2, padx=(4, 0), sticky="ew")
        
        ctk.CTkLabel(card_shield, text="🛡️ ESCUDO ANTI-ARP SPOOFING", font=FONT_CARD_LABEL, text_color=COLOR_TEXT_MUTED).pack(anchor="w", padx=10, pady=(8, 2))
        self.lbl_sentinel_shield_status = ctk.CTkLabel(card_shield, text="INACTIVO ⚠️", font=("Segoe UI", 12, "bold"), text_color=COLOR_WARNING)
        self.lbl_sentinel_shield_status.pack(anchor="w", padx=10, pady=1)
        
        shield_controls = ctk.CTkFrame(card_shield, fg_color="transparent")
        shield_controls.pack(fill="x", padx=10, pady=(0, 6))
        
        self.switch_arp_guard = ctk.CTkSwitch(
            shield_controls, text="Activar Escudo", font=("Segoe UI", 10, "bold"),
            command=self.on_toggle_arp_guard, progress_color=COLOR_SUCCESS
        )
        self.switch_arp_guard.pack(side="left")
        
        self.chk_auto_fix = ctk.CTkCheckBox(
            shield_controls, text="Autoprotección", font=("Segoe UI", 9),
            hover_color=COLOR_HOVER
        )
        self.chk_auto_fix.pack(side="right")

        sentinel_actions = ctk.CTkFrame(self.tab_sentinel, fg_color=COLOR_CARD, corner_radius=8)
        sentinel_actions.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        
        btn_audit_gateway = ctk.CTkButton(
            sentinel_actions, text="🔍 Auditar Vulnerabilidades del Router", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_ACCENT, hover_color=COLOR_HOVER, text_color="#ffffff", height=32, command=self.start_gateway_audit_async
        )
        btn_audit_gateway.pack(side="left", padx=10, pady=8)
        
        btn_evil_twin = ctk.CTkButton(
            sentinel_actions, text="📡 Buscar Redes Gemelas (Evil Twin)", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_CYAN, height=32, command=self.start_evil_twin_scan_async
        )
        btn_evil_twin.pack(side="left", padx=(0, 10), pady=8)
        
        btn_wifi_kill = ctk.CTkButton(
            sentinel_actions, text="🛑 Aislamiento Wi-Fi de Emergencia", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_DANGER, hover_color="#c0392b", text_color="#ffffff", height=32, command=self.on_wifi_kill_clicked
        )
        btn_wifi_kill.pack(side="right", padx=10, pady=8)

        self.tabview_sentinel = ctk.CTkTabview(self.tab_sentinel, fg_color=COLOR_CARD, corner_radius=8)
        self.tabview_sentinel.grid(row=2, column=0, sticky="nsew")
        
        tab_hardening = self.tabview_sentinel.add("🔒 Hardening de Puertos Router")
        tab_eviltwin = self.tabview_sentinel.add("📡 Espectro Wi-Fi & Rogue AP")
        
        tab_hardening.grid_columnconfigure(0, weight=1)
        tab_hardening.grid_rowconfigure(0, weight=1)
        
        cols_h = ("port", "service", "status", "risk", "rec")
        self.tree_sentinel_ports = ttk.Treeview(tab_hardening, columns=cols_h, show="headings", style="Cyber.Treeview", selectmode="browse")
        
        self.tree_sentinel_ports.heading("port", text="Puerto", anchor="center")
        self.tree_sentinel_ports.heading("service", text="Servicio", anchor="w")
        self.tree_sentinel_ports.heading("status", text="Estado Puerto", anchor="center")
        self.tree_sentinel_ports.heading("risk", text="Nivel de Riesgo", anchor="center")
        self.tree_sentinel_ports.heading("rec", text="Recomendación / Diagnóstico de Seguridad", anchor="w")
        
        self.tree_sentinel_ports.column("port", width=80, minwidth=60, anchor="center")
        self.tree_sentinel_ports.column("service", width=120, minwidth=90, anchor="w")
        self.tree_sentinel_ports.column("status", width=120, minwidth=90, anchor="center")
        self.tree_sentinel_ports.column("risk", width=130, minwidth=100, anchor="center")
        self.tree_sentinel_ports.column("rec", width=420, minwidth=240, anchor="w")
        
        sb_h = ttk.Scrollbar(tab_hardening, orient="vertical", command=self.tree_sentinel_ports.yview)
        self.tree_sentinel_ports.configure(yscrollcommand=sb_h.set)
        
        self.tree_sentinel_ports.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        sb_h.grid(row=0, column=1, sticky="ns", padx=(0, 8), pady=8)

        tab_eviltwin.grid_columnconfigure(0, weight=1)
        tab_eviltwin.grid_rowconfigure(0, weight=1)
        
        cols_e = ("ssid", "bssid", "auth", "status", "details")
        self.tree_sentinel_eviltwin = ttk.Treeview(tab_eviltwin, columns=cols_e, show="headings", style="Cyber.Treeview", selectmode="browse")
        
        self.tree_sentinel_eviltwin.heading("ssid", text="Nombre de Red (SSID)", anchor="w")
        self.tree_sentinel_eviltwin.heading("bssid", text="Dirección MAC AP (BSSID)", anchor="center")
        self.tree_sentinel_eviltwin.heading("auth", text="Autenticación", anchor="center")
        self.tree_sentinel_eviltwin.heading("status", text="Diagnóstico Rogue AP", anchor="center")
        self.tree_sentinel_eviltwin.heading("details", text="Detalles de Espectro", anchor="w")
        
        self.tree_sentinel_eviltwin.column("ssid", width=160, minwidth=120, anchor="w")
        self.tree_sentinel_eviltwin.column("bssid", width=160, minwidth=130, anchor="center")
        self.tree_sentinel_eviltwin.column("auth", width=140, minwidth=100, anchor="center")
        self.tree_sentinel_eviltwin.column("status", width=160, minwidth=110, anchor="center")
        self.tree_sentinel_eviltwin.column("details", width=300, minwidth=200, anchor="w")
        
        sb_e = ttk.Scrollbar(tab_eviltwin, orient="vertical", command=self.tree_sentinel_eviltwin.yview)
        self.tree_sentinel_eviltwin.configure(yscrollcommand=sb_e.set)
        
        self.tree_sentinel_eviltwin.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        sb_e.grid(row=0, column=1, sticky="ns", padx=(0, 8), pady=8)

    # -------------------------------------------------------------
    # CONSTRUCCIÓN PESTAÑA 1: SOCKETS & TELEMETRÍA
    # -------------------------------------------------------------
    def _build_sockets_tab(self):
        self.tab_sockets.grid_columnconfigure(0, weight=1)
        self.tab_sockets.grid_rowconfigure(1, weight=1)
        
        self.cards_frame = ctk.CTkFrame(self.tab_sockets, fg_color="transparent")
        self.cards_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        for i in range(4):
            self.cards_frame.grid_columnconfigure(i, weight=1)
            
        self.card_total = self._create_metric_card(self.cards_frame, 0, "TOTAL CONEXIONES", "0", COLOR_ACCENT)
        self.card_remote = self._create_metric_card(self.cards_frame, 1, "REMOTAS ACTIVAS", "0", COLOR_CYAN)
        self.card_procs = self._create_metric_card(self.cards_frame, 2, "PROCESOS RED", "0", COLOR_SUCCESS)
        self.card_public = self._create_metric_card(self.cards_frame, 3, "IPs PÚBLICAS / WAN", "0", COLOR_WARNING)
        
        self.table_container = ctk.CTkFrame(self.tab_sockets, fg_color=COLOR_CARD, corner_radius=8)
        self.table_container.grid(row=1, column=0, sticky="nsew")
        self.table_container.grid_columnconfigure(0, weight=1)
        self.table_container.grid_rowconfigure(1, weight=1)
        
        table_header = ctk.CTkFrame(self.table_container, fg_color="transparent")
        table_header.grid(row=0, column=0, sticky="ew", padx=10, pady=8)
        table_header.grid_columnconfigure(0, weight=1)
        
        header_top = ctk.CTkFrame(table_header, fg_color="transparent")
        header_top.pack(fill="x", expand=True, pady=(0, 6))
        
        tbl_title = ctk.CTkLabel(header_top, text="📡 Matriz Forense de Sockets y Procesos", font=FONT_SUBTITLE, text_color=COLOR_TEXT_MAIN)
        tbl_title.pack(side="left")
        
        self.lbl_status = ctk.CTkLabel(header_top, text="Listo", font=FONT_BODY, text_color=COLOR_TEXT_MUTED)
        self.lbl_status.pack(side="right", padx=(10, 0))
        
        self.btn_export = ctk.CTkButton(
            header_top, text="📄 Exportar Auditoría", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_CYAN, width=130, height=26, command=self.on_export_audit_clicked
        )
        self.btn_export.pack(side="right")
        
        header_controls = ctk.CTkFrame(table_header, fg_color="transparent")
        header_controls.pack(fill="x", expand=True)
        
        self.btn_scan = ctk.CTkButton(
            header_controls, text="🔍 Escanear Sockets", width=120, height=28, font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_ACCENT, hover_color=COLOR_HOVER, text_color="#ffffff", command=self.start_scan_async
        )
        self.btn_scan.pack(side="left", padx=(0, 6))

        self.btn_filter_all = ctk.CTkButton(
            header_controls, text="Todas", width=65, height=28, font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_ACCENT, hover_color=COLOR_HOVER, text_color="#ffffff", command=lambda: self._set_status_filter("ALL")
        )
        self.btn_filter_all.pack(side="left", padx=(0, 4))
        
        self.btn_filter_estab = ctk.CTkButton(
            header_controls, text="Conectadas", width=80, height=28, font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MAIN, command=lambda: self._set_status_filter("ESTABLISHED")
        )
        self.btn_filter_estab.pack(side="left", padx=(0, 4))
        
        self.btn_filter_listen = ctk.CTkButton(
            header_controls, text="En Escucha", width=80, height=28, font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MAIN, command=lambda: self._set_status_filter("LISTEN")
        )
        self.btn_filter_listen.pack(side="left", padx=(0, 10))
        
        self.entry_search = ctk.CTkEntry(
            header_controls, placeholder_text="🔍 Filtrar sockets por binario, PID o IP...", font=FONT_BODY, height=28,
            fg_color=COLOR_CARD_INNER, text_color=COLOR_TEXT_MAIN, border_color=COLOR_BORDER
        )
        self.entry_search.pack(side="left", fill="x", expand=True)
        self.entry_search.bind("<KeyRelease>", self._on_search_key_release)

        columns = ("pid", "process", "protocol", "remote_ip", "remote_port", "geo_isp", "status")
        self.tree = ttk.Treeview(self.table_container, columns=columns, show="headings", style="Cyber.Treeview", selectmode="browse")
        
        self.tree.heading("pid", text="PID", anchor="center")
        self.tree.heading("process", text="Proceso", anchor="w")
        self.tree.heading("protocol", text="Proto", anchor="center")
        self.tree.heading("remote_ip", text="IP Remota", anchor="w")
        self.tree.heading("remote_port", text="Puerto", anchor="center")
        self.tree.heading("geo_isp", text="País / ISP / GeoIP", anchor="w")
        self.tree.heading("status", text="Estado", anchor="center")
        
        self.tree.column("pid", width=65, minwidth=55, anchor="center")
        self.tree.column("process", width=170, minwidth=110, anchor="w")
        self.tree.column("protocol", width=65, minwidth=50, anchor="center")
        self.tree.column("remote_ip", width=130, minwidth=100, anchor="w")
        self.tree.column("remote_port", width=65, minwidth=50, anchor="center")
        self.tree.column("geo_isp", width=250, minwidth=160, anchor="w")
        self.tree.column("status", width=100, minwidth=80, anchor="center")
        
        scrollbar = ttk.Scrollbar(self.table_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=1, column=0, sticky="nsew", padx=(10, 0), pady=(0, 10))
        scrollbar.grid(row=1, column=1, sticky="ns", padx=(0, 10), pady=(0, 10))

        actions_bar = ctk.CTkFrame(self.table_container, fg_color="transparent")
        actions_bar.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 8))
        
        self.btn_block_ip = ctk.CTkButton(
            actions_bar, text="🚫 Bloquear IP Seleccionada", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_WARNING, height=28, command=self.on_block_ip_clicked
        )
        self.btn_block_ip.pack(side="left", padx=(0, 8))
        
        self.btn_kill_proc = ctk.CTkButton(
            actions_bar, text="💀 Terminar Proceso (Kill)", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_DANGER, height=28, command=self.on_kill_proc_clicked
        )
        self.btn_kill_proc.pack(side="left")

    # -------------------------------------------------------------
    # CONSTRUCCIÓN PESTAÑA RED LOCAL / WI-FI
    # -------------------------------------------------------------
    def _build_lan_tab(self):
        self.tab_lan.grid_columnconfigure(0, weight=1)
        self.tab_lan.grid_rowconfigure(1, weight=1)
        
        lan_header = ctk.CTkFrame(self.tab_lan, fg_color=COLOR_CARD, corner_radius=8)
        lan_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        lan_header.grid_columnconfigure(1, weight=1)
        
        lbl_lan_title = ctk.CTkLabel(lan_header, text="📡 Escáner de Dispositivos en la Red Local", font=FONT_SUBTITLE, text_color=COLOR_CYAN)
        lbl_lan_title.grid(row=0, column=0, padx=12, pady=10, sticky="w")
        
        self.lbl_lan_info = ctk.CTkLabel(lan_header, text="Local IP: ... | Gateway: ... | Total: 0", font=FONT_BODY, text_color=COLOR_TEXT_MUTED)
        self.lbl_lan_info.grid(row=0, column=1, padx=12, pady=10, sticky="w")
        
        self.btn_scan_lan = ctk.CTkButton(
            lan_header, text="🔍 Escanear Red Wi-Fi / LAN", font=("Segoe UI", 11, "bold"),
            fg_color=COLOR_ACCENT, hover_color=COLOR_HOVER, text_color="#ffffff", height=32, command=self.start_lan_scan_async
        )
        self.btn_scan_lan.grid(row=0, column=2, padx=12, pady=10, sticky="e")
        
        lan_table_box = ctk.CTkFrame(self.tab_lan, fg_color=COLOR_CARD, corner_radius=8)
        lan_table_box.grid(row=1, column=0, sticky="nsew")
        lan_table_box.grid_columnconfigure(0, weight=1)
        lan_table_box.grid_rowconfigure(0, weight=1)
        
        columns = ("ip", "mac", "hostname", "vendor", "type", "status")
        self.tree_lan = ttk.Treeview(lan_table_box, columns=columns, show="headings", style="Cyber.Treeview", selectmode="browse")
        
        self.tree_lan.heading("ip", text="Dirección IP", anchor="w")
        self.tree_lan.heading("mac", text="Dirección MAC", anchor="center")
        self.tree_lan.heading("hostname", text="Nombre de Host (Hostname)", anchor="w")
        self.tree_lan.heading("vendor", text="Fabricante / OUI", anchor="w")
        self.tree_lan.heading("type", text="Tipo Estimado", anchor="center")
        self.tree_lan.heading("status", text="Estado Política", anchor="center")
        
        self.tree_lan.column("ip", width=120, minwidth=100, anchor="w")
        self.tree_lan.column("mac", width=140, minwidth=120, anchor="center")
        self.tree_lan.column("hostname", width=180, minwidth=120, anchor="w")
        self.tree_lan.column("vendor", width=220, minwidth=150, anchor="w")
        self.tree_lan.column("type", width=140, minwidth=110, anchor="center")
        self.tree_lan.column("status", width=130, minwidth=100, anchor="center")
        
        scrollbar_lan = ttk.Scrollbar(lan_table_box, orient="vertical", command=self.tree_lan.yview)
        self.tree_lan.configure(yscrollcommand=scrollbar_lan.set)
        
        self.tree_lan.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
        scrollbar_lan.grid(row=0, column=1, sticky="ns", padx=(0, 10), pady=10)
        
        lan_actions = ctk.CTkFrame(lan_table_box, fg_color="transparent")
        lan_actions.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 8))
        
        btn_lan_audit = ctk.CTkButton(
            lan_actions, text="🛡️ Auditar Host", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_ACCENT, hover_color=COLOR_HOVER, text_color="#ffffff", height=28, command=self.on_lan_audit_host_clicked
        )
        btn_lan_audit.pack(side="left", padx=(0, 8))

        btn_lan_block = ctk.CTkButton(
            lan_actions, text="🚫 Bloquear en este equipo (Firewall)", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_DANGER, height=28, command=self.on_lan_block_clicked
        )
        btn_lan_block.pack(side="left", padx=(0, 8))
        
        btn_lan_blacklist = ctk.CTkButton(
            lan_actions, text="🛡️ Añadir a Blacklist", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_WARNING, height=28, command=self.on_lan_add_blacklist_clicked
        )
        btn_lan_blacklist.pack(side="left", padx=(0, 8))
        
        btn_lan_whitelist = ctk.CTkButton(
            lan_actions, text="✅ Autorizar en Whitelist", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_SUCCESS, height=28, command=self.on_lan_add_whitelist_clicked
        )
        btn_lan_whitelist.pack(side="left")

    # -------------------------------------------------------------
    # CONSTRUCCIÓN PESTAÑA FILTRO DE RED
    # -------------------------------------------------------------
    def _build_access_tab(self):
        self.tab_access.grid_columnconfigure(0, weight=1)
        self.tab_access.grid_rowconfigure(1, weight=1)
        
        acc_header = ctk.CTkFrame(self.tab_access, fg_color=COLOR_CARD, corner_radius=8)
        acc_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        acc_header.grid_columnconfigure(1, weight=1)
        
        lbl_acc_title = ctk.CTkLabel(acc_header, text="🛡️ Sistema de Control de Acceso Local", font=FONT_SUBTITLE, text_color=COLOR_CYAN)
        lbl_acc_title.grid(row=0, column=0, padx=12, pady=10, sticky="w")
        
        lbl_mode_sel = ctk.CTkLabel(acc_header, text="Modo de Política:", font=("Segoe UI", 10, "bold"), text_color=COLOR_TEXT_MUTED)
        lbl_mode_sel.grid(row=0, column=1, padx=(12, 4), pady=10, sticky="e")
        
        self.seg_access_mode = ctk.CTkSegmentedButton(
            acc_header, values=["Blacklist Mode", "Whitelist Mode"], command=self.on_access_mode_changed,
            font=("Segoe UI", 10, "bold"), selected_color=COLOR_ACCENT, selected_hover_color=COLOR_HOVER
        )
        self.seg_access_mode.set("Blacklist Mode")
        self.seg_access_mode.grid(row=0, column=2, padx=12, pady=10, sticky="e")
        
        acc_table_box = ctk.CTkFrame(self.tab_access, fg_color=COLOR_CARD, corner_radius=8)
        acc_table_box.grid(row=1, column=0, sticky="nsew")
        acc_table_box.grid_columnconfigure(0, weight=1)
        acc_table_box.grid_rowconfigure(0, weight=1)
        
        columns = ("mac", "ip", "alias", "status", "compliance")
        self.tree_access = ttk.Treeview(acc_table_box, columns=columns, show="headings", style="Cyber.Treeview", selectmode="browse")
        
        self.tree_access.heading("mac", text="Dirección MAC", anchor="center")
        self.tree_access.heading("ip", text="Dirección IP", anchor="w")
        self.tree_access.heading("alias", text="Alias / Nombre Dispositivo", anchor="w")
        self.tree_access.heading("status", text="Estado Regla", anchor="center")
        self.tree_access.heading("compliance", text="Evaluación de Política", anchor="w")
        
        self.tree_access.column("mac", width=140, minwidth=120, anchor="center")
        self.tree_access.column("ip", width=120, minwidth=100, anchor="w")
        self.tree_access.column("alias", width=200, minwidth=140, anchor="w")
        self.tree_access.column("status", width=120, minwidth=90, anchor="center")
        self.tree_access.column("compliance", width=250, minwidth=180, anchor="w")
        
        scrollbar_acc = ttk.Scrollbar(acc_table_box, orient="vertical", command=self.tree_access.yview)
        self.tree_access.configure(yscrollcommand=scrollbar_acc.set)
        
        self.tree_access.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
        scrollbar_acc.grid(row=0, column=1, sticky="ns", padx=(0, 10), pady=10)
        
        acc_actions = ctk.CTkFrame(acc_table_box, fg_color="transparent")
        acc_actions.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 8))
        
        btn_acc_add = ctk.CTkButton(
            acc_actions, text="➕ Agregar Regla Manual", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_ACCENT, hover_color=COLOR_HOVER, text_color="#ffffff", height=28, command=self.open_add_access_rule_modal
        )
        btn_acc_add.pack(side="left", padx=(0, 8))
        
        btn_acc_allow = ctk.CTkButton(
            acc_actions, text="✅ Cambiar a Permitido", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_SUCCESS, height=28, command=lambda: self.set_selected_access_status("allowed")
        )
        btn_acc_allow.pack(side="left", padx=(0, 8))
        
        btn_acc_block = ctk.CTkButton(
            acc_actions, text="🚫 Cambiar a Bloqueado", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_DANGER, height=28, command=lambda: self.set_selected_access_status("blocked")
        )
        btn_acc_block.pack(side="left", padx=(0, 8))
        
        btn_acc_delete = ctk.CTkButton(
            acc_actions, text="🗑️ Eliminar Regla", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MUTED, height=28, command=self.on_delete_access_rule_clicked
        )
        btn_acc_delete.pack(side="left")

    # -------------------------------------------------------------
    # CONSTRUCCIÓN PESTAÑA DIAGNÓSTICO DE BLOQUEOS
    # -------------------------------------------------------------
    def _build_restrictions_tab(self):
        self.tab_restrictions.grid_columnconfigure(0, weight=1)
        self.tab_restrictions.grid_rowconfigure(1, weight=1)
        
        res_header = ctk.CTkFrame(self.tab_restrictions, fg_color=COLOR_CARD, corner_radius=8)
        res_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        res_header.grid_columnconfigure(1, weight=1)
        
        lbl_res_title = ctk.CTkLabel(res_header, text="🌐 Diagnóstico de Bloqueos y Restricciones de Red", font=FONT_SUBTITLE, text_color=COLOR_CYAN)
        lbl_res_title.grid(row=0, column=0, padx=12, pady=10, sticky="w")
        
        self.lbl_adapter_info = ctk.CTkLabel(res_header, text=f"Interfaz: {get_active_network_adapter()}", font=FONT_BODY, text_color=COLOR_TEXT_MUTED)
        self.lbl_adapter_info.grid(row=0, column=1, padx=12, pady=10, sticky="w")
        
        self.btn_test_restrictions = ctk.CTkButton(
            res_header, text="⚡ Testear Restricciones de Red", font=("Segoe UI", 11, "bold"),
            fg_color=COLOR_ACCENT, hover_color=COLOR_HOVER, text_color="#ffffff", height=32, command=self.start_restriction_test_async
        )
        self.btn_test_restrictions.grid(row=0, column=2, padx=12, pady=10, sticky="e")
        
        res_table_box = ctk.CTkFrame(self.tab_restrictions, fg_color=COLOR_CARD, corner_radius=8)
        res_table_box.grid(row=1, column=0, sticky="nsew")
        res_table_box.grid_columnconfigure(0, weight=1)
        res_table_box.grid_rowconfigure(0, weight=1)
        
        columns = ("category", "target", "status", "cause", "ip", "details")
        self.tree_restrictions = ttk.Treeview(res_table_box, columns=columns, show="headings", style="Cyber.Treeview", selectmode="browse")
        
        self.tree_restrictions.heading("category", text="Categoría", anchor="w")
        self.tree_restrictions.heading("target", text="Servicio / Dominio", anchor="w")
        self.tree_restrictions.heading("status", text="Estado", anchor="center")
        self.tree_restrictions.heading("cause", text="Causa de Bloqueo", anchor="w")
        self.tree_restrictions.heading("ip", text="IP Resuelta", anchor="center")
        self.tree_restrictions.heading("details", text="Detalles de Diagnóstico", anchor="w")
        
        self.tree_restrictions.column("category", width=140, minwidth=110, anchor="w")
        self.tree_restrictions.column("target", width=140, minwidth=110, anchor="w")
        self.tree_restrictions.column("status", width=140, minwidth=110, anchor="center")
        self.tree_restrictions.column("cause", width=160, minwidth=120, anchor="w")
        self.tree_restrictions.column("ip", width=120, minwidth=90, anchor="center")
        self.tree_restrictions.column("details", width=250, minwidth=160, anchor="w")
        
        scrollbar_res = ttk.Scrollbar(res_table_box, orient="vertical", command=self.tree_restrictions.yview)
        self.tree_restrictions.configure(yscrollcommand=scrollbar_res.set)
        
        self.tree_restrictions.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
        scrollbar_res.grid(row=0, column=1, sticky="ns", padx=(0, 10), pady=10)
        
        res_actions = ctk.CTkFrame(res_table_box, fg_color="transparent")
        res_actions.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 8))
        
        btn_apply_dns = ctk.CTkButton(
            res_actions, text="🔓 Aplicar DNS Seguros (Bypass Bloqueo DNS)", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_SUCCESS, hover_color="#15803d", text_color="#ffffff", height=30, command=self.on_apply_secure_dns_clicked
        )
        btn_apply_dns.pack(side="left", padx=(0, 8))
        
        btn_reset_dns = ctk.CTkButton(
            res_actions, text="🔄 Restaurar DNS Automático (DHCP)", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MAIN, height=30, command=self.on_reset_dns_clicked
        )
        btn_reset_dns.pack(side="left", padx=(0, 8))
        
        btn_clean_hosts = ctk.CTkButton(
            res_actions, text="🧹 Limpiar Archivo Hosts", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=COLOR_HOVER, text_color=COLOR_WARNING, height=30, command=self.on_clean_hosts_clicked
        )
        btn_clean_hosts.pack(side="left")

    def _create_metric_card(self, parent, col, title, value, accent_color):
        card = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        card.grid(row=0, column=col, padx=4 if col > 0 else (0, 4), sticky="ew")
        
        lbl_val = ctk.CTkLabel(card, text=value, font=FONT_CARD_NUM, text_color=accent_color)
        lbl_val.pack(pady=(8, 0), padx=10)
        
        lbl_title = ctk.CTkLabel(card, text=title, font=FONT_CARD_LABEL, text_color=COLOR_TEXT_MUTED)
        lbl_title.pack(pady=(0, 8), padx=10)
        
        return lbl_val

    # -------------------------------------------------------------
    # NAVEGACIÓN Y CAMBIO DE PESTAÑAS
    # -------------------------------------------------------------
    def switch_tab(self, tab_key: str):
        if tab_key == "sockets":
            self.tabview.set("📊 Sockets & Telemetría")
        elif tab_key == "sentinel":
            self.tabview.set("🚨 Centinela Wi-Fi (IDS)")
            self.refresh_sentinel_gateway_info_async()
        elif tab_key == "auditor":
            self.tabview.set("🛡️ Auditoría & Hardening")
        elif tab_key == "lan":
            self.tabview.set("📡 Red Local / Wi-Fi")
            if not self.lan_devices:
                self.start_lan_scan_async()
        elif tab_key == "access":
            self.tabview.set("🛡️ Filtro de Red")
            self.refresh_access_control_ui()
        elif tab_key == "restrictions":
            self.tabview.set("🌐 Diagnóstico de Bloqueos")
            if not self.restriction_results:
                self.start_restriction_test_async()
                
        self._update_nav_buttons_highlight(tab_key)

    def _on_tab_changed(self):
        tab_name = self.tabview.get()
        if "Sockets" in tab_name:
            self._update_nav_buttons_highlight("sockets")
        elif "Centinela" in tab_name:
            self._update_nav_buttons_highlight("sentinel")
            self.refresh_sentinel_gateway_info_async()
        elif "Auditoría" in tab_name:
            self._update_nav_buttons_highlight("auditor")
        elif "Red Local" in tab_name:
            self._update_nav_buttons_highlight("lan")
            if not self.lan_devices:
                self.start_lan_scan_async()
        elif "Filtro" in tab_name:
            self._update_nav_buttons_highlight("access")
            self.refresh_access_control_ui()
        elif "Diagnóstico" in tab_name:
            self._update_nav_buttons_highlight("restrictions")
            if not self.restriction_results:
                self.start_restriction_test_async()

    def _update_nav_buttons_highlight(self, active_key: str):
        btns = {
            "sockets": self.btn_nav_sockets,
            "sentinel": self.btn_nav_sentinel,
            "auditor": self.btn_nav_auditor,
            "lan": self.btn_nav_lan,
            "access": self.btn_nav_access,
            "restrictions": self.btn_nav_restrictions
        }
        for key, btn in btns.items():
            if key == active_key:
                btn.configure(fg_color=COLOR_ACCENT, text_color="#ffffff")
            else:
                btn.configure(fg_color=COLOR_CARD, text_color=COLOR_TEXT_MAIN)

    def log_message(self, message: str, level: str = "INFO"):
        """Registra un mensaje con marca de tiempo en la consola inferior."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        prefix = f"[{timestamp}] [{level}] "
        full_text = f"{prefix}{message}\n"
        
        self.txt_console.configure(state="normal")
        if level == "DANGER":
            self.txt_console.insert("end", full_text, "DANGER")
        else:
            self.txt_console.insert("end", full_text)
            
        self.txt_console.see("end")
        self.txt_console.configure(state="disabled")

    def clear_log_console(self):
        self.txt_console.configure(state="normal")
        self.txt_console.delete("1.0", "end")
        self.txt_console.configure(state="disabled")

    # -------------------------------------------------------------
    # GESTIÓN DE TEMAS Y TAGS TREEVIEW
    # -------------------------------------------------------------
    def _update_all_treeview_tags(self, effective_mode: str):
        is_light = str(effective_mode).lower() == "light"
        even_bg = "#ffffff" if is_light else "#0f172a"
        odd_bg = "#f1f5f9" if is_light else "#1e293b"
        pub_fg = "#0284c7" if is_light else "#38bdf8"
        blk_fg = "#dc2626" if is_light else "#f85149"
        ok_fg = "#16a34a" if is_light else "#3fb950"
        
        for t in (self.tree, self.tree_lan, self.tree_access, self.tree_restrictions, self.tree_sentinel_ports, self.tree_sentinel_eviltwin, self.tree_auditor):
            t.tag_configure("even", background=even_bg)
            t.tag_configure("odd", background=odd_bg)
            t.tag_configure("public", foreground=pub_fg)
            t.tag_configure("blocked", foreground=blk_fg)
            t.tag_configure("allowed", foreground=ok_fg)
            t.tag_configure("accessible", foreground=ok_fg)

    def _on_theme_changed(self, new_theme: str):
        ctk.set_appearance_mode(new_theme)
        effective_mode = ctk.get_appearance_mode()
        
        configure_treeview_style(effective_mode)
        self._update_all_treeview_tags(effective_mode)
        self._apply_table_filters()
        self.refresh_lan_table_ui()
        self.refresh_access_control_ui()
        self.refresh_restrictions_table_ui()
        
        self.config["theme"] = new_theme
        save_config(self.config)
        self.log_message(f"[CONFIG] Modo de apariencia cambiado a '{new_theme}'.", "INFO")

    # -------------------------------------------------------------
    # MÓDULO AUDITORÍA & HARDENING DE RED
    # -------------------------------------------------------------
    def on_load_my_local_ip(self):
        local_ip = get_local_ip()
        self.entry_audit_target.delete(0, "end")
        self.entry_audit_target.insert(0, local_ip)

    def start_device_audit_async(self):
        target_ip = self.entry_audit_target.get().strip()
        if not target_ip:
            messagebox.showwarning("IP Requerida", "Ingrese una IP objetivo válida para auditar.")
            return
            
        self.btn_start_audit.configure(state="disabled", text="⏳ Auditando Puertos...")
        self.log_message(f"[AUDITORÍA HOST] Iniciando escaneo de seguridad y hardening sobre {target_ip}...", "INFO")
        threading.Thread(target=self._device_audit_worker, args=(target_ip,), daemon=True).start()

    def _device_audit_worker(self, target_ip: str):
        try:
            results = scan_device_security(target_ip)
            cleartext_warnings = audit_cleartext_protocols(target_ip, results)
            self.after(0, self._update_auditor_ui, target_ip, results, cleartext_warnings)
        except Exception as e:
            self.after(0, self.log_message, f"[AUDITORÍA HOST] Error durante la auditoría: {str(e)}", "ERROR")
            self.after(0, self._reset_auditor_button)

    def _update_auditor_ui(self, target_ip: str, results: list[dict], cleartext_warnings: list[dict]):
        for item in self.tree_auditor.get_children():
            self.tree_auditor.delete(item)

        open_count = sum(1 for r in results if r["is_open"])
        self.log_message(f"[AUDITORÍA HOST] Análisis completado en {target_ip}. {open_count} puertos abiertos detectados.", "SUCCESS")
        
        if cleartext_warnings:
            for w in cleartext_warnings:
                self.log_message(f"[HARDENING] [{w['severity']}] {w['title']}: {w['desc']} Recomendación: {w['recommendation']}", "WARNING")

        for idx, r in enumerate(results):
            port = r["port"]
            service = r["service"]
            status = r["status"]
            banner = r["banner"]
            
            tag = "blocked" if r["is_open"] and port in (21, 23, 139, 445) else ("allowed" if r["is_open"] else "even")
            self.tree_auditor.insert("", "end", values=(port, service, status, banner), tags=(tag,))

        self._reset_auditor_button()

    def _reset_auditor_button(self):
        self.btn_start_audit.configure(state="normal", text="🔍 Iniciar Auditoría de Puertos y Servicios")

    def on_isolate_target_clicked(self):
        target_ip = self.entry_audit_target.get().strip()
        if not target_ip:
            messagebox.showwarning("IP Requerida", "Especifique una IP objetivo para aislar en el cortafuegos.")
            return
            
        if not messagebox.askyesno(
            "Confirmar Aislamiento Local",
            f"¿Bloquear todo el tráfico entrante y saliente hacia/desde la IP {target_ip} en el Firewall de Windows?",
            icon="warning"
        ):
            return
            
        threading.Thread(target=self._isolate_target_worker, args=(target_ip,), daemon=True).start()

    def _isolate_target_worker(self, target_ip: str):
        success, msg = isolate_host_local_firewall(target_ip)
        self.after(0, self.log_message, msg, "SUCCESS" if success else "ERROR")
        self.after(0, messagebox.showinfo if success else messagebox.showerror, "Aislamiento Host", msg)

    def on_lan_audit_host_clicked(self):
        row = self._get_selected_lan_row()
        if not row:
            return
        ip, mac, host, vendor, dtype, status = row
        self.entry_audit_target.delete(0, "end")
        self.entry_audit_target.insert(0, ip)
        self.switch_tab("auditor")
        self.start_device_audit_async()

    # -------------------------------------------------------------
    # MÓDULO CENTINELA WI-FI (IDS DEFENSIVO)
    # -------------------------------------------------------------
    def refresh_sentinel_gateway_info_async(self):
        threading.Thread(target=self._sentinel_gw_worker, daemon=True).start()

    def _sentinel_gw_worker(self):
        try:
            info = get_gateway_info()
            self.after(0, self._update_sentinel_gw_ui, info)
        except Exception as e:
            pass

    def _update_sentinel_gw_ui(self, info: dict):
        self.gateway_cache = info
        gw_ip = info.get("gateway_ip", "192.168.1.1")
        gw_mac = info.get("gateway_mac", "Desconocida")
        ssid = info.get("ssid", "No conectado")
        bssid = info.get("bssid", "N/A")
        channel = info.get("channel", "N/A")
        signal = info.get("signal", "N/A")
        
        self.lbl_sentinel_gw_ip.configure(text=f"Gateway IP: {gw_ip}")
        self.lbl_sentinel_gw_mac.configure(text=f"MAC Router: {gw_mac}")
        self.lbl_sentinel_ssid.configure(text=f"SSID: {ssid}")
        self.lbl_sentinel_bssid.configure(text=f"BSSID: {bssid} | Canal: {channel} ({signal})")

    def on_toggle_arp_guard(self):
        if self.switch_arp_guard.get() == 1:
            self.arp_guard_active = True
            self.arp_guard_stop_event.clear()
            auto_fix = (self.chk_auto_fix.get() == 1)
            
            self.lbl_sentinel_shield_status.configure(text="ACTIVO 🛡️", text_color=COLOR_SUCCESS)
            self.log_message(f"[IDS CENTINELA] Escudo Anti-ARP Spoofing ACTIVADO (Autoprotección: {auto_fix}).", "SUCCESS")
            
            self.arp_guard_thread = threading.Thread(
                target=start_arp_guard,
                args=(self._on_arp_spoof_detected, self.arp_guard_stop_event, auto_fix),
                daemon=True
            )
            self.arp_guard_thread.start()
        else:
            self.arp_guard_active = False
            self.arp_guard_stop_event.set()
            self.lbl_sentinel_shield_status.configure(text="INACTIVO ⚠️", text_color=COLOR_WARNING)
            self.log_message("[IDS CENTINELA] Escudo Anti-ARP Spoofing DESACTIVADO.")

    def _on_arp_spoof_detected(self, alert_msg: str, attacker_mac: str):
        self.after(0, self.lbl_sentinel_shield_status.configure, {"text": "🚨 ATAQUE DETECTADO", "text_color": "#ef4444"})
        self.after(0, self.log_message, alert_msg, "DANGER")
        self.after(0, messagebox.showerror, "🚨 ALERTA DE CIBERSEGURIDAD: MITM DETECTADO", alert_msg)

    def start_gateway_audit_async(self):
        self.log_message("[IDS CENTINELA] Iniciando auditoría de puertos críticos del router...", "INFO")
        threading.Thread(target=self._gateway_audit_worker, daemon=True).start()

    def _gateway_audit_worker(self):
        try:
            gw_ip = self.gateway_cache.get("gateway_ip") or get_gateway_ip()
            results = audit_gateway_security(gw_ip)
            self.after(0, self._update_sentinel_ports_ui, results)
        except Exception as e:
            self.after(0, self.log_message, f"[IDS CENTINELA] Error en auditoría de router: {str(e)}", "ERROR")

    def _update_sentinel_ports_ui(self, results: list[dict]):
        for item in self.tree_sentinel_ports.get_children():
            self.tree_sentinel_ports.delete(item)

        open_critical = sum(1 for r in results if r["is_open"] and r["risk_level"] in ("CRÍTICO", "ALTO"))
        if open_critical > 0:
            self.log_message(f"[IDS CENTINELA] Auditoría finalizada: ¡Atención! Se encontraron {open_critical} puertos críticos expuestos en el router.", "WARNING")
        else:
            self.log_message("[IDS CENTINELA] Auditoría de puertos del router finalizada. No se detectaron vulnerabilidades críticas abiertas.", "SUCCESS")

        for idx, r in enumerate(results):
            port = r["port"]
            service = r["service"]
            status = r["status"]
            risk = r["risk_level"]
            rec = r["recommendation"]
            
            tag = "blocked" if r["is_open"] and risk in ("CRÍTICO", "ALTO") else ("allowed" if not r["is_open"] else "even")
            self.tree_sentinel_ports.insert("", "end", values=(port, service, status, risk, rec), tags=(tag,))

        self.tabview_sentinel.set("🔒 Hardening de Puertos Router")

    def start_evil_twin_scan_async(self):
        self.log_message("[IDS CENTINELA] Auditando espectro Wi-Fi en busca de redes clonadas (Evil Twin)...", "INFO")
        threading.Thread(target=self._evil_twin_worker, daemon=True).start()

    def _evil_twin_worker(self):
        try:
            findings = detect_evil_twin()
            self.after(0, self._update_sentinel_eviltwin_ui, findings)
        except Exception as e:
            self.after(0, self.log_message, f"[IDS CENTINELA] Error al buscar redes gemelas: {str(e)}", "ERROR")

    def _update_sentinel_eviltwin_ui(self, findings: list[dict]):
        for item in self.tree_sentinel_eviltwin.get_children():
            self.tree_sentinel_eviltwin.delete(item)

        suspicious_count = sum(1 for f in findings if f["is_suspicious"])
        if suspicious_count > 0:
            self.log_message(f"[IDS CENTINELA] 🚨 ¡ALERTA DE SEGURIDAD! Se detectaron {suspicious_count} posibles redes clonadas (Evil Twin).", "DANGER")
        else:
            self.log_message(f"[IDS CENTINELA] Auditoría Wi-Fi completada. {len(findings)} BSSIDs inspeccionados. Sin anomalías de Evil Twin.", "SUCCESS")

        for idx, f in enumerate(findings):
            ssid = f["ssid"]
            bssid = f["bssid"]
            auth = f["auth"]
            status = f["status"]
            details = f["details"]
            
            tag = "blocked" if f["is_suspicious"] else "even"
            self.tree_sentinel_eviltwin.insert("", "end", values=(ssid, bssid, auth, status, details), tags=(tag,))

        self.tabview_sentinel.set("📡 Espectro Wi-Fi & Rogue AP")

    def on_wifi_kill_clicked(self):
        if not messagebox.askyesno(
            "🛑 AISLAMIENTO WI-FI DE EMERGENCIA",
            "⚠️ ¿CONFIRMA EL DESCONECTAR Y DESHABILITAR INMEDIATAMENTE EL ADAPTADOR WI-FI?\n\nEsta acción cortará toda la conectividad inalámbrica ante un ataque activo.",
            icon="warning"
        ):
            return
        threading.Thread(target=self._wifi_kill_worker, daemon=True).start()

    def _wifi_kill_worker(self):
        success, msg = emergency_wifi_disconnect()
        self.after(0, self.log_message, msg, "DANGER" if success else "ERROR")
        self.after(0, messagebox.showwarning if success else messagebox.showerror, "Aislamiento Wi-Fi", msg)
        self.refresh_sentinel_gateway_info_async()

    # -------------------------------------------------------------
    # MÓDULO TELEMETRÍA DE SOCKETS
    # -------------------------------------------------------------
    def start_scan_async(self):
        self.btn_scan.configure(state="disabled", text="⏳ Escaneando...")
        self.lbl_status.configure(text="Capturando sockets activos...", text_color=COLOR_CYAN)
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            conns = get_active_connections()
            public_ips = set()
            for c in conns:
                if not c["is_private"] and c["remote_ip"] != "-":
                    public_ips.add(c["remote_ip"])
            
            geo_results = {}
            if public_ips:
                futures = {ip: self.executor.submit(lookup_ip, ip) for ip in public_ips}
                for ip, f in futures.items():
                    try:
                        geo_results[ip] = f.result()
                    except Exception:
                        geo_results[ip] = {"country": "Error", "city": "Error", "isp": "N/A"}
            
            processed = []
            for c in conns:
                ip = c["remote_ip"]
                if c["is_private"]:
                    geo_str = "Local / LAN"
                else:
                    g = geo_results.get(ip, {})
                    country = g.get("country", "Pública")
                    city = g.get("city", "")
                    isp = g.get("isp", "")
                    geo_str = f"{country} ({city}) - {isp}".strip(" -")
                    
                c["geo_str"] = geo_str
                processed.append(c)
                
            self.after(0, self._update_ui_with_connections, processed)
        except Exception as e:
            self.after(0, self.log_message, f"Error en escaneo de sockets: {str(e)}", "ERROR")
            self.after(0, self._reset_scan_button)

    def _update_ui_with_connections(self, connections):
        self.current_connections = connections
        total_count = len(connections)
        remote_active_count = sum(1 for c in connections if c["remote_ip"] != "-")
        pids_connected = len(set(c["pid"] for c in connections if c["pid"] > 0))
        public_count = sum(1 for c in connections if not c["is_private"] and c["remote_ip"] != "-")
        
        self.card_total.configure(text=str(total_count))
        self.card_remote.configure(text=str(remote_active_count))
        self.card_procs.configure(text=str(pids_connected))
        self.card_public.configure(text=str(public_count))
        
        self.lbl_status.configure(text=f"Último escaneo: {datetime.datetime.now().strftime('%H:%M:%S')}", text_color=COLOR_SUCCESS)
        self._apply_table_filters()
        self._reset_scan_button()

    def _reset_scan_button(self):
        self.btn_scan.configure(state="normal", text="🔍 Escanear Sockets")

    def _set_status_filter(self, filter_mode: str):
        self.active_status_filter = filter_mode
        self.btn_filter_all.configure(fg_color=COLOR_ACCENT if filter_mode == "ALL" else COLOR_CARD_INNER, text_color="#ffffff" if filter_mode == "ALL" else COLOR_TEXT_MAIN)
        self.btn_filter_estab.configure(fg_color=COLOR_ACCENT if filter_mode == "ESTABLISHED" else COLOR_CARD_INNER, text_color="#ffffff" if filter_mode == "ESTABLISHED" else COLOR_TEXT_MAIN)
        self.btn_filter_listen.configure(fg_color=COLOR_ACCENT if filter_mode == "LISTEN" else COLOR_CARD_INNER, text_color="#ffffff" if filter_mode == "LISTEN" else COLOR_TEXT_MAIN)
        self._apply_table_filters()

    def _on_search_key_release(self, event=None):
        self.search_query = self.entry_search.get().strip().lower()
        self._apply_table_filters()

    def _apply_table_filters(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        query = self.search_query
        filtered = []

        for conn in self.current_connections:
            status = conn.get("status", "").upper()
            remote_ip = conn.get("remote_ip", "-")

            if self.active_status_filter == "ESTABLISHED" and (status != "ESTABLISHED" and remote_ip == "-"):
                continue
            elif self.active_status_filter == "LISTEN" and status != "LISTEN":
                continue

            if query:
                pid_str = str(conn.get("pid", ""))
                proc_name = str(conn.get("process_name", "")).lower()
                remote_ip_str = str(conn.get("remote_ip", "")).lower()
                geo_str = str(conn.get("geo_str", "")).lower()

                if not (query in pid_str or query in proc_name or query in remote_ip_str or query in geo_str):
                    continue

            filtered.append(conn)

        for idx, conn in enumerate(filtered):
            tag = "even" if idx % 2 == 0 else "odd"
            if not conn["is_private"] and conn["remote_ip"] != "-":
                tag = "public"

            self.tree.insert("", "end", values=(
                conn["pid"], conn["process_name"], conn["protocol"], conn["remote_ip"],
                conn["remote_port"], conn["geo_str"], conn["status"]
            ), tags=(tag,))

    def on_export_audit_clicked(self):
        if not self.current_connections:
            messagebox.showwarning("Sin Datos", "No hay conexiones capturadas para exportar.")
            return

        filepath = filedialog.asksaveasfilename(
            title="Exportar Auditoría Forense de Red",
            defaultextension=".csv",
            filetypes=[("Archivo CSV (*.csv)", "*.csv"), ("Archivo JSON (*.json)", "*.json")]
        )
        if not filepath:
            return

        try:
            if filepath.lower().endswith(".json"):
                export_data = {
                    "suite": "KILLNet Network Forensics",
                    "export_timestamp": datetime.datetime.now().isoformat(),
                    "admin_privileges": self.is_admin_user,
                    "total_sockets": len(self.current_connections),
                    "connections": self.current_connections
                }
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
            else:
                with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
                    writer = csv.writer(f)
                    writer.writerow(["PID", "Proceso", "Ruta", "Protocolo", "Direccion_Local", "Direccion_Remota", "GeoIP", "Estado"])
                    for c in self.current_connections:
                        writer.writerow([c.get("pid"), c.get("process_name"), c.get("process_path"), c.get("protocol"), c.get("local_address"), c.get("remote_address"), c.get("geo_str"), c.get("status")])

            self.log_message(f"[AUDITORÍA] Snapshot exportado a '{os.path.basename(filepath)}'.", "SUCCESS")
            messagebox.showinfo("Exportación Exitosa", f"Auditoría exportada correctamente en:\n{filepath}")
        except Exception as e:
            self.log_message(f"[ERROR] Fallo al exportar: {str(e)}", "ERROR")

    def toggle_auto_monitor(self):
        self.is_auto_monitoring = not self.is_auto_monitoring
        if self.is_auto_monitoring:
            self.btn_auto_monitor.configure(text="📡 Monitoreo En Vivo [ON]", fg_color=COLOR_SUCCESS, text_color="#ffffff")
            self.log_message("[MONITOREO] Monitoreo automático ACTIVADO (3s).", "SUCCESS")
            self._schedule_auto_scan()
        else:
            self.btn_auto_monitor.configure(text="📡 Monitoreo En Vivo [OFF]", fg_color=COLOR_CARD, text_color=COLOR_TEXT_MAIN)
            self.log_message("[MONITOREO] Monitoreo automático DESACTIVADO.")

    def _schedule_auto_scan(self):
        if self.is_auto_monitoring:
            self.start_scan_async()
            self.after(3000, self._schedule_auto_scan)

    def _get_selected_socket_row(self):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Selección Requerida", "Seleccione una fila de la tabla de sockets.")
            return None
        return self.tree.item(selected_items[0], "values")

    def on_block_ip_clicked(self):
        row = self._get_selected_socket_row()
        if not row:
            return
        pid, proc, proto, remote_ip, remote_port, geo, status = row
        if not remote_ip or remote_ip in ("-", "*", "127.0.0.1", "0.0.0.0"):
            messagebox.showerror("IP Inválida", "La conexión no posee una IP remota válida para bloquear.")
            return
        if not messagebox.askyesno("Bloquear IP", f"¿Crear regla de bloqueo de salida en Firewall de Windows para:\n{remote_ip} ({geo})?"):
            return
        threading.Thread(target=self._block_ip_worker, args=(remote_ip,), daemon=True).start()

    def _block_ip_worker(self, ip_address):
        success, msg = block_remote_ip(ip_address)
        self.after(0, self.log_message, msg, "SUCCESS" if success else "ERROR")
        self.after(0, messagebox.showinfo if success else messagebox.showerror, "Bloqueo de IP", msg)
        self.start_scan_async()

    def on_kill_proc_clicked(self):
        row = self._get_selected_socket_row()
        if not row:
            return
        pid_str, proc_name = row[0], row[1]
        try:
            pid = int(pid_str)
        except ValueError:
            return
        if pid <= 0:
            messagebox.showerror("Error", "No se pueden terminar procesos de sistema o PID <= 0.")
            return
        if not messagebox.askyesno("Terminar Proceso", f"¿Terminar forzosamente '{proc_name}' (PID: {pid})?"):
            return
        threading.Thread(target=self._kill_proc_worker, args=(pid,), daemon=True).start()

    def _kill_proc_worker(self, pid):
        success, msg = kill_process_by_pid(pid)
        self.after(0, self.log_message, msg, "SUCCESS" if success else "ERROR")
        self.after(0, messagebox.showinfo if success else messagebox.showerror, "Terminar Proceso", msg)
        self.start_scan_async()

    # -------------------------------------------------------------
    # MÓDULO ESCÁNER DE RED LOCAL
    # -------------------------------------------------------------
    def start_lan_scan_async(self):
        self.btn_scan_lan.configure(state="disabled", text="⏳ Escaneando Red...")
        self.lbl_lan_info.configure(text="Enviando ping sweep y resolviendo ARP de subred...", text_color=COLOR_CYAN)
        threading.Thread(target=self._lan_scan_worker, daemon=True).start()

    def _lan_scan_worker(self):
        try:
            devices = scan_lan_devices()
            self.after(0, self._update_lan_ui, devices)
        except Exception as e:
            self.after(0, self.log_message, f"[LAN] Error durante escaneo LAN: {str(e)}", "ERROR")
            self.after(0, self._reset_lan_button)

    def _update_lan_ui(self, devices):
        self.lan_devices = devices
        local_ip = get_local_ip()
        gateway_ip = next((d["ip"] for d in devices if d.get("is_gateway")), f"{local_ip.rsplit('.', 1)[0]}.1")
        
        self.lbl_lan_info.configure(
            text=f"Local IP: {local_ip} | Gateway: {gateway_ip} | Dispositivos Detectados: {len(devices)}",
            text_color=COLOR_SUCCESS
        )
        self.log_message(f"[LAN] Escaneo Wi-Fi/LAN finalizado. {len(devices)} dispositivos encontrados.", "SUCCESS")
        self.refresh_lan_table_ui()
        self._reset_lan_button()

    def _reset_lan_button(self):
        self.btn_scan_lan.configure(state="normal", text="🔍 Escanear Red Wi-Fi / LAN")

    def refresh_lan_table_ui(self):
        for item in self.tree_lan.get_children():
            self.tree_lan.delete(item)

        for idx, dev in enumerate(self.lan_devices):
            ip = dev["ip"]
            mac = dev["mac"]
            host = dev["hostname"]
            vendor = dev["vendor"]
            dtype = dev["device_type"]
            is_local = dev["is_local"]
            
            is_allowed, policy_msg = is_device_allowed(mac, ip)
            if is_local:
                status_str = "Mi PC (Local)"
                tag = "allowed"
            elif not is_allowed:
                status_str = "🚫 Bloqueado"
                tag = "blocked"
            else:
                status_str = "✅ Autorizado"
                tag = "even" if idx % 2 == 0 else "odd"

            self.tree_lan.insert("", "end", values=(ip, mac, host, vendor, dtype, status_str), tags=(tag,))

    def _get_selected_lan_row(self):
        selected_items = self.tree_lan.selection()
        if not selected_items:
            messagebox.showwarning("Selección Requerida", "Seleccione un dispositivo de la tabla de Red Local.")
            return None
        return self.tree_lan.item(selected_items[0], "values")

    def on_lan_block_clicked(self):
        row = self._get_selected_lan_row()
        if not row:
            return
        ip, mac, host, vendor, dtype, status = row
        if not messagebox.askyesno("Bloquear Dispositivo", f"¿Bloquear todo el tráfico con la IP local {ip} ({host}) en el Firewall de Windows?"):
            return
        threading.Thread(target=self._lan_block_worker, args=(ip, host), daemon=True).start()

    def _lan_block_worker(self, ip, alias):
        success, msg = block_ip_host(ip, alias)
        self.after(0, self.log_message, msg, "SUCCESS" if success else "ERROR")
        self.after(0, messagebox.showinfo if success else messagebox.showerror, "Bloqueo de Red Local", msg)
        self.after(0, self.refresh_lan_table_ui)

    def on_lan_add_blacklist_clicked(self):
        row = self._get_selected_lan_row()
        if not row:
            return
        ip, mac, host, vendor, dtype, status = row
        success, msg = add_or_update_device_rule(mac, ip, host, "blocked")
        self.log_message(f"[ACCESO] {msg}", "WARNING")
        messagebox.showinfo("Blacklist Actualizada", msg)
        self.refresh_lan_table_ui()
        self.refresh_access_control_ui()

    def on_lan_add_whitelist_clicked(self):
        row = self._get_selected_lan_row()
        if not row:
            return
        ip, mac, host, vendor, dtype, status = row
        success, msg = add_or_update_device_rule(mac, ip, host, "allowed")
        self.log_message(f"[ACCESO] {msg}", "SUCCESS")
        messagebox.showinfo("Whitelist Actualizada", msg)
        self.refresh_lan_table_ui()
        self.refresh_access_control_ui()

    # -------------------------------------------------------------
    # MÓDULO CONTROL DE ACCESO (BLACK/WHITE LIST)
    # -------------------------------------------------------------
    def refresh_access_control_ui(self):
        rules = load_access_rules()
        mode = rules.get("mode", "blacklist")
        devices = rules.get("devices", [])
        
        mode_label = "Blacklist Mode" if mode == "blacklist" else "Whitelist Mode"
        if self.seg_access_mode.get() != mode_label:
            self.seg_access_mode.set(mode_label)
            
        for item in self.tree_access.get_children():
            self.tree_access.delete(item)

        for idx, d in enumerate(devices):
            mac = d.get("mac", "N/A")
            ip = d.get("ip", "-")
            alias = d.get("alias", "Dispositivo")
            status = d.get("status", "allowed")
            
            is_allowed, compliance_msg = is_device_allowed(mac, ip)
            tag = "allowed" if is_allowed else "blocked"

            self.tree_access.insert("", "end", values=(mac, ip, alias, status.upper(), compliance_msg), tags=(tag,))

    def on_access_mode_changed(self, value: str):
        new_mode = "blacklist" if "Blacklist" in value else "whitelist"
        set_access_control_mode(new_mode)
        self.log_message(f"[ACCESO] Modo cambiado a '{new_mode.upper()}'.", "INFO")
        self.refresh_access_control_ui()
        self.refresh_lan_table_ui()

    def set_selected_access_status(self, new_status: str):
        selected = self.tree_access.selection()
        if not selected:
            messagebox.showwarning("Selección Requerida", "Seleccione una regla de la tabla.")
            return
        values = self.tree_access.item(selected[0], "values")
        mac, ip, alias, old_status, comp = values
        
        success, msg = add_or_update_device_rule(mac, ip, alias, new_status)
        self.log_message(f"[ACCESO] {msg}", "SUCCESS" if success else "ERROR")
        self.refresh_access_control_ui()
        self.refresh_lan_table_ui()

    def on_delete_access_rule_clicked(self):
        selected = self.tree_access.selection()
        if not selected:
            messagebox.showwarning("Selección Requerida", "Seleccione una regla para eliminar.")
            return
        values = self.tree_access.item(selected[0], "values")
        mac, ip, alias, status, comp = values
        
        target = mac if mac != "N/A" else ip
        if messagebox.askyesno("Eliminar Regla", f"¿Eliminar la regla de acceso para '{alias}' ({target})?"):
            success, msg = remove_device_rule(target)
            self.log_message(f"[ACCESO] {msg}", "INFO")
            self.refresh_access_control_ui()
            self.refresh_lan_table_ui()

    def open_add_access_rule_modal(self):
        modal = ctk.CTkToplevel(self)
        modal.title("➕ Agregar Regla de Control de Acceso")
        modal.configure(fg_color=COLOR_BG)
        modal.transient(self)
        modal.grab_set()
        
        self._center_modal(modal, 420, 380)
        
        lbl_t = ctk.CTkLabel(modal, text="➕ Agregar Dispositivo a la Lista", font=("Segoe UI", 14, "bold"), text_color=COLOR_CYAN)
        lbl_t.pack(pady=(16, 10))
        
        ctk.CTkLabel(modal, text="Dirección MAC (XX:XX:XX:XX:XX:XX):", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=30, pady=(4, 2))
        entry_mac = ctk.CTkEntry(modal, placeholder_text="AA:BB:CC:DD:EE:FF", fg_color=COLOR_CARD, text_color=COLOR_TEXT_MAIN)
        entry_mac.pack(fill="x", padx=30, pady=(0, 8))
        
        ctk.CTkLabel(modal, text="Dirección IP Local (Opcional):", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=30, pady=(4, 2))
        entry_ip = ctk.CTkEntry(modal, placeholder_text="192.168.1.50", fg_color=COLOR_CARD, text_color=COLOR_TEXT_MAIN)
        entry_ip.pack(fill="x", padx=30, pady=(0, 8))
        
        ctk.CTkLabel(modal, text="Alias / Nombre del Dispositivo:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=30, pady=(4, 2))
        entry_alias = ctk.CTkEntry(modal, placeholder_text="Teléfono Personal", fg_color=COLOR_CARD, text_color=COLOR_TEXT_MAIN)
        entry_alias.pack(fill="x", padx=30, pady=(0, 8))
        
        ctk.CTkLabel(modal, text="Estado de la Regla:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=30, pady=(4, 2))
        opt_status = ctk.CTkOptionMenu(modal, values=["blocked", "allowed"], fg_color=COLOR_CARD, button_color=COLOR_BORDER, text_color=COLOR_TEXT_MAIN)
        opt_status.pack(fill="x", padx=30, pady=(0, 16))
        
        def save_rule():
            mac_val = entry_mac.get().strip()
            ip_val = entry_ip.get().strip()
            alias_val = entry_alias.get().strip()
            status_val = opt_status.get()
            
            if not mac_val and not ip_val:
                messagebox.showwarning("Campos Requeridos", "Debe proporcionar al menos una MAC o una IP válida.")
                return
                
            success, msg = add_or_update_device_rule(mac_val, ip_val, alias_val, status_val)
            self.log_message(f"[ACCESO] {msg}", "SUCCESS" if success else "ERROR")
            self.refresh_access_control_ui()
            self.refresh_lan_table_ui()
            modal.destroy()
            
        btn_save = ctk.CTkButton(modal, text="Guardar Regla", font=("Segoe UI", 11, "bold"), fg_color=COLOR_ACCENT, command=save_rule)
        btn_save.pack(fill="x", padx=30)

    # -------------------------------------------------------------
    # MÓDULO DIAGNÓSTICO DE RESTRICCIONES
    # -------------------------------------------------------------
    def start_restriction_test_async(self):
        self.btn_test_restrictions.configure(state="disabled", text="⏳ Evaluando Red...")
        threading.Thread(target=self._restriction_worker, daemon=True).start()

    def _restriction_worker(self):
        try:
            results = run_restriction_diagnostics()
            self.after(0, self._update_restriction_ui, results)
        except Exception as e:
            self.after(0, self.log_message, f"[DIAGNÓSTICO] Error en pruebas de red: {str(e)}", "ERROR")
            self.after(0, self._reset_restriction_button)

    def _update_restriction_ui(self, results):
        self.restriction_results = results
        blocked_count = sum(1 for r in results if r["status"] != "ACCESIBLE")
        
        if blocked_count > 0:
            self.log_message(f"[DIAGNÓSTICO] Se detectaron {blocked_count} servicios bloqueados o restringidos en la red.", "WARNING")
        else:
            self.log_message("[DIAGNÓSTICO] Todos los servicios de prueba se encuentran ACCESIBLES.", "SUCCESS")
            
        self.refresh_restrictions_table_ui()
        self._reset_restriction_button()

    def _reset_restriction_button(self):
        self.btn_test_restrictions.configure(state="normal", text="⚡ Testear Restricciones de Red")

    def refresh_restrictions_table_ui(self):
        for item in self.tree_restrictions.get_children():
            self.tree_restrictions.delete(item)

        for r in self.restriction_results:
            cat = r["category"]
            target = r["target"]
            status = r["status"]
            cause = r["cause"]
            ip = r["ip"]
            details = r["details"]
            
            tag = "accessible" if status == "ACCESIBLE" else "blocked"
            self.tree_restrictions.insert("", "end", values=(cat, target, status, cause, ip, details), tags=(tag,))

    def on_apply_secure_dns_clicked(self):
        if not messagebox.askyesno("DNS Seguros", "¿Configurar DNS públicos de Cloudflare (1.1.1.1 / 1.0.0.1) para evitar bloqueos por DNS?"):
            return
        threading.Thread(target=self._apply_dns_worker, daemon=True).start()

    def _apply_dns_worker(self):
        success, msg = apply_secure_dns()
        self.after(0, self.log_message, msg, "SUCCESS" if success else "ERROR")
        self.after(0, messagebox.showinfo if success else messagebox.showerror, "Bypass Bloqueo DNS", msg)
        self.start_restriction_test_async()

    def on_reset_dns_clicked(self):
        if not messagebox.askyesno("Restaurar DNS", "¿Restaurar la obtención automática de DNS (DHCP)?"):
            return
        threading.Thread(target=self._reset_dns_worker, daemon=True).start()

    def _reset_dns_worker(self):
        success, msg = reset_dns_dhcp()
        self.after(0, self.log_message, msg, "SUCCESS" if success else "ERROR")
        self.after(0, messagebox.showinfo if success else messagebox.showerror, "Restaurar DNS", msg)
        self.start_restriction_test_async()

    def on_clean_hosts_clicked(self):
        blocked = check_hosts_file()
        if not blocked:
            messagebox.showinfo("Archivo Hosts Limpio", "No se encontraron redirecciones de bloqueo en C:\\Windows\\System32\\drivers\\etc\\hosts.")
            return
            
        domains_list = "\n".join(f"- {b['domain']} ({b['ip']})" for b in blocked)
        if messagebox.askyesno("Limpiar Hosts", f"Se detectaron las siguientes entradas de bloqueo:\n\n{domains_list}\n\n¿Desea eliminarlas automáticamente?"):
            threading.Thread(target=self._clean_hosts_worker, daemon=True).start()

    def _clean_hosts_worker(self):
        success, msg = clean_hosts_file()
        self.after(0, self.log_message, f"[HOSTS] {msg}", "SUCCESS" if success else "ERROR")
        self.after(0, messagebox.showinfo if success else messagebox.showerror, "Limpieza de Hosts", msg)
        self.start_restriction_test_async()

    # -------------------------------------------------------------
    # MODO PÁNICO Y AISLAMIENTO
    # -------------------------------------------------------------
    def on_toggle_emergency_isolation(self):
        if not self.is_emergency_isolated:
            if not messagebox.askyesno(
                "🚨 ALERTA: Modo Pánico",
                "¿DESEA ACTIVAR EL MODO PÁNICO Y CORTAR TODO EL TRÁFICO SALIENTE DE RED?\n\nSe creará una regla temporal global en Windows Firewall.",
                icon="warning"
            ):
                return
            threading.Thread(target=self._isolate_worker, args=(True,), daemon=True).start()
        else:
            if not messagebox.askyesno("Restaurar Conectividad", "¿Desactivar el Modo Pánico y restaurar el tráfico de red?"):
                return
            threading.Thread(target=self._isolate_worker, args=(False,), daemon=True).start()

    def _isolate_worker(self, enable_isolation: bool):
        success, msg = toggle_panic_mode(block=enable_isolation)
        if enable_isolation:
            if success:
                self.is_emergency_isolated = True
                self.after(0, self._update_emergency_btn_state, True)
                self.after(0, self.log_message, msg, "DANGER")
                self.after(0, messagebox.showwarning, "Modo Pánico Activado", msg)
            else:
                self.after(0, self.log_message, msg, "ERROR")
                self.after(0, messagebox.showerror, "Error de Aislamiento", msg)
        else:
            if success:
                self.is_emergency_isolated = False
                self.after(0, self._update_emergency_btn_state, False)
                self.after(0, self.log_message, msg, "SUCCESS")
                self.after(0, messagebox.showinfo, "Red Restaurada", msg)
            else:
                self.after(0, self.log_message, msg, "ERROR")
                self.after(0, messagebox.showerror, "Error al Desaislar", msg)

    def _update_emergency_btn_state(self, isolated: bool):
        if isolated:
            self.btn_emergency.configure(text="🔓 Desactivar Modo Pánico", fg_color=COLOR_WARNING, hover_color="#b7791f")
        else:
            self.btn_emergency.configure(text="🚨 Modo Pánico (Aislamiento)", fg_color=COLOR_DANGER, hover_color="#c0392b")

    # -------------------------------------------------------------
    # MODALES: DONACIÓN, SUPPORT & MANUAL
    # -------------------------------------------------------------
    def open_donation_modal(self):
        modal = ctk.CTkToplevel(self)
        modal.title("☕ Apoyar el Proyecto KILLNet")
        modal.configure(fg_color=COLOR_BG)
        modal.transient(self)
        modal.grab_set()
        
        self._center_modal(modal, 460, 340)
        
        lbl_title = ctk.CTkLabel(modal, text="☕ Apoyar el Proyecto KILLNet", font=("Segoe UI", 16, "bold"), text_color="#eab308")
        lbl_title.pack(pady=(22, 10))
        
        card_info = ctk.CTkFrame(modal, fg_color=COLOR_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        card_info.pack(fill="x", padx=25, pady=(0, 15))
        
        lbl_desc = ctk.CTkLabel(
            card_info, text="KILLNet es una herramienta forense de red gratuita y de código abierto.\n\nSi te ha resultado útil para auditorías de telemetría y seguridad en tu sistema, puedes apoyar directamente su desarrollo continuo.",
            font=FONT_BODY, justify="center", text_color=COLOR_TEXT_MAIN, wraplength=380
        )
        lbl_desc.pack(padx=15, pady=15)
        
        btn_cafecito = ctk.CTkButton(
            modal, text="☕ Donar en Cafecito (Argentina)", font=("Segoe UI", 11, "bold"),
            fg_color="#eab308", hover_color="#ca8a04", text_color="#1c1917", height=38, command=lambda: webbrowser.open("https://cafecito.app/cristian_dev")
        )
        btn_cafecito.pack(fill="x", padx=25, pady=5)
        
        btn_github = ctk.CTkButton(
            modal, text="⭐ Ver Proyecto en GitHub", font=("Segoe UI", 11, "bold"),
            fg_color=COLOR_CARD, hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MAIN, border_width=1, border_color=COLOR_BORDER, height=38, command=lambda: webbrowser.open("https://github.com/CristianNLC/KILLNet")
        )
        btn_github.pack(fill="x", padx=25, pady=5)
        
        btn_close = ctk.CTkButton(modal, text="Cerrar", font=FONT_BODY, fg_color="transparent", hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MUTED, height=28, command=modal.destroy)
        btn_close.pack(pady=(10, 0))

    def open_feedback_modal(self):
        modal = ctk.CTkToplevel(self)
        modal.title("💬 Soporte & Buzón de Dudas - KILLNet")
        modal.configure(fg_color=COLOR_BG)
        modal.transient(self)
        modal.grab_set()
        
        self._center_modal(modal, 480, 510)
        
        lbl_title = ctk.CTkLabel(modal, text="💬 Soporte & Consultas", font=("Segoe UI", 16, "bold"), text_color=COLOR_CYAN)
        lbl_title.pack(pady=(18, 5))
        
        lbl_desc = ctk.CTkLabel(
            modal, text="Envía tu duda o reporte directamente al equipo mediante la API Web3Forms.\nEl proceso se ejecuta en segundo plano.",
            font=FONT_BODY, justify="center", text_color=COLOR_TEXT_MUTED
        )
        lbl_desc.pack(padx=20, pady=(0, 12))
        
        lbl_cat = ctk.CTkLabel(modal, text="Categoría:", font=("Segoe UI", 10, "bold"), text_color=COLOR_TEXT_MAIN)
        lbl_cat.pack(anchor="w", padx=30, pady=(0, 2))
        
        option_cat = ctk.CTkOptionMenu(
            modal, values=["Duda / Consulta", "Sugerencia / Feedback", "Reporte de Error", "Otro"],
            fg_color=COLOR_CARD, button_color=COLOR_BORDER, button_hover_color=COLOR_HOVER, text_color=COLOR_TEXT_MAIN, dropdown_fg_color=COLOR_CARD, dropdown_hover_color=COLOR_HOVER, dropdown_text_color=COLOR_TEXT_MAIN
        )
        option_cat.pack(fill="x", padx=30, pady=(0, 10))
        
        lbl_email = ctk.CTkLabel(modal, text="Correo Electrónico (opcional para respuesta):", font=("Segoe UI", 10, "bold"), text_color=COLOR_TEXT_MAIN)
        lbl_email.pack(anchor="w", padx=30, pady=(0, 2))
        
        entry_email = ctk.CTkEntry(modal, placeholder_text="tu_email@ejemplo.com", font=FONT_BODY, fg_color=COLOR_CARD, text_color=COLOR_TEXT_MAIN, border_color=COLOR_BORDER)
        entry_email.pack(fill="x", padx=30, pady=(0, 10))
        
        lbl_msg = ctk.CTkLabel(modal, text="Mensaje o Consulta:", font=("Segoe UI", 10, "bold"), text_color=COLOR_TEXT_MAIN)
        lbl_msg.pack(anchor="w", padx=30, pady=(0, 2))
        
        txt_msg = ctk.CTkTextbox(modal, font=FONT_BODY, height=110, fg_color=COLOR_CARD, text_color=COLOR_TEXT_MAIN, corner_radius=6)
        txt_msg.pack(fill="x", padx=30, pady=(0, 15))
        
        btn_send = ctk.CTkButton(
            modal, text="🚀 Enviar Mensaje en Segundo Plano", font=("Segoe UI", 11, "bold"),
            fg_color=COLOR_ACCENT, hover_color=COLOR_HOVER, text_color="#ffffff", height=36
        )
        
        def send_feedback():
            cat = option_cat.get()
            email_val = entry_email.get().strip()
            msg_val = txt_msg.get("1.0", "end").strip()
            
            if not msg_val:
                messagebox.showwarning("Campo Requerido", "Por favor, escribe un mensaje antes de enviar.")
                return
                
            btn_send.configure(state="disabled", text="⏳ Enviando...")
            
            def worker():
                payload = {
                    "access_key": "6468511d-508d-4078-aa8f-44f33fb19a29",
                    "subject": f"KILLNet Feedback [{cat}]",
                    "from_name": "KILLNet User",
                    "category": cat,
                    "email": email_val if email_val else "Anónimo",
                    "message": msg_val
                }
                try:
                    res = requests.post("https://api.web3forms.com/submit", json=payload, timeout=8)
                    if res.status_code == 200 and res.json().get("success"):
                        self.after(0, self.log_message, f"[FEEDBACK] Mensaje enviado ({cat}).", "SUCCESS")
                        self.after(0, lambda: messagebox.showinfo("Enviado", "¡Gracias por tu mensaje! Se ha enviado con éxito."))
                        self.after(0, modal.destroy)
                    else:
                        err = res.json().get("message", f"HTTP {res.status_code}")
                        self.after(0, self.log_message, f"[FEEDBACK] Fallo al enviar: {err}", "ERROR")
                        self.after(0, lambda: messagebox.showerror("Error", f"No se pudo enviar el mensaje: {err}"))
                        self.after(0, lambda: btn_send.configure(state="normal", text="🚀 Enviar Mensaje en Segundo Plano"))
                except Exception as ex:
                    self.after(0, self.log_message, f"[FEEDBACK] Excepción de red: {str(ex)}", "ERROR")
                    self.after(0, lambda: messagebox.showerror("Error de Red", f"Error de conexión: {str(ex)}"))
                    self.after(0, lambda: btn_send.configure(state="normal", text="🚀 Enviar Mensaje en Segundo Plano"))
                    
            threading.Thread(target=worker, daemon=True).start()

        btn_send.configure(command=send_feedback)
        btn_send.pack(fill="x", padx=30, pady=(0, 10))

    def open_user_manual(self):
        modal = ctk.CTkToplevel(self)
        modal.title("Manual de Usuario y Guía Forense - KILLNet v2.0")
        modal.geometry("780x560")
        modal.resizable(False, False)
        modal.transient(self)
        modal.grab_set()

        modal.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - 390
        y = self.winfo_y() + (self.winfo_height() // 2) - 280
        modal.geometry(f"+{max(0, x)}+{max(0, y)}")

        head_frame = ctk.CTkFrame(modal, fg_color="transparent")
        head_frame.pack(fill="x", padx=24, pady=(20, 10))
        ctk.CTkLabel(
            head_frame, text="📖 Manual de Usuario y Defensa Perimetral",
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"), text_color=("#0f172a", "#38bdf8")
        ).pack(anchor="w")

        tabs = ctk.CTkTabview(modal, width=730, height=410, corner_radius=10)
        tabs.pack(padx=24, pady=(0, 10), fill="both", expand=True)

        tab_sentinel = tabs.add("Centinela IDS")
        tab_auditor = tabs.add("Auditoría Host")
        tab_sockets = tabs.add("Sockets & Red")
        tab_lan = tabs.add("Red Local / Wi-Fi")
        tab_access = tabs.add("Filtro & Whitelist")
        tab_restrictions = tabs.add("Bloqueos & DNS")
        tab_panic = tabs.add("Modo Pánico")

        def _add_section(parent, title, content_list):
            scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
            scroll.pack(fill="both", expand=True, padx=10, pady=10)
            
            lbl_t = ctk.CTkLabel(
                scroll, text=title, font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
                text_color=("#0f172a", "#f8fafc"), anchor="w"
            )
            lbl_t.pack(fill="x", pady=(0, 10))

            for item_title, desc in content_list:
                card = ctk.CTkFrame(scroll, corner_radius=8, fg_color=("#e2e8f0", "#1e293b"))
                card.pack(fill="x", pady=5, padx=2)
                
                ctk.CTkLabel(
                    card, text=item_title, font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                    text_color=("#1e293b", "#38bdf8"), anchor="w"
                ).pack(fill="x", padx=14, pady=(10, 4))
                
                ctk.CTkLabel(
                    card, text=desc, font=ctk.CTkFont(family="Segoe UI", size=12),
                    text_color=("#334155", "#cbd5e1"), justify="left", wraplength=660, anchor="w"
                ).pack(fill="x", padx=14, pady=(0, 10))

        _add_section(tab_sentinel, "IDS Defensivo & Centinela Wi-Fi", [
            ("🛡️ Escudo Anti-ARP Spoofing:", "Monitorea continuamente la tabla ARP de Windows para prevenir suplantación de la puerta de enlace (Man-in-the-Middle) con opción de fijación estática."),
            ("📡 Auditoría Evil Twin / Rogue AP:", "Inspecciona el espectro inalámbrico buscando SSIDs clonados o puntos de acceso falsos emitiendo con autenticación degradada."),
            ("🔒 Hardening de Puertos Router:", "Audita servicios expuestos en el gateway (Telnet 23, UPnP 1900/5000, FTP, HTTP) identificando vulnerabilidades de red.")
        ])

        _add_section(tab_auditor, "Auditoría de Servicios & Hardening de Host", [
            ("🔍 Diagnóstico de Exposición:", "Escanea puertos TCP en hosts específicos para capturar versiones de servicios y detectar protocolos en texto plano (Telnet, FTP, HTTP)."),
            ("🚫 Aislamiento Local:", "Permite aislar cualquier host sospechoso bloqueando todo su tráfico entrante y saliente mediante reglas nativas en el Firewall de Windows.")
        ])

        _add_section(tab_sockets, "Inspección de Sockets y Conexiones Activas", [
            ("📡 Mapeo en Vivo:", "KILLNet inspecciona la tabla de conexiones inet (TCP y UDP) mediante psutil, asociando cada puerto al PID y ejecutable responsable en disco."),
            ("🔍 Búsqueda Rápida:", "Filtra en tiempo real por PID, nombre de ejecutable (.exe), o IP de destino.")
        ])

        _add_section(tab_lan, "Escáner de Dispositivos en la Red Local (Wi-Fi / LAN)", [
            ("📡 Barrido Concurrente ARP:", "Realiza pings ultrarrápidos con ThreadPoolExecutor(max_workers=50) sin ventana de consola para poblar la tabla ARP de Windows."),
            ("📱 Detección de Fabricantes y MAC Privada:", "Identifica si un celular usa MAC Aleatoria/Privada y resuelve fabricantes por OUI (Apple, Samsung, Xiaomi, Motorola, etc.).")
        ])

        _add_section(tab_access, "Sistema de Control de Acceso (Blacklist / Whitelist)", [
            ("🛡️ Reglas Persistentes:", "Almacena preferencias en data/access_rules.json y aplica bloqueos nativos de entrada/salida en el Firewall de Windows con netsh."),
            ("⚡ Alternancia de Política:", "Conmuta fácilmente entre el modo Blacklist (Permitir todo salvo lista negra) y Whitelist (Bloquear todo salvo autorizados).")
        ])

        _add_section(tab_restrictions, "Diagnóstico y Bypass de Restricciones de Red", [
            ("🌐 Comprobación de Servicios:", "Evalúa conectividad a YouTube, Redes Sociales, Streaming y sitios de prueba diferenciando bloqueos DNS de Firewall."),
            ("🔓 Desbloqueo Automático:", "Permite cambiar DNS a servidores seguros (Cloudflare 1.1.1.1) y limpiar redirecciones en C:\\Windows\\System32\\drivers\\etc\\hosts.")
        ])

        _add_section(tab_panic, "Aislamiento Forense de Emergencia", [
            ("🚨 Modo Pánico:", "Bloquea inmediatamente todo el tráfico saliente de la máquina ante sospecha de exfiltración o malware."),
            ("📄 Auditoría Forense:", "Exporta volcados completos de sockets y eventos en formato CSV o JSON.")
        ])

        btn_close = ctk.CTkButton(modal, text="Entendido", width=120, height=34, command=modal.destroy)
        btn_close.pack(pady=(0, 16))

    open_manual_modal = open_user_manual
