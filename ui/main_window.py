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
    get_gateway_info, get_gateway_ip, start_arp_guard, detect_evil_twin,
    audit_gateway_security, emergency_wifi_disconnect
)
from core.security_auditor import (
    scan_device_security, audit_cleartext_protocols, isolate_host_local_firewall
)
from core.device_inventory import process_devices, set_alias as set_inventory_alias
from core.tray_sentinel import (
    TraySentinelManager, notify_new_device, notify_mitm_alert, notify_tray_minimized
)

from ui.theme import (
    BG_MAIN, BG_CARD, BG_CARD_HOVER, TEXT_PRIMARY, TEXT_MUTED,
    ACCENT_CYAN, ACCENT_GREEN, ACCENT_RED, ACCENT_GOLD,
    COLOR_BG, COLOR_BG_DARK, COLOR_SIDEBAR, COLOR_CARD, COLOR_CARD_INNER,
    COLOR_ACCENT, COLOR_CYAN, COLOR_DANGER, COLOR_SUCCESS, COLOR_WARNING,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_MAIN, COLOR_TEXT_MUTED, COLOR_BORDER, COLOR_HOVER,
    FONT_TITLE, FONT_SUBTITLE, FONT_CARD_NUM, FONT_CARD_LABEL, FONT_BODY,
    FONT_MANUAL_HEADER, FONT_MANUAL_BODY, FONT_CONSOLE, configure_treeview_style
)
from ui.device_card import DeviceCard, load_device_aliases, save_device_alias

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
        "version": "3.0.0",
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
        
        # Configuración de ventana elevada en 1100x720 para margen sobre la barra de tareas
        self.title("KILLNet v3.0 - Suite Forense, Auditoría & Hardening de Red Local")
        self.minsize(1040, 680)
        self.configure(fg_color=BG_MAIN)
        self._position_window(1100, 720)
        
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
        self.txt_console.tag_config("DANGER", foreground=ACCENT_RED)
        
        # Logs de bienvenida
        self.log_message(f"=== KILLNet v3.0 Suite Inicializada [{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ===")
        self.log_message(f"[CONFIG] Tema cargado: '{saved_theme}' (Efectivo: '{effective_mode}').", "INFO")
        if self.is_admin_user:
            self.log_message("[ENTORNO] Privilegios de Administrador ACTIVOS (IDS, Hardening, Firewall y Kill habilitados).", "SUCCESS")
        else:
            self.log_message("[ADVERTENCIA] Ejecutándose SIN privilegios de Administrador. Funciones netsh requerirán elevación.", "WARNING")
            
        # Escaneo inicial automático
        self.start_lan_scan_async()
        self.start_scan_async()
        
        # Cargar reglas iniciales de acceso e información del gateway
        self.refresh_access_control_ui()
        self.refresh_sentinel_gateway_info_async()

        # Inicializar gestor de bandeja del sistema (System Tray) y protocolo de cierre
        self.tray_manager = TraySentinelManager()
        self.tray_manager.setup_tray(
            show_window_callback=self._restore_from_tray,
            exit_app_callback=self._exit_completely
        )
        self.tray_manager.show_icon()
        self.protocol("WM_DELETE_WINDOW", self.on_close_window)

    def _position_window(self, width: int = 1100, height: int = 720):
        self.update_idletasks()
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = max(0, int((screen_w - width) / 2))
        y = max(15, int((screen_h - height) / 2) - 40)
        self.geometry(f"{width}x{height}+{x}+{y}")

    _center_window = _position_window

    def on_close_window(self):
        """Oculta la ventana y minimiza a la bandeja del sistema con notificación toast."""
        self.withdraw()
        notify_tray_minimized()
        self.log_message("[CENTINELA] KILLNet continúa vigilando la red en segundo plano (Bandeja del sistema).", "INFO")
        if hasattr(self, "tray_manager") and not self.tray_manager.is_running:
            self.tray_manager.show_icon()

    def _restore_from_tray(self):
        """Restaura la ventana principal desde la bandeja del sistema."""
        self.after(0, self._do_restore)

    def _do_restore(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    def _exit_completely(self):
        """Cierra completamente la aplicación, hilos y bandeja."""
        self.after(0, self._do_exit)

    def _do_exit(self):
        if hasattr(self, "arp_guard_stop_event") and self.arp_guard_stop_event:
            self.arp_guard_stop_event.set()
        if hasattr(self, "tray_manager") and self.tray_manager:
            self.tray_manager.stop_tray()
        try:
            self.destroy()
        except Exception:
            pass
        sys.exit(0)

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
            self.sidebar, text="⚡ KILLNet v3.0", font=("Segoe UI", 22, "bold"), text_color=ACCENT_CYAN
        )
        self.lbl_title.grid(row=0, column=0, padx=20, pady=(16, 0), sticky="w")
        
        self.lbl_subtitle = ctk.CTkLabel(
            self.sidebar, text="Network Forensics & Security Suite", font=("Segoe UI", 9), text_color=TEXT_MUTED
        )
        self.lbl_subtitle.grid(row=1, column=0, padx=20, pady=(0, 8), sticky="w")
        
        # Badge de privilegios Admin
        admin_text = "🛡️ Modo Admin (Elevado)" if self.is_admin_user else "⚠️ Modo Usuario (Limitado)"
        admin_color = ACCENT_GREEN if self.is_admin_user else ACCENT_GOLD
        self.lbl_admin_badge = ctk.CTkLabel(
            self.sidebar, text=admin_text, font=("Segoe UI", 9, "bold"), text_color=admin_color,
            fg_color=BG_CARD, corner_radius=6, height=24
        )
        self.lbl_admin_badge.grid(row=2, column=0, padx=15, pady=(0, 8), sticky="ew")
        
        sep1 = ctk.CTkFrame(self.sidebar, height=2, fg_color=COLOR_BORDER)
        sep1.grid(row=3, column=0, padx=15, pady=(0, 6), sticky="ew")
        
        # NAV BUTTONS
        self.lbl_nav_title = ctk.CTkLabel(
            self.sidebar, text="MÓDULOS DE AUDITORÍA & DEFENSA:", font=("Segoe UI", 8, "bold"), text_color=TEXT_MUTED, anchor="w"
        )
        self.lbl_nav_title.grid(row=4, column=0, padx=15, pady=(0, 4), sticky="w")

        self.btn_nav_lan = ctk.CTkButton(
            self.sidebar, text="📡 Red & Dispositivos (Fing)", font=("Segoe UI", 10, "bold"),
            fg_color=ACCENT_CYAN, hover_color=BG_CARD_HOVER, text_color="#ffffff", anchor="w",
            command=lambda: self.switch_tab("lan")
        )
        self.btn_nav_lan.grid(row=5, column=0, padx=15, pady=2, sticky="ew")

        self.btn_nav_sockets = ctk.CTkButton(
            self.sidebar, text="📊 Telemetría de Sockets", font=("Segoe UI", 10, "bold"),
            fg_color=BG_CARD, hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY, anchor="w",
            command=lambda: self.switch_tab("sockets")
        )
        self.btn_nav_sockets.grid(row=6, column=0, padx=15, pady=2, sticky="ew")

        self.btn_nav_sentinel = ctk.CTkButton(
            self.sidebar, text="🚨 Centinela Wi-Fi (IDS)", font=("Segoe UI", 10, "bold"),
            fg_color=BG_CARD, hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY, anchor="w",
            command=lambda: self.switch_tab("sentinel")
        )
        self.btn_nav_sentinel.grid(row=7, column=0, padx=15, pady=2, sticky="ew")

        self.btn_nav_auditor = ctk.CTkButton(
            self.sidebar, text="🛡️ Auditoría & Hardening", font=("Segoe UI", 10, "bold"),
            fg_color=BG_CARD, hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY, anchor="w",
            command=lambda: self.switch_tab("auditor")
        )
        self.btn_nav_auditor.grid(row=8, column=0, padx=15, pady=2, sticky="ew")

        self.btn_nav_access = ctk.CTkButton(
            self.sidebar, text="🛡️ Filtro de Red (Access)", font=("Segoe UI", 10, "bold"),
            fg_color=BG_CARD, hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY, anchor="w",
            command=lambda: self.switch_tab("access")
        )
        self.btn_nav_access.grid(row=9, column=0, padx=15, pady=2, sticky="ew")

        self.btn_nav_restrictions = ctk.CTkButton(
            self.sidebar, text="🌐 Diagnóstico de Bloqueos", font=("Segoe UI", 10, "bold"),
            fg_color=BG_CARD, hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY, anchor="w",
            command=lambda: self.switch_tab("restrictions")
        )
        self.btn_nav_restrictions.grid(row=10, column=0, padx=15, pady=2, sticky="ew")

        sep2 = ctk.CTkFrame(self.sidebar, height=2, fg_color=COLOR_BORDER)
        sep2.grid(row=11, column=0, padx=15, pady=(6, 6), sticky="ew")
        
        # ACCIONES RÁPIDAS
        self.btn_auto_monitor = ctk.CTkButton(
            self.sidebar, text="📡 Monitoreo En Vivo [OFF]", font=("Segoe UI", 10, "bold"),
            fg_color=BG_CARD, hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY, anchor="w",
            command=self.toggle_auto_monitor
        )
        self.btn_auto_monitor.grid(row=12, column=0, padx=15, pady=2, sticky="ew")
        
        self.btn_emergency = ctk.CTkButton(
            self.sidebar, text="🚨 Modo Pánico (Aislamiento)", font=("Segoe UI", 10, "bold"),
            fg_color=ACCENT_RED, hover_color="#c0392b", text_color="#ffffff", anchor="w",
            command=self.on_toggle_emergency_isolation
        )
        self.btn_emergency.grid(row=13, column=0, padx=15, pady=(4, 6), sticky="ew")

        sep3 = ctk.CTkFrame(self.sidebar, height=2, fg_color=COLOR_BORDER)
        sep3.grid(row=14, column=0, padx=15, pady=(0, 6), sticky="ew")

        # BOTONES SECUNDARIOS Y SOPORTE
        self.btn_donate = ctk.CTkButton(
            self.sidebar, text="☕ Apoyar el Proyecto", font=("Segoe UI", 10, "bold"),
            fg_color=ACCENT_GOLD, hover_color="#ca8a04", text_color="#1c1917", anchor="w",
            command=self.open_donation_modal
        )
        self.btn_donate.grid(row=15, column=0, padx=15, pady=2, sticky="ew")
        
        self.btn_feedback = ctk.CTkButton(
            self.sidebar, text="💬 Soporte & Dudas", font=("Segoe UI", 10, "bold"),
            fg_color=BG_CARD, hover_color=BG_CARD_HOVER, text_color=ACCENT_CYAN, anchor="w",
            command=self.open_feedback_modal
        )
        self.btn_feedback.grid(row=16, column=0, padx=15, pady=2, sticky="ew")
        
        self.btn_manual = ctk.CTkButton(
            self.sidebar, text="📖 Manual de Usuario", font=("Segoe UI", 10, "bold"),
            fg_color=BG_CARD, hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY, anchor="w",
            command=self.open_manual_modal
        )
        self.btn_manual.grid(row=17, column=0, padx=15, pady=2, sticky="ew")
        
        spacer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        spacer.grid(row=18, column=0, sticky="nsew")
        
        # Selector de Tema
        self.lbl_theme = ctk.CTkLabel(
            self.sidebar, text="🎨 Modo de Tema:", font=("Segoe UI", 9, "bold"), text_color=TEXT_MUTED, anchor="w"
        )
        self.lbl_theme.grid(row=19, column=0, padx=15, pady=(4, 2), sticky="w")
        
        self.option_theme = ctk.CTkOptionMenu(
            self.sidebar, values=["Dark", "Light", "System"], command=self._on_theme_changed,
            fg_color=BG_CARD, button_color=COLOR_BORDER, button_hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY,
            dropdown_fg_color=BG_CARD, dropdown_hover_color=BG_CARD_HOVER, dropdown_text_color=TEXT_PRIMARY, height=26
        )
        self.option_theme.set(current_theme)
        self.option_theme.grid(row=20, column=0, padx=15, pady=(0, 10), sticky="ew")

        # -------------------------------------------------------------
        # 2. PANEL CENTRAL PRINCIPAL CON TABVIEW
        # -------------------------------------------------------------
        self.main_panel = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        self.main_panel.grid(row=0, column=1, sticky="nsew", padx=12, pady=12)
        self.main_panel.grid_columnconfigure(0, weight=1)
        self.main_panel.grid_rowconfigure(0, weight=1)
        self.main_panel.grid_rowconfigure(1, weight=0)
        
        self.tabview = ctk.CTkTabview(self.main_panel, fg_color="transparent", corner_radius=8, command=self._on_tab_changed)
        self.tabview.grid(row=0, column=0, sticky="nsew")
        
        # Pestañas principales
        self.tab_network = self.tabview.add("📡 Red & Dispositivos")
        self.tab_sentinel = self.tabview.add("🚨 Centinela Wi-Fi (IDS)")
        self.tab_auditor = self.tabview.add("🛡️ Auditoría & Hardening")
        self.tab_access = self.tabview.add("🛡️ Filtro de Red")
        self.tab_restrictions = self.tabview.add("🌐 Diagnóstico de Bloqueos")
        
        self._build_network_tab()
        self._build_sentinel_tab()
        self._build_auditor_tab()
        self._build_access_tab()
        self._build_restrictions_tab()

        # CONSOLA DE AUDITORIA INFERIOR (COLAPSABLE / MINIMIZABLE)
        self.console_container = ctk.CTkFrame(self.main_panel, fg_color=BG_CARD, corner_radius=8)
        self.console_container.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        self.console_container.grid_columnconfigure(0, weight=1)
        self.console_container.grid_rowconfigure(1, weight=1)
        
        console_bar = ctk.CTkFrame(self.console_container, fg_color="transparent", height=26)
        console_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(4, 4))
        console_bar.grid_columnconfigure(0, weight=1)
        
        lbl_console_title = ctk.CTkLabel(
            console_bar, text="💻 Consola Global de Auditoría y Eventos CTI", font=("Segoe UI", 10, "bold"), text_color=TEXT_MUTED
        )
        lbl_console_title.grid(row=0, column=0, sticky="w")
        
        self.console_visible = True
        self.btn_toggle_console = ctk.CTkButton(
            console_bar, text="[ Minimizar Consola ▼ ]", width=145, height=22, font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=BG_CARD_HOVER, text_color=ACCENT_CYAN, command=self.toggle_console_visibility
        )
        self.btn_toggle_console.grid(row=0, column=1, sticky="e", padx=(0, 6))

        btn_clear_console = ctk.CTkButton(
            console_bar, text="Limpiar Logs", width=75, height=22, font=("Segoe UI", 9),
            fg_color=COLOR_CARD_INNER, hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY, command=self.clear_log_console
        )
        btn_clear_console.grid(row=0, column=2, sticky="e")

        self.txt_console = ctk.CTkTextbox(
            self.console_container, font=FONT_CONSOLE, fg_color=COLOR_CARD_INNER, text_color=TEXT_PRIMARY, height=85, corner_radius=4
        )
        self.txt_console.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 6))
        self.log_textbox = self.txt_console

    # -------------------------------------------------------------
    # CONSTRUCCIÓN PESTAÑA PRINCIPAL: RED & DISPOSITIVOS (FING + FORENSE)
    # -------------------------------------------------------------
    def _build_network_tab(self):
        self.tab_network.grid_columnconfigure(0, weight=1)
        self.tab_network.grid_rowconfigure(2, weight=1)
        
        # 1. DASHBOARD SUPERIOR (4 TARJETAS MÉTRICAS COMPACTAS)
        self.top_dashboard = ctk.CTkFrame(self.tab_network, fg_color="transparent")
        self.top_dashboard.grid(row=0, column=0, sticky="ew", pady=(0, 0))
        for i in range(4):
            self.top_dashboard.grid_columnconfigure(i, weight=1)
            
        # Tarjeta 1: Red Actual
        self.card_net_val, self.card_net_sub = self._create_dashboard_card(
            self.top_dashboard, col=0, title="🌐 RED ACTUAL",
            initial_val="Detectando...", initial_sub="Analizando adaptador...",
            accent_color=ACCENT_CYAN
        )
        # Tarjeta 2: Dispositivos Activos
        self.card_dev_val, self.card_dev_sub = self._create_dashboard_card(
            self.top_dashboard, col=1, title="👥 DISPOSITIVOS ACTIVOS",
            initial_val="0 Activos", initial_sub="Subred local /24",
            accent_color=ACCENT_GREEN
        )
        # Tarjeta 3: Gateway / Router
        self.card_gw_val, self.card_gw_sub = self._create_dashboard_card(
            self.top_dashboard, col=2, title="🚪 GATEWAY / ROUTER",
            initial_val="192.168.1.1", initial_sub="Puerta de enlace",
            accent_color=ACCENT_GOLD
        )
        # Tarjeta 4: Estado del Escudo
        self.card_shield_val, self.card_shield_sub = self._create_dashboard_card(
            self.top_dashboard, col=3, title="🛡️ ESTADO DEL ESCUDO",
            initial_val="EN ESPERA ⚠️", initial_sub="Protección Anti-ARP",
            accent_color=ACCENT_GOLD
        )

        # 2. CABECERA CON CONMUTADOR DE VISTAS (Fing vs Forense) & BUSCADOR
        self.header_controls = ctk.CTkFrame(self.tab_network, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=COLOR_BORDER)
        self.header_controls.grid(row=1, column=0, sticky="ew", pady=(10, 6))
        self.header_controls.grid_columnconfigure(1, weight=1)
        
        # Conmutador Segmentado de Vistas
        self.seg_network_view = ctk.CTkSegmentedButton(
            self.header_controls,
            values=["Vista Dispositivos (Fing)", "Vista Sockets (Forense)"],
            command=self.on_network_view_changed,
            font=("Segoe UI", 10, "bold"),
            selected_color=ACCENT_CYAN,
            selected_hover_color=("#0891b2", "#0e7490"),
            height=32
        )
        self.seg_network_view.set("Vista Dispositivos (Fing)")
        self.seg_network_view.grid(row=0, column=0, padx=10, pady=8, sticky="w")
        
        # Campo de Búsqueda Dinámica
        self.entry_network_search = ctk.CTkEntry(
            self.header_controls,
            placeholder_text="🔍 Filtrar dispositivos por IP, Hostname, MAC o Fabricante...",
            font=FONT_BODY,
            height=32,
            fg_color=COLOR_CARD_INNER,
            text_color=TEXT_PRIMARY,
            border_color=COLOR_BORDER
        )
        self.entry_network_search.grid(row=0, column=1, padx=8, pady=8, sticky="ew")
        self.entry_network_search.bind("<KeyRelease>", self._on_network_search_changed)
        
        # Botón de Acción Principal (Escanear Red)
        self.btn_network_scan = ctk.CTkButton(
            self.header_controls,
            text="🔍 Escanear Red Wi-Fi / LAN",
            font=("Segoe UI", 10, "bold"),
            fg_color=ACCENT_CYAN,
            hover_color=("#0891b2", "#0e7490"),
            text_color="#ffffff",
            height=32,
            command=self.on_network_scan_clicked
        )
        self.btn_network_scan.grid(row=0, column=2, padx=10, pady=8, sticky="e")

        # 3. CONTENEDORES DE CONTENIDO
        # Contenedor 1: VISTA DISPOSITIVOS (FING)
        self.container_fing = ctk.CTkFrame(self.tab_network, fg_color="transparent")
        self.container_fing.grid(row=2, column=0, sticky="nsew")
        self.container_fing.grid_columnconfigure(0, weight=1)
        self.container_fing.grid_rowconfigure(0, weight=1)
        
        self.scroll_devices = ctk.CTkScrollableFrame(self.container_fing, fg_color="transparent")
        self.scroll_devices.grid(row=0, column=0, sticky="nsew")
        self.scroll_devices.grid_columnconfigure(0, weight=1)
        
        # Contenedor 2: VISTA SOCKETS (FORENSE)
        self.container_forensic = ctk.CTkFrame(self.tab_network, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=COLOR_BORDER)
        self.container_forensic.grid_columnconfigure(0, weight=1)
        self.container_forensic.grid_rowconfigure(1, weight=1)
        
        self._build_forensic_sockets_content()

    def _create_dashboard_card(self, parent, col, title, initial_val, initial_sub, accent_color):
        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=COLOR_BORDER)
        card.grid(row=0, column=col, padx=4 if col > 0 else (0, 4), sticky="nsew")
        card.grid_columnconfigure(0, weight=1)
        
        lbl_title = ctk.CTkLabel(card, text=title, font=FONT_CARD_LABEL, text_color=TEXT_MUTED, anchor="w")
        lbl_title.pack(anchor="w", padx=12, pady=(10, 2))
        
        lbl_val = ctk.CTkLabel(card, text=initial_val, font=FONT_CARD_NUM, text_color=accent_color, anchor="w")
        lbl_val.pack(anchor="w", padx=12, pady=(0, 2))
        
        lbl_sub = ctk.CTkLabel(card, text=initial_sub, font=("Segoe UI", 9), text_color=TEXT_MUTED, anchor="w")
        lbl_sub.pack(anchor="w", padx=12, pady=(0, 10))
        
        return lbl_val, lbl_sub

    def _build_forensic_sockets_content(self):
        # Barra superior de filtros forenses
        forensic_header = ctk.CTkFrame(self.container_forensic, fg_color="transparent")
        forensic_header.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 6))
        forensic_header.grid_columnconfigure(0, weight=1)
        
        f_left = ctk.CTkFrame(forensic_header, fg_color="transparent")
        f_left.pack(side="left")
        
        ctk.CTkLabel(f_left, text="📡 Matriz Forense de Sockets & Conexiones:", font=("Segoe UI", 10, "bold"), text_color=TEXT_MUTED).pack(side="left", padx=(0, 8))
        
        self.btn_filter_all = ctk.CTkButton(
            f_left, text="Todas", width=65, height=26, font=("Segoe UI", 9, "bold"),
            fg_color=ACCENT_CYAN, hover_color=BG_CARD_HOVER, text_color="#ffffff", command=lambda: self._set_status_filter("ALL")
        )
        self.btn_filter_all.pack(side="left", padx=(0, 4))
        
        self.btn_filter_estab = ctk.CTkButton(
            f_left, text="Conectadas", width=80, height=26, font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY, command=lambda: self._set_status_filter("ESTABLISHED")
        )
        self.btn_filter_estab.pack(side="left", padx=(0, 4))
        
        self.btn_filter_listen = ctk.CTkButton(
            f_left, text="En Escucha", width=80, height=26, font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY, command=lambda: self._set_status_filter("LISTEN")
        )
        self.btn_filter_listen.pack(side="left", padx=(0, 4))
        
        self.lbl_status = ctk.CTkLabel(forensic_header, text="Listo", font=FONT_BODY, text_color=TEXT_MUTED)
        self.lbl_status.pack(side="right", padx=(10, 0))
        
        self.btn_export = ctk.CTkButton(
            forensic_header, text="📄 Exportar Auditoría", font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=BG_CARD_HOVER, text_color=ACCENT_CYAN, width=125, height=26, command=self.on_export_audit_clicked
        )
        self.btn_export.pack(side="right")
        
        # Tabla Treeview Forense
        columns = ("pid", "process", "protocol", "remote_ip", "remote_port", "geo_isp", "status", "risk")
        self.tree = ttk.Treeview(self.container_forensic, columns=columns, show="headings", style="Cyber.Treeview", selectmode="browse")
        
        self.tree.heading("pid", text="PID", anchor="center")
        self.tree.heading("process", text="Proceso", anchor="w")
        self.tree.heading("protocol", text="Proto", anchor="center")
        self.tree.heading("remote_ip", text="IP Remota", anchor="w")
        self.tree.heading("remote_port", text="Puerto", anchor="center")
        self.tree.heading("geo_isp", text="País / ISP / GeoIP", anchor="w")
        self.tree.heading("status", text="Estado", anchor="center")
        self.tree.heading("risk", text="Riesgo", anchor="center")
        
        self.tree.column("pid", width=65, minwidth=55, anchor="center")
        self.tree.column("process", width=180, minwidth=120, anchor="w")
        self.tree.column("protocol", width=65, minwidth=50, anchor="center")
        self.tree.column("remote_ip", width=130, minwidth=100, anchor="w")
        self.tree.column("remote_port", width=65, minwidth=50, anchor="center")
        self.tree.column("geo_isp", width=260, minwidth=160, anchor="w")
        self.tree.column("status", width=100, minwidth=80, anchor="center")
        self.tree.column("risk", width=90, minwidth=70, anchor="center")
        
        scrollbar = ttk.Scrollbar(self.container_forensic, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=1, column=0, sticky="nsew", padx=(10, 0), pady=(0, 6))
        scrollbar.grid(row=1, column=1, sticky="ns", padx=(0, 10), pady=(0, 6))

        # Barra de acciones de sockets
        actions_bar = ctk.CTkFrame(self.container_forensic, fg_color="transparent")
        actions_bar.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 8))
        
        self.btn_block_ip = ctk.CTkButton(
            actions_bar, text="🚫 Bloquear IP Seleccionada", font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=BG_CARD_HOVER, text_color=ACCENT_GOLD, height=28, command=self.on_block_ip_clicked
        )
        self.btn_block_ip.pack(side="left", padx=(0, 8))
        
        self.btn_kill_proc = ctk.CTkButton(
            actions_bar, text="💀 Terminar Proceso (Kill)", font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=BG_CARD_HOVER, text_color=ACCENT_RED, height=28, command=self.on_kill_proc_clicked
        )
        self.btn_kill_proc.pack(side="left")

    def on_network_view_changed(self, selected_view: str):
        if "Fing" in selected_view:
            self.container_forensic.grid_forget()
            self.container_fing.grid(row=2, column=0, sticky="nsew")
            self.entry_network_search.configure(
                placeholder_text="🔍 Filtrar dispositivos por IP, Hostname, MAC o Fabricante..."
            )
            self.btn_network_scan.configure(text="🔍 Escanear Red Wi-Fi / LAN")
            self._update_nav_buttons_highlight("lan")
            self.render_device_cards()
        else:
            self.container_fing.grid_forget()
            self.container_forensic.grid(row=2, column=0, sticky="nsew")
            self.entry_network_search.configure(
                placeholder_text="🔍 Filtrar sockets por binario, PID o IP..."
            )
            self.btn_network_scan.configure(text="🔍 Escanear Sockets")
            self._update_nav_buttons_highlight("sockets")
            if not self.current_connections:
                self.start_scan_async()
            else:
                self._apply_table_filters()

    def on_network_scan_clicked(self):
        current_view = self.seg_network_view.get()
        if "Fing" in current_view:
            self.start_lan_scan_async()
        else:
            self.start_scan_async()

    def _on_network_search_changed(self, event=None):
        current_view = self.seg_network_view.get()
        if "Fing" in current_view:
            self.render_device_cards()
        else:
            self.search_query = self.entry_network_search.get().strip().lower()
            self._apply_table_filters()

    # -------------------------------------------------------------
    # CONSTRUCCIÓN PESTAÑA AUDITORÍA & HARDENING DE RED
    # -------------------------------------------------------------
    def _build_auditor_tab(self):
        self.tab_auditor.grid_columnconfigure(0, weight=1)
        self.tab_auditor.grid_rowconfigure(2, weight=1)
        
        # Banner Informativo
        banner_box = ctk.CTkFrame(self.tab_auditor, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        banner_box.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        
        lbl_disclaimer = ctk.CTkLabel(
            banner_box,
            text="🛡️ MÓDULO DE AUDITORÍA Y HARDENING PERIMETRAL LOCAL\n"
                 "Diagnóstico defensivo para identificar la exposición de servicios en hosts de la red local "
                 "y aplicar reglas de aislamiento nativas mediante el Firewall de Windows.",
            font=("Segoe UI", 9),
            text_color=TEXT_MUTED,
            justify="center",
            wraplength=850
        )
        lbl_disclaimer.pack(padx=16, pady=8)

        # Controles y Target IP
        target_box = ctk.CTkFrame(self.tab_auditor, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        target_box.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        target_box.grid_columnconfigure(1, weight=1)
        
        lbl_target = ctk.CTkLabel(target_box, text="Host / IP Objetivo:", font=("Segoe UI", 11, "bold"), text_color=ACCENT_CYAN)
        lbl_target.grid(row=0, column=0, padx=(12, 6), pady=10, sticky="w")
        
        self.entry_audit_target = ctk.CTkEntry(
            target_box, placeholder_text="192.168.1.50", font=FONT_BODY, height=30,
            fg_color=COLOR_CARD_INNER, text_color=TEXT_PRIMARY, border_color=COLOR_BORDER
        )
        self.entry_audit_target.grid(row=0, column=1, padx=6, pady=10, sticky="ew")
        
        self.btn_paste_lan_ip = ctk.CTkButton(
            target_box, text="📋 Usar Mi IP Local", font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY, height=30, command=self.on_load_my_local_ip
        )
        self.btn_paste_lan_ip.grid(row=0, column=2, padx=6, pady=10)

        self.btn_start_audit = ctk.CTkButton(
            target_box, text="🔍 Iniciar Auditoría de Puertos y Servicios", font=("Segoe UI", 11, "bold"),
            fg_color=ACCENT_CYAN, hover_color=("#0891b2", "#0e7490"), text_color="#ffffff", height=30, command=self.start_device_audit_async
        )
        self.btn_start_audit.grid(row=0, column=3, padx=(6, 12), pady=10)

        # Tabla de Resultados de Auditoría
        audit_table_box = ctk.CTkFrame(self.tab_auditor, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
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
        
        audit_actions = ctk.CTkFrame(audit_table_box, fg_color="transparent")
        audit_actions.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 8))
        
        btn_isolate_target = ctk.CTkButton(
            audit_actions, text="🚫 Aislar Host en este Equipo (Regla de Firewall)", font=("Segoe UI", 10, "bold"),
            fg_color=ACCENT_RED, hover_color="#c0392b", text_color="#ffffff", height=30, command=self.on_isolate_target_clicked
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
            
        card_gw = ctk.CTkFrame(sentinel_top, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        card_gw.grid(row=0, column=0, padx=(0, 4), sticky="ew")
        
        ctk.CTkLabel(card_gw, text="🌐 PUERTA DE ENLACE (ROUTER)", font=FONT_CARD_LABEL, text_color=TEXT_MUTED).pack(anchor="w", padx=10, pady=(8, 2))
        self.lbl_sentinel_gw_ip = ctk.CTkLabel(card_gw, text="Gateway IP: 192.168.1.1", font=("Segoe UI", 11, "bold"), text_color=ACCENT_CYAN)
        self.lbl_sentinel_gw_ip.pack(anchor="w", padx=10, pady=1)
        self.lbl_sentinel_gw_mac = ctk.CTkLabel(card_gw, text="MAC: 00:00:00:00:00:00", font=("Segoe UI", 10), text_color=TEXT_PRIMARY)
        self.lbl_sentinel_gw_mac.pack(anchor="w", padx=10, pady=(0, 8))
        
        card_wifi = ctk.CTkFrame(sentinel_top, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        card_wifi.grid(row=0, column=1, padx=4, sticky="ew")
        
        ctk.CTkLabel(card_wifi, text="📡 TELEMETRÍA WI-FI / BSSID", font=FONT_CARD_LABEL, text_color=TEXT_MUTED).pack(anchor="w", padx=10, pady=(8, 2))
        self.lbl_sentinel_ssid = ctk.CTkLabel(card_wifi, text="SSID: No conectado", font=("Segoe UI", 11, "bold"), text_color=ACCENT_CYAN)
        self.lbl_sentinel_ssid.pack(anchor="w", padx=10, pady=1)
        self.lbl_sentinel_bssid = ctk.CTkLabel(card_wifi, text="BSSID: N/A | Canal: N/A", font=("Segoe UI", 10), text_color=TEXT_PRIMARY)
        self.lbl_sentinel_bssid.pack(anchor="w", padx=10, pady=(0, 8))
        
        card_shield = ctk.CTkFrame(sentinel_top, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        card_shield.grid(row=0, column=2, padx=(4, 0), sticky="ew")
        
        ctk.CTkLabel(card_shield, text="🛡️ ESCUDO ANTI-ARP SPOOFING", font=FONT_CARD_LABEL, text_color=TEXT_MUTED).pack(anchor="w", padx=10, pady=(8, 2))
        self.lbl_sentinel_shield_status = ctk.CTkLabel(card_shield, text="INACTIVO ⚠️", font=("Segoe UI", 12, "bold"), text_color=ACCENT_GOLD)
        self.lbl_sentinel_shield_status.pack(anchor="w", padx=10, pady=1)
        
        shield_controls = ctk.CTkFrame(card_shield, fg_color="transparent")
        shield_controls.pack(fill="x", padx=10, pady=(0, 6))
        
        self.switch_arp_guard = ctk.CTkSwitch(
            shield_controls, text="Activar Escudo", font=("Segoe UI", 10, "bold"),
            command=self.on_toggle_arp_guard, progress_color=ACCENT_GREEN
        )
        self.switch_arp_guard.pack(side="left")
        
        self.chk_auto_fix = ctk.CTkCheckBox(
            shield_controls, text="Autoprotección", font=("Segoe UI", 9),
            hover_color=BG_CARD_HOVER
        )
        self.chk_auto_fix.pack(side="right")

        sentinel_actions = ctk.CTkFrame(self.tab_sentinel, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        sentinel_actions.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        
        btn_audit_gateway = ctk.CTkButton(
            sentinel_actions, text="🔍 Auditar Vulnerabilidades del Router", font=("Segoe UI", 10, "bold"),
            fg_color=ACCENT_CYAN, hover_color=("#0891b2", "#0e7490"), text_color="#ffffff", height=32, command=self.start_gateway_audit_async
        )
        btn_audit_gateway.pack(side="left", padx=10, pady=8)
        
        btn_evil_twin = ctk.CTkButton(
            sentinel_actions, text="📡 Buscar Redes Gemelas (Evil Twin)", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=BG_CARD_HOVER, text_color=ACCENT_CYAN, height=32, command=self.start_evil_twin_scan_async
        )
        btn_evil_twin.pack(side="left", padx=(0, 10), pady=8)
        
        btn_wifi_kill = ctk.CTkButton(
            sentinel_actions, text="🛑 Aislamiento Wi-Fi de Emergencia", font=("Segoe UI", 10, "bold"),
            fg_color=ACCENT_RED, hover_color="#c0392b", text_color="#ffffff", height=32, command=self.on_wifi_kill_clicked
        )
        btn_wifi_kill.pack(side="right", padx=10, pady=8)

        self.tabview_sentinel = ctk.CTkTabview(self.tab_sentinel, fg_color=BG_CARD, corner_radius=8)
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
    # CONSTRUCCIÓN PESTAÑA FILTRO DE RED
    # -------------------------------------------------------------
    def _build_access_tab(self):
        self.tab_access.grid_columnconfigure(0, weight=1)
        self.tab_access.grid_rowconfigure(1, weight=1)
        
        acc_header = ctk.CTkFrame(self.tab_access, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        acc_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        acc_header.grid_columnconfigure(1, weight=1)
        
        lbl_acc_title = ctk.CTkLabel(acc_header, text="🛡️ Sistema de Control de Acceso Local", font=FONT_SUBTITLE, text_color=ACCENT_CYAN)
        lbl_acc_title.grid(row=0, column=0, padx=12, pady=10, sticky="w")
        
        lbl_mode_sel = ctk.CTkLabel(acc_header, text="Modo de Política:", font=("Segoe UI", 10, "bold"), text_color=TEXT_MUTED)
        lbl_mode_sel.grid(row=0, column=1, padx=(12, 4), pady=10, sticky="e")
        
        self.seg_access_mode = ctk.CTkSegmentedButton(
            acc_header, values=["Blacklist Mode", "Whitelist Mode"], command=self.on_access_mode_changed,
            font=("Segoe UI", 10, "bold"), selected_color=ACCENT_CYAN, selected_hover_color=BG_CARD_HOVER
        )
        self.seg_access_mode.set("Blacklist Mode")
        self.seg_access_mode.grid(row=0, column=2, padx=12, pady=10, sticky="e")
        
        acc_table_box = ctk.CTkFrame(self.tab_access, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        acc_table_box.grid(row=1, column=0, sticky="nsew")
        acc_table_box.grid_columnconfigure(0, weight=1)
        acc_table_box.grid_rowconfigure(0, weight=1)
        
        columns = ("mac", "ip", "alias", "status", "compliance")
        self.tree_access = ttk.Treeview(acc_table_box, columns=columns, show="headings", style="Cyber.Treeview", selectmode="browse")
        
        self.tree_access.heading("mac", text="Dirección MAC", anchor="center")
        self.tree_access.heading("ip", text="Dirección IP", anchor="w")
        self.tree_access.heading("alias", text="Nombre / Alias", anchor="w")
        self.tree_access.heading("status", text="Regla Asignada", anchor="center")
        self.tree_access.heading("compliance", text="Estado de Acceso Efectivo", anchor="w")
        
        self.tree_access.column("mac", width=160, minwidth=130, anchor="center")
        self.tree_access.column("ip", width=140, minwidth=110, anchor="w")
        self.tree_access.column("alias", width=180, minwidth=120, anchor="w")
        self.tree_access.column("status", width=140, minwidth=110, anchor="center")
        self.tree_access.column("compliance", width=360, minwidth=220, anchor="w")
        
        scrollbar_acc = ttk.Scrollbar(acc_table_box, orient="vertical", command=self.tree_access.yview)
        self.tree_access.configure(yscrollcommand=scrollbar_acc.set)
        
        self.tree_access.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
        scrollbar_acc.grid(row=0, column=1, sticky="ns", padx=(0, 10), pady=10)
        
        acc_actions = ctk.CTkFrame(acc_table_box, fg_color="transparent")
        acc_actions.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 8))
        
        btn_acc_add = ctk.CTkButton(
            acc_actions, text="➕ Agregar Regla Manual", font=("Segoe UI", 10, "bold"),
            fg_color=ACCENT_CYAN, hover_color=("#0891b2", "#0e7490"), text_color="#ffffff", height=28, command=self.open_add_access_rule_modal
        )
        btn_acc_add.pack(side="left", padx=(0, 8))
        
        btn_acc_allow = ctk.CTkButton(
            acc_actions, text="✅ Marcar Permitido", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=BG_CARD_HOVER, text_color=ACCENT_GREEN, height=28, command=lambda: self.set_selected_access_status("allowed")
        )
        btn_acc_allow.pack(side="left", padx=(0, 8))
        
        btn_acc_block = ctk.CTkButton(
            acc_actions, text="🚫 Marcar Bloqueado", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=BG_CARD_HOVER, text_color=ACCENT_RED, height=28, command=lambda: self.set_selected_access_status("blocked")
        )
        btn_acc_block.pack(side="left", padx=(0, 8))
        
        btn_acc_delete = ctk.CTkButton(
            acc_actions, text="🗑️ Eliminar Regla", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=BG_CARD_HOVER, text_color=TEXT_MUTED, height=28, command=self.on_delete_access_rule_clicked
        )
        btn_acc_delete.pack(side="left")

    # -------------------------------------------------------------
    # CONSTRUCCIÓN PESTAÑA DIAGNÓSTICO DE BLOQUEOS
    # -------------------------------------------------------------
    def _build_restrictions_tab(self):
        self.tab_restrictions.grid_columnconfigure(0, weight=1)
        self.tab_restrictions.grid_rowconfigure(1, weight=1)
        
        res_header = ctk.CTkFrame(self.tab_restrictions, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        res_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        res_header.grid_columnconfigure(1, weight=1)
        
        lbl_res_title = ctk.CTkLabel(res_header, text="🌐 Diagnóstico de Bloqueos y Restricciones de Red", font=FONT_SUBTITLE, text_color=ACCENT_CYAN)
        lbl_res_title.grid(row=0, column=0, padx=12, pady=10, sticky="w")
        
        self.lbl_adapter_info = ctk.CTkLabel(res_header, text=f"Interfaz: {get_active_network_adapter()}", font=FONT_BODY, text_color=TEXT_MUTED)
        self.lbl_adapter_info.grid(row=0, column=1, padx=12, pady=10, sticky="w")
        
        self.btn_test_restrictions = ctk.CTkButton(
            res_header, text="⚡ Testear Restricciones de Red", font=("Segoe UI", 11, "bold"),
            fg_color=ACCENT_CYAN, hover_color=("#0891b2", "#0e7490"), text_color="#ffffff", height=32, command=self.start_restriction_test_async
        )
        self.btn_test_restrictions.grid(row=0, column=2, padx=12, pady=10, sticky="e")
        
        res_table_box = ctk.CTkFrame(self.tab_restrictions, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
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
            fg_color=ACCENT_GREEN, hover_color="#15803d", text_color="#ffffff", height=30, command=self.on_apply_secure_dns_clicked
        )
        btn_apply_dns.pack(side="left", padx=(0, 8))
        
        btn_reset_dns = ctk.CTkButton(
            res_actions, text="🔄 Restaurar DNS Automático (DHCP)", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY, height=30, command=self.on_reset_dns_clicked
        )
        btn_reset_dns.pack(side="left", padx=(0, 8))
        
        btn_clean_hosts = ctk.CTkButton(
            res_actions, text="🧹 Limpiar Archivo Hosts", font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER, hover_color=BG_CARD_HOVER, text_color=ACCENT_GOLD, height=30, command=self.on_clean_hosts_clicked
        )
        btn_clean_hosts.pack(side="left")

    # -------------------------------------------------------------
    # GESTIÓN Y RENDERIZADO DE TARJETAS FING
    # -------------------------------------------------------------
    def render_device_cards(self):
        """Renderiza la lista de tarjetas interactivas de dispositivos estilo Fing."""
        for widget in self.scroll_devices.winfo_children():
            widget.destroy()
            
        search_q = self.entry_network_search.get().strip().lower()
        aliases = load_device_aliases()
        
        filtered_devices = []
        for dev in self.lan_devices:
            ip = dev.get("ip", "")
            mac = dev.get("mac", "")
            host = dev.get("hostname", "")
            vendor = dev.get("vendor", "")
            dtype = dev.get("device_type", "")
            alias = aliases.get(mac.upper(), "")
            
            if search_q:
                match = (
                    search_q in ip.lower()
                    or search_q in mac.lower()
                    or search_q in host.lower()
                    or search_q in vendor.lower()
                    or search_q in dtype.lower()
                    or search_q in alias.lower()
                )
                if not match:
                    continue
            filtered_devices.append(dev)
            
        if not filtered_devices:
            empty_frame = ctk.CTkFrame(self.scroll_devices, fg_color=BG_CARD, corner_radius=12, border_width=1, border_color=COLOR_BORDER)
            empty_frame.pack(fill="x", expand=True, padx=20, pady=40)
            
            if not self.lan_devices:
                icon_text = "📡"
                msg_main = "No se han detectado dispositivos aún en la red local"
                msg_sub = "Presione el botón 'Escanear Red Wi-Fi / LAN' para iniciar el barrido ARP multihilo y mapear los equipos."
            else:
                icon_text = "🔍"
                msg_main = "Ningún dispositivo coincide con la búsqueda"
                msg_sub = f"No se encontraron resultados para '{search_q}'. Intente con otra IP, MAC o nombre."
                
            ctk.CTkLabel(empty_frame, text=icon_text, font=("Segoe UI Emoji", 32)).pack(pady=(25, 8))
            ctk.CTkLabel(empty_frame, text=msg_main, font=("Segoe UI", 13, "bold"), text_color=TEXT_PRIMARY).pack(pady=(0, 4))
            ctk.CTkLabel(empty_frame, text=msg_sub, font=FONT_BODY, text_color=TEXT_MUTED).pack(pady=(0, 25))
            return

        for dev in filtered_devices:
            mac = dev.get("mac", "")
            ip = dev.get("ip", "")
            is_local = dev.get("is_local", False)
            
            is_allowed, _ = is_device_allowed(mac, ip)
            is_blocked = (not is_allowed and not is_local)
            
            # Determinar el nivel de riesgo del dispositivo (desde telemetría de sockets activa)
            dev_risk_level = "LOW"
            if not is_local:
                for c in self.current_connections:
                    conn_remote = c.get("remote_ip") or ""
                    conn_remote = conn_remote if conn_remote not in ("-", "*") else ""
                    conn_local = c.get("local_ip") or ""
                    conn_local = conn_local if conn_local not in ("-", "*") else ""
                    if (ip and conn_remote == ip) or (is_local and conn_local == ip):
                        dev_risk_level = c.get("risk_level") or "LOW"
                        break
            
            card = DeviceCard(
                self.scroll_devices,
                device=dev,
                is_blocked=is_blocked,
                risk_level=dev_risk_level,
                on_audit=self.on_device_card_audit,
                on_isolate=self.on_device_card_isolate,
                on_copy=self.on_device_card_copy,
                on_alias_saved=self.on_device_card_alias_saved
            )
            card.pack(fill="x", expand=True, pady=4, padx=6)

    def on_device_card_audit(self, ip: str):
        """Acción rápida de tarjeta Fing: cambia a pestaña Auditoría y carga la IP."""
        self.switch_tab("auditor")
        self.entry_audit_target.delete(0, "end")
        self.entry_audit_target.insert(0, ip)
        self.log_message(f"[AUDITORÍA] IP objetivo cargada desde tarjeta Fing: {ip}", "INFO")
        self.start_device_audit_async()

    def on_device_card_isolate(self, ip: str, hostname: str, is_currently_blocked: bool):
        """Acción rápida de tarjeta Fing: aísla o desbloquea el host en el firewall local."""
        if not is_currently_blocked:
            if not messagebox.askyesno(
                "Aislar en Firewall",
                f"¿Desea aislar el dispositivo '{hostname}' ({ip}) en el Firewall de Windows?\n\nSe bloqueará todo el tráfico de red local con este equipo."
            ):
                return
            threading.Thread(target=self._lan_block_worker, args=(ip, hostname), daemon=True).start()
        else:
            if not messagebox.askyesno(
                "Desbloquear Dispositivo",
                f"¿Restaurar comunicación con '{hostname}' ({ip}) y eliminar la regla de aislamiento del Firewall?"
            ):
                return
            threading.Thread(target=self._lan_unblock_worker, args=(ip, hostname), daemon=True).start()

    def _lan_unblock_worker(self, ip, alias):
        success, msg = unblock_ip_host(ip, alias)
        self.after(0, self.log_message, msg, "SUCCESS" if success else "ERROR")
        self.after(0, messagebox.showinfo if success else messagebox.showerror, "Desbloqueo de Red Local", msg)
        self.after(0, self.render_device_cards)
        self.after(0, self.refresh_access_control_ui)

    def on_device_card_copy(self, text: str, ip: str):
        self.log_message(f"[PORTAPAPELES] Copiada información de {ip}: {text}", "INFO")

    def on_device_card_alias_saved(self, mac: str, alias: str):
        self.log_message(f"[DISPOSITIVOS] Alias actualizado para MAC {mac}: '{alias}'", "SUCCESS")
        set_inventory_alias(mac, alias)
        self.render_device_cards()

    # -------------------------------------------------------------
    # ACTUALIZACIÓN DE MÉTRICAS EN VIVO DEL DASHBOARD
    # -------------------------------------------------------------
    def _update_top_metric_cards(self):
        """Actualiza las 4 métricas compactas del dashboard de Red en vivo."""
        # 1. Red Actual
        ssid = self.gateway_cache.get("ssid", "")
        bssid = self.gateway_cache.get("bssid", "")
        signal = self.gateway_cache.get("signal", "")
        if ssid and ssid != "No conectado":
            self.card_net_val.configure(text=f"Wi-Fi: {ssid[:18]}")
            sub_info = f"BSSID: {bssid}"
            if signal and signal != "N/A":
                sub_info += f" • {signal}"
            self.card_net_sub.configure(text=sub_info)
        else:
            adapter = get_active_network_adapter()
            self.card_net_val.configure(text=f"Red: {adapter[:18]}")
            self.card_net_sub.configure(text="Conexión Cableada / LAN")
            
        # 2. Dispositivos Activos
        local_ip = get_local_ip()
        dev_count = len(self.lan_devices)
        self.card_dev_val.configure(text=f"{dev_count} Activos")
        subnet_str = f"Subred: {local_ip.rsplit('.', 1)[0]}.0/24" if "." in local_ip else "Subred local"
        self.card_dev_sub.configure(text=subnet_str)
        
        # 3. Gateway / Router
        gw_ip = self.gateway_cache.get("gateway_ip")
        if not gw_ip:
            gw_ip = next((d["ip"] for d in self.lan_devices if d.get("is_gateway")), f"{local_ip.rsplit('.', 1)[0]}.1")
        gw_mac = self.gateway_cache.get("gateway_mac", "Detectando...")
        self.card_gw_val.configure(text=f"{gw_ip}")
        self.card_gw_sub.configure(text=f"MAC: {gw_mac}")
        
        # 4. Estado del Escudo
        if self.arp_guard_active:
            self.card_shield_val.configure(text="ACTIVO 🛡️", text_color=ACCENT_GREEN)
            self.card_shield_sub.configure(text="Escudo Anti-ARP Spoofing")
        else:
            self.card_shield_val.configure(text="EN ESPERA ⚠️", text_color=ACCENT_GOLD)
            self.card_shield_sub.configure(text="Protección en espera")

    # -------------------------------------------------------------
    # NAVEGACIÓN Y CAMBIO DE PESTAÑAS
    # -------------------------------------------------------------
    def switch_tab(self, tab_key: str):
        if tab_key in ("lan", "network"):
            self.tabview.set("📡 Red & Dispositivos")
            self.seg_network_view.set("Vista Dispositivos (Fing)")
            self.on_network_view_changed("Vista Dispositivos (Fing)")
        elif tab_key == "sockets":
            self.tabview.set("📡 Red & Dispositivos")
            self.seg_network_view.set("Vista Sockets (Forense)")
            self.on_network_view_changed("Vista Sockets (Forense)")
        elif tab_key == "sentinel":
            self.tabview.set("🚨 Centinela Wi-Fi (IDS)")
            self.refresh_sentinel_gateway_info_async()
        elif tab_key == "auditor":
            self.tabview.set("🛡️ Auditoría & Hardening")
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
        if "Red" in tab_name:
            curr_view = self.seg_network_view.get()
            if "Fing" in curr_view:
                self._update_nav_buttons_highlight("lan")
                if not self.lan_devices:
                    self.start_lan_scan_async()
            else:
                self._update_nav_buttons_highlight("sockets")
                if not self.current_connections:
                    self.start_scan_async()
        elif "Centinela" in tab_name:
            self._update_nav_buttons_highlight("sentinel")
            self.refresh_sentinel_gateway_info_async()
        elif "Auditoría" in tab_name:
            self._update_nav_buttons_highlight("auditor")
        elif "Filtro" in tab_name:
            self._update_nav_buttons_highlight("access")
            self.refresh_access_control_ui()
        elif "Diagnóstico" in tab_name:
            self._update_nav_buttons_highlight("restrictions")
            if not self.restriction_results:
                self.start_restriction_test_async()

    def _update_nav_buttons_highlight(self, active_key: str):
        btns = {
            "lan": self.btn_nav_lan,
            "sockets": self.btn_nav_sockets,
            "sentinel": self.btn_nav_sentinel,
            "auditor": self.btn_nav_auditor,
            "access": self.btn_nav_access,
            "restrictions": self.btn_nav_restrictions
        }
        for key, btn in btns.items():
            if key == active_key:
                btn.configure(fg_color=ACCENT_CYAN, text_color="#ffffff")
            else:
                btn.configure(fg_color=BG_CARD, text_color=TEXT_PRIMARY)

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

    def toggle_console_visibility(self):
        """Alterna la visibilidad del área de texto de la consola para ganar espacio vertical."""
        if self.console_visible:
            self.txt_console.grid_forget()
            self.console_visible = False
            self.btn_toggle_console.configure(text="[ Expandir Consola ▲ ]")
        else:
            self.txt_console.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 6))
            self.console_visible = True
            self.btn_toggle_console.configure(text="[ Minimizar Consola ▼ ]")

    # -------------------------------------------------------------
    # GESTIÓN DE TEMAS Y TAGS TREEVIEW
    # -------------------------------------------------------------
    def _update_all_treeview_tags(self, effective_mode: str):
        is_light = str(effective_mode).lower() == "light"
        even_bg = "#ffffff" if is_light else "#161f30"
        odd_bg = "#f1f5f9" if is_light else "#0b0f19"
        pub_fg = ACCENT_CYAN
        blk_fg = ACCENT_RED
        ok_fg = ACCENT_GREEN
        risk_fg = {
            "critical": ACCENT_RED,
            "high": ACCENT_RED,
            "medium": ACCENT_GOLD,
            "low": ACCENT_GREEN,
        }
        
        for t in (self.tree, self.tree_access, self.tree_restrictions, self.tree_sentinel_ports, self.tree_sentinel_eviltwin, self.tree_auditor):
            try:
                t.tag_configure("even", background=even_bg)
                t.tag_configure("odd", background=odd_bg)
                t.tag_configure("public", foreground=pub_fg)
                t.tag_configure("blocked", foreground=blk_fg)
                t.tag_configure("allowed", foreground=ok_fg)
                t.tag_configure("accessible", foreground=ok_fg)
                for lvl, fg in risk_fg.items():
                    t.tag_configure(f"risk_{lvl}", foreground=fg)
            except Exception:
                pass

    def _on_theme_changed(self, new_theme: str):
        ctk.set_appearance_mode(new_theme)
        effective_mode = ctk.get_appearance_mode()
        
        configure_treeview_style(effective_mode)
        self._update_all_treeview_tags(effective_mode)
        self._apply_table_filters()
        self.render_device_cards()
        self.refresh_access_control_ui()
        self.refresh_restrictions_table_ui()
        
        self.config["theme"] = new_theme
        save_config(self.config)
        self.log_message(f"[CONFIG] Modo de apariencia cambiado a '{new_theme}'.", "INFO")

    # -------------------------------------------------------------
    # MÓDULO ESCÁNER DE RED LOCAL (FING)
    # -------------------------------------------------------------
    def start_lan_scan_async(self):
        self.btn_network_scan.configure(state="disabled", text="⏳ Escaneando Red...")
        self.log_message("[LAN] Iniciando barrido ARP multihilo y descubrimiento de subred...", "INFO")
        threading.Thread(target=self._lan_scan_worker, daemon=True).start()

    def _lan_scan_worker(self):
        try:
            raw_devices = scan_lan_devices()
            devices = process_devices(raw_devices)

            # Notificar nativamente si hay nuevos dispositivos descubiertos
            new_hosts = [d for d in devices if d.get("is_new")]
            for d in new_hosts:
                ip = d.get("ip", "")
                mac = d.get("mac", "")
                vendor = d.get("vendor", "Desconocido")
                notify_new_device(ip, mac, vendor)
                msg_new = f"[INVENTARIO] ¡Nuevo host detectado en la red!: {ip} ({vendor}) [{mac}]"
                self.after(0, self.log_message, msg_new, "WARNING")

            self.after(0, self._update_lan_ui, devices)
        except Exception as e:
            self.after(0, self.log_message, f"[LAN] Error durante escaneo LAN: {str(e)}", "ERROR")
            self.after(0, self._reset_lan_button)

    def _update_lan_ui(self, devices):
        self.lan_devices = devices
        local_ip = get_local_ip()
        gateway_ip = next((d["ip"] for d in devices if d.get("is_gateway")), f"{local_ip.rsplit('.', 1)[0]}.1")
        
        self.log_message(f"[LAN] Escaneo Wi-Fi/LAN finalizado. {len(devices)} dispositivos encontrados.", "SUCCESS")
        self._update_top_metric_cards()
        self.render_device_cards()
        self._reset_lan_button()

    def _reset_lan_button(self):
        curr_view = self.seg_network_view.get()
        btn_txt = "🔍 Escanear Red Wi-Fi / LAN" if "Fing" in curr_view else "🔍 Escanear Sockets"
        self.btn_network_scan.configure(state="normal", text=btn_txt)

    def _lan_block_worker(self, ip, alias):
        success, msg = block_ip_host(ip, alias)
        self.after(0, self.log_message, msg, "SUCCESS" if success else "ERROR")
        self.after(0, messagebox.showinfo if success else messagebox.showerror, "Bloqueo de Red Local", msg)
        self.after(0, self.render_device_cards)
        self.after(0, self.refresh_access_control_ui)

    # -------------------------------------------------------------
    # MÓDULO TELEMETRÍA DE SOCKETS
    # -------------------------------------------------------------
    def start_scan_async(self):
        self.lbl_status.configure(text="Capturando sockets del sistema...", text_color=ACCENT_CYAN)
        if "Sockets" in self.seg_network_view.get():
            self.btn_network_scan.configure(state="disabled", text="⏳ Escaneando Sockets...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            conns = get_active_connections()
            self.after(0, self._update_scan_ui, conns)
        except Exception as e:
            self.after(0, self.log_message, f"[ERROR] Error al recopilar sockets: {str(e)}", "ERROR")
            self.after(0, self._reset_scan_ui_state)

    def _update_scan_ui(self, conns):
        self.current_connections = conns
        self.lbl_status.configure(text=f"Listo ({len(conns)} sockets activos)", text_color=TEXT_MUTED)
        self.log_message(f"[SOCKETS] Mapeo de telemetría completado: {len(conns)} conexiones detectadas.")
        self._reset_scan_ui_state()
        self._apply_table_filters()
        self.start_geoip_resolutions_async()

    def _reset_scan_ui_state(self):
        curr_view = self.seg_network_view.get()
        btn_txt = "🔍 Escanear Red Wi-Fi / LAN" if "Fing" in curr_view else "🔍 Escanear Sockets"
        self.btn_network_scan.configure(state="normal", text=btn_txt)

    def _set_status_filter(self, status: str):
        self.active_status_filter = status
        self.btn_filter_all.configure(fg_color=ACCENT_CYAN if status == "ALL" else COLOR_CARD_INNER, text_color="#ffffff" if status == "ALL" else TEXT_PRIMARY)
        self.btn_filter_estab.configure(fg_color=ACCENT_CYAN if status == "ESTABLISHED" else COLOR_CARD_INNER, text_color="#ffffff" if status == "ESTABLISHED" else TEXT_PRIMARY)
        self.btn_filter_listen.configure(fg_color=ACCENT_CYAN if status == "LISTEN" else COLOR_CARD_INNER, text_color="#ffffff" if status == "LISTEN" else TEXT_PRIMARY)
        self._apply_table_filters()

    def _apply_table_filters(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        filtered = []
        for c in self.current_connections:
            if self.active_status_filter != "ALL" and c["status"] != self.active_status_filter:
                continue
            if self.search_query:
                proc_str = c["process_name"].lower()
                pid_str = str(c["pid"])
                ip_str = c["remote_ip"].lower()
                if self.search_query not in proc_str and self.search_query not in pid_str and self.search_query not in ip_str:
                    continue
            filtered.append(c)

        for idx, c in enumerate(filtered):
            tag = "even" if idx % 2 == 0 else "odd"
            tags = (tag,)
            if c.get("is_public"):
                tags = (tag, "public")

            risk_level = c.get("risk_level") or "LOW"
            risk_tag = f"risk_{str(risk_level).lower()}"
            tags = (tag, risk_tag)

            self.tree.insert("", "end", values=(
                c["pid"],
                c["process_name"],
                c["protocol"],
                c["remote_ip"],
                c["remote_port"],
                c.get("geo_isp", "..."),
                c["status"],
                risk_level
            ), tags=tags)

    def start_geoip_resolutions_async(self):
        public_ips = list({c["remote_ip"] for c in self.current_connections if c.get("is_public")})
        for ip in public_ips:
            self.executor.submit(self._resolve_geoip_worker, ip)

    def _resolve_geoip_worker(self, ip: str):
        geo_info = lookup_ip(ip)
        formatted_str = f"{geo_info.get('flag', '')} {geo_info.get('country', 'N/A')} ({geo_info.get('isp', 'N/A')})"
        self.after(0, self._update_row_geoip, ip, formatted_str)

    def _update_row_geoip(self, ip: str, formatted_str: str):
        for item_id in self.tree.get_children():
            vals = list(self.tree.item(item_id, "values"))
            if vals[3] == ip:
                vals[5] = formatted_str
                self.tree.item(item_id, values=vals)

    def on_block_ip_clicked(self):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Selección requerida", "Por favor seleccione una fila para bloquear la IP remota.")
            return
        vals = self.tree.item(selected_items[0], "values")
        target_ip = vals[3]
        if target_ip in ("0.0.0.0", "127.0.0.1", "::", "-", "N/A"):
            messagebox.showinfo("IP No Bloqueable", f"No se puede bloquear una dirección local o especial ({target_ip}).")
            return
        if not messagebox.askyesno("Confirmar Bloqueo", f"¿Desea bloquear la IP remota {target_ip} en el Firewall de Windows?"):
            return
        threading.Thread(target=self._block_ip_worker, args=(target_ip,), daemon=True).start()

    def _block_ip_worker(self, ip: str):
        success, msg = block_remote_ip(ip)
        self.after(0, self.log_message, msg, "SUCCESS" if success else "ERROR")
        self.after(0, messagebox.showinfo if success else messagebox.showerror, "Bloqueo de IP", msg)

    def on_kill_proc_clicked(self):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Selección requerida", "Por favor seleccione una fila para terminar el proceso.")
            return
        vals = self.tree.item(selected_items[0], "values")
        try:
            pid = int(vals[0])
        except ValueError:
            return
        proc_name = vals[1]
        if pid in (0, 4):
            messagebox.showerror("Acción Denegada", f"No se puede terminar un proceso crítico del Sistema Operativo (PID {pid}).")
            return
        
        # Determinar el nivel de riesgo asociado al proceso seleccionado desde la telemetría
        risk_level = "LOW"
        for c in self.current_connections:
            if c.get("pid") == pid:
                risk_level = c.get("risk_level") or "LOW"
                break
        
        risk_note = f"Riesgo detectado: {risk_level}" if risk_level in ("HIGH", "CRITICAL") else f"Riesgo detectado: {risk_level} (bajo / dentro de lo esperado)"
        if not messagebox.askyesno(
            "Terminar Proceso",
            f"¿Desea forzar la terminación del proceso '{proc_name}' (PID: {pid})?\n\n{risk_note}"
        ):
            return
        threading.Thread(target=self._kill_proc_worker, args=(pid, proc_name), daemon=True).start()

    def _kill_proc_worker(self, pid: int, name: str):
        success, msg = kill_process_by_pid(pid, name)
        self.after(0, self.log_message, msg, "SUCCESS" if success else "ERROR")
        self.after(0, messagebox.showinfo if success else messagebox.showerror, "Terminar Proceso", msg)
        self.start_scan_async()

    def on_export_audit_clicked(self):
        if not self.current_connections:
            messagebox.showwarning("Sin Datos", "No hay conexiones capturadas para exportar.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Archivos CSV", "*.csv"), ("Archivos JSON", "*.json")],
            initialfile=f"KILLNet_Auditoria_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        if not path:
            return
        try:
            if path.endswith(".json"):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self.current_connections, f, indent=2, ensure_ascii=False)
            else:
                keys = ["pid", "process_name", "protocol", "local_ip", "local_port", "remote_ip", "remote_port", "status", "geo_isp", "risk_level", "risk_score"]
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                    writer.writeheader()
                    writer.writerows(self.current_connections)
            self.log_message(f"[EXPORT] Auditoría exportada exitosamente a: {path}", "SUCCESS")
            messagebox.showinfo("Exportación Exitosa", f"Archivo generado:\n{path}")
        except Exception as e:
            self.log_message(f"[EXPORT ERROR] No se pudo guardar: {str(e)}", "ERROR")
            messagebox.showerror("Error al Exportar", str(e))

    # -------------------------------------------------------------
    # MÓDULO CENTINELA WI-FI (IDS)
    # -------------------------------------------------------------
    def refresh_sentinel_gateway_info_async(self):
        threading.Thread(target=self._sentinel_info_worker, daemon=True).start()

    def _sentinel_info_worker(self):
        info = get_gateway_info()
        self.gateway_cache = info
        self.after(0, self._update_sentinel_info_ui, info)
        self.after(0, self._update_top_metric_cards)

    def _update_sentinel_info_ui(self, info: dict):
        self.lbl_sentinel_gw_ip.configure(text=f"Gateway IP: {info['gateway_ip']}")
        self.lbl_sentinel_gw_mac.configure(text=f"MAC: {info['gateway_mac']}")
        self.lbl_sentinel_ssid.configure(text=f"SSID: {info['ssid']}")
        self.lbl_sentinel_bssid.configure(text=f"BSSID: {info['bssid']} | Canal: {info['channel']}")

    def on_toggle_arp_guard(self):
        if self.switch_arp_guard.get() == 1:
            self.arp_guard_active = True
            self.arp_guard_stop_event.clear()
            self.lbl_sentinel_shield_status.configure(text="ACTIVO (Blindaje)", text_color=ACCENT_GREEN)
            self.log_message("[IDS CENTINELA] Escudo Anti-ARP Spoofing ACTIVADO.", "SUCCESS")
            auto_fix = bool(self.chk_auto_fix.get() == 1)
            self.arp_guard_thread = threading.Thread(
                target=start_arp_guard,
                args=(self._arp_alert_callback, self.arp_guard_stop_event, auto_fix),
                daemon=True
            )
            self.arp_guard_thread.start()
        else:
            self.arp_guard_active = False
            self.arp_guard_stop_event.set()
            self.lbl_sentinel_shield_status.configure(text="INACTIVO ⚠️", text_color=ACCENT_GOLD)
            self.log_message("[IDS CENTINELA] Escudo Anti-ARP Spoofing DETENIDO.", "WARNING")
        self._update_top_metric_cards()

    def _arp_alert_callback(self, alert_data: dict):
        msg = f"[ALERTA IDS] {alert_data.get('type')}: {alert_data.get('message')}"
        self.after(0, self.log_message, msg, "DANGER")
        if alert_data.get("type") == "ARP_SPOOFING_DETECTED":
            gw_ip = self.gateway_cache.get("gateway_ip") or "Router"
            spoofed_mac = alert_data.get("current_mac", alert_data.get("spoofed_mac", "Desconocida"))
            notify_mitm_alert(gw_ip, spoofed_mac)
            self.after(0, messagebox.showerror, "🚨 ALERTA ROJA: Suplantación de Gateway (ARP Spoofing)", alert_data.get("message"))

    def start_gateway_audit_async(self):
        gw_raw = self.lbl_sentinel_gw_ip.cget("text").replace("Gateway IP: ", "").strip()
        gw_ip = gw_raw if (gw_raw and gw_raw not in ("Desconocido", "-", "127.0.0.1", "0.0.0.0")) else ""
        if not gw_ip:
            gw_ip = self.gateway_cache.get("gateway_ip") or get_gateway_ip() or "192.168.1.1"
        self.log_message(f"[CENTINELA] Auditando puertos y servicios del router ({gw_ip})...", "INFO")
        threading.Thread(target=self._gateway_audit_worker, args=(gw_ip,), daemon=True).start()

    def _gateway_audit_worker(self, gw_ip: str):
        try:
            results = audit_gateway_security(gw_ip)
            self.after(0, self._update_gateway_audit_ui, results)
        except Exception as e:
            self.after(0, self.log_message, f"[CENTINELA] Error en auditoría: {str(e)}", "ERROR")
            self.after(0, self._update_gateway_audit_ui, [])

    def _update_gateway_audit_ui(self, results: list):
        for item in self.tree_sentinel_ports.get_children():
            self.tree_sentinel_ports.delete(item)

        if not results:
            self.tree_sentinel_ports.insert("", "end", values=(
                "-", "Puerta de Enlace", "SEGURO ✅", "SEGURO", "No se detectaron puertos críticos expuestos en la puerta de enlace."
            ), tags=("allowed",))
            self.log_message("[CENTINELA] Auditoría finalizada: No se detectaron puertos críticos expuestos en la puerta de enlace.", "SUCCESS")
            return

        for r in results:
            port = r.get("port", "-")
            service = r.get("service", "Desconocido")
            status = r.get("status", "CERRADO")
            risk = r.get("risk_level", r.get("risk_if_open", "SEGURO"))
            rec = r.get("recommendation", r.get("rec", r.get("info", "")))

            tag = "even"
            if risk in ("CRÍTICO", "ALTO", "PELIGRO") and "ABIERTO" in str(status):
                tag = "blocked"
            elif "CERRADO" in str(status) or risk == "SEGURO":
                tag = "allowed"

            self.tree_sentinel_ports.insert("", "end", values=(
                port, service, status, risk, rec
            ), tags=(tag,))
        self.log_message("[CENTINELA] Auditoría de vulnerabilidades del router finalizada.", "SUCCESS")

    def start_evil_twin_scan_async(self):
        self.log_message("[CENTINELA] Escaneando espectro Wi-Fi en busca de Rogue APs / Evil Twin...", "INFO")
        threading.Thread(target=self._evil_twin_worker, daemon=True).start()

    def _evil_twin_worker(self):
        results = detect_evil_twin()
        self.after(0, self._update_evil_twin_ui, results)

    def _update_evil_twin_ui(self, results: list):
        for item in self.tree_sentinel_eviltwin.get_children():
            self.tree_sentinel_eviltwin.delete(item)

        for r in results:
            tag = "even"
            if "PELIGRO" in r["status"] or "ALERTA" in r["status"]:
                tag = "blocked"
            elif "CONFIABLE" in r["status"]:
                tag = "allowed"

            self.tree_sentinel_eviltwin.insert("", "end", values=(
                r["ssid"], r["bssid"], r["auth"], r["status"], r["details"]
            ), tags=(tag,))
        self.log_message("[CENTINELA] Escaneo de espectro inalámbrico finalizado.", "SUCCESS")

    def on_wifi_kill_clicked(self):
        if not messagebox.askyesno("Aislamiento Wi-Fi", "¿DESCONECTAR INMEDIATAMENTE de la red Wi-Fi actual por sospecha de ataque?"):
            return
        success, msg = emergency_wifi_disconnect()
        self.log_message(f"[CENTINELA] {msg}", "DANGER" if success else "ERROR")
        if success:
            messagebox.showwarning("Wi-Fi Desconectado", msg)
        else:
            messagebox.showerror("Fallo al Desconectar", msg)

    # -------------------------------------------------------------
    # MÓDULO AUDITORÍA DE SERVICIOS LOCALES
    # -------------------------------------------------------------
    def on_load_my_local_ip(self):
        local_ip = get_local_ip()
        self.entry_audit_target.delete(0, "end")
        self.entry_audit_target.insert(0, local_ip)
        self.log_message(f"[AUDITOR] IP local cargada en el objetivo: {local_ip}", "INFO")

    def start_device_audit_async(self):
        target = self.entry_audit_target.get().strip()
        if not target:
            messagebox.showwarning("Objetivo Requerido", "Ingrese una dirección IP o host para auditar.")
            return
        self.btn_start_audit.configure(state="disabled", text="⏳ Auditando...")
        self.log_message(f"[AUDITOR] Iniciando diagnóstico de servicios expuestos en {target}...", "INFO")
        threading.Thread(target=self._device_audit_worker, args=(target,), daemon=True).start()

    def _device_audit_worker(self, target: str):
        try:
            results = scan_device_security(target)
            self.after(0, self._update_device_audit_ui, results, target)
        except Exception as e:
            self.after(0, self.log_message, f"[AUDITOR] Error en auditoría: {str(e)}", "ERROR")
            self.after(0, lambda: self.btn_start_audit.configure(state="normal", text="🔍 Iniciar Auditoría de Puertos y Servicios"))

    def _update_device_audit_ui(self, results: list, target: str):
        for item in self.tree_auditor.get_children():
            self.tree_auditor.delete(item)

        if not results:
            self.tree_auditor.insert("", "end", values=(
                "-", "Auditoría de Host", "SEGURO ✅", "No se detectaron puertos críticos expuestos en el objetivo."
            ), tags=("allowed",))
        else:
            for r in results:
                port = r.get("port", "-")
                service = r.get("service", "Desconocido")
                status = r.get("status", "CERRADO")
                banner = r.get("banner", "")

                tag = "even"
                if "ABIERTO" in str(status):
                    tag = "blocked" if ("PELIGRO" in banner or service in ("Telnet", "FTP", "SMB")) else "public"
                elif "CERRADO" in str(status):
                    tag = "allowed"

                self.tree_auditor.insert("", "end", values=(
                    port, service, status, banner
                ), tags=(tag,))

        self.btn_start_audit.configure(state="normal", text="🔍 Iniciar Auditoría de Puertos y Servicios")
        self.log_message(f"[AUDITOR] Auditoría de {target} finalizada ({len(results)} servicios evaluados).", "SUCCESS")

    def on_isolate_target_clicked(self):
        target = self.entry_audit_target.get().strip()
        if not target:
            messagebox.showwarning("Objetivo Requerido", "No hay ninguna IP objetivo especificada para aislar.")
            return
        if target in ("127.0.0.1", "localhost", get_local_ip()):
            messagebox.showerror("Operación Peligrosa", "No puede aislar su propia interfaz local mediante esta función.")
            return
        if not messagebox.askyesno("Aislar Host", f"¿Crear regla en Windows Firewall para bloquear TODO el tráfico con el host {target}?"):
            return
        success, msg = isolate_host_local_firewall(target)
        self.log_message(f"[HARDENING] {msg}", "SUCCESS" if success else "ERROR")
        messagebox.showinfo("Aislamiento Perimetral", msg)

    # -------------------------------------------------------------
    # MÓDULO CONTROL DE ACCESO (BLACKLIST / WHITELIST)
    # -------------------------------------------------------------
    def refresh_access_control_ui(self):
        for item in self.tree_access.get_children():
            self.tree_access.delete(item)

        rules_data = load_access_rules()
        devices = rules_data.get("devices", [])
        
        device_items = []
        if isinstance(devices, dict):
            for key, val in devices.items():
                if isinstance(val, dict):
                    mac = val.get("mac", key if ":" in key else "N/A")
                    ip = val.get("ip", key if "." in key else "N/A")
                    alias = val.get("alias", "Sin alias")
                    status = val.get("status", "allowed")
                else:
                    mac = key if ":" in key else "N/A"
                    ip = key if "." in key else "N/A"
                    alias = "Sin alias"
                    status = str(val)
                device_items.append((mac, ip, alias, status))
        elif isinstance(devices, list):
            for d in devices:
                if isinstance(d, dict):
                    mac = d.get("mac", "N/A")
                    ip = d.get("ip", "N/A")
                    alias = d.get("alias", "Sin alias")
                    status = d.get("status", "allowed")
                    device_items.append((mac, ip, alias, status))

        for mac, ip, alias, status in device_items:
            is_allowed, compliance_msg = is_device_allowed(mac, ip)
            tag = "allowed" if is_allowed else "blocked"

            self.tree_access.insert("", "end", values=(mac, ip, alias, str(status).upper(), compliance_msg), tags=(tag,))

    def on_access_mode_changed(self, value: str):
        new_mode = "blacklist" if "Blacklist" in value else "whitelist"
        set_access_control_mode(new_mode)
        self.log_message(f"[ACCESO] Modo cambiado a '{new_mode.upper()}'.", "INFO")
        self.refresh_access_control_ui()
        self.render_device_cards()

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
        self.render_device_cards()

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
            self.render_device_cards()

    def open_add_access_rule_modal(self):
        modal = ctk.CTkToplevel(self)
        modal.title("➕ Agregar Regla de Control de Acceso")
        modal.configure(fg_color=BG_MAIN)
        modal.transient(self)
        modal.grab_set()
        
        self._center_modal(modal, 420, 380)
        
        lbl_t = ctk.CTkLabel(modal, text="➕ Agregar Dispositivo a la Lista", font=("Segoe UI", 14, "bold"), text_color=ACCENT_CYAN)
        lbl_t.pack(pady=(16, 10))
        
        ctk.CTkLabel(modal, text="Dirección MAC (XX:XX:XX:XX:XX:XX):", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=30, pady=(4, 2))
        entry_mac = ctk.CTkEntry(modal, placeholder_text="AA:BB:CC:DD:EE:FF", fg_color=BG_CARD, text_color=TEXT_PRIMARY)
        entry_mac.pack(fill="x", padx=30, pady=(0, 8))
        
        ctk.CTkLabel(modal, text="Dirección IP Local (Opcional):", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=30, pady=(4, 2))
        entry_ip = ctk.CTkEntry(modal, placeholder_text="192.168.1.50", fg_color=BG_CARD, text_color=TEXT_PRIMARY)
        entry_ip.pack(fill="x", padx=30, pady=(0, 8))
        
        ctk.CTkLabel(modal, text="Alias / Nombre del Dispositivo:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=30, pady=(4, 2))
        entry_alias = ctk.CTkEntry(modal, placeholder_text="Teléfono Personal", fg_color=BG_CARD, text_color=TEXT_PRIMARY)
        entry_alias.pack(fill="x", padx=30, pady=(0, 8))
        
        ctk.CTkLabel(modal, text="Estado de la Regla:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=30, pady=(4, 2))
        opt_status = ctk.CTkOptionMenu(modal, values=["blocked", "allowed"], fg_color=BG_CARD, button_color=COLOR_BORDER, text_color=TEXT_PRIMARY)
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
            self.render_device_cards()
            modal.destroy()
            
        btn_save = ctk.CTkButton(modal, text="Guardar Regla", font=("Segoe UI", 11, "bold"), fg_color=ACCENT_CYAN, command=save_rule)
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
    # MODO PÁNICO Y MONITOREO EN VIVO
    # -------------------------------------------------------------
    def toggle_auto_monitor(self):
        self.is_auto_monitoring = not self.is_auto_monitoring
        if self.is_auto_monitoring:
            self.btn_auto_monitor.configure(text="📡 Monitoreo En Vivo [ON]", fg_color=ACCENT_GREEN, text_color="#ffffff")
            self.log_message("[MONITOREO] Monitoreo automático en vivo ACTIVADO.", "SUCCESS")
            threading.Thread(target=self._auto_monitor_loop, daemon=True).start()
        else:
            self.btn_auto_monitor.configure(text="📡 Monitoreo En Vivo [OFF]", fg_color=BG_CARD, text_color=TEXT_PRIMARY)
            self.log_message("[MONITOREO] Monitoreo automático en vivo DETENIDO.", "INFO")

    def _auto_monitor_loop(self):
        while self.is_auto_monitoring:
            time.sleep(self.config.get("auto_refresh_seconds", 3))
            if not self.is_auto_monitoring:
                break
            try:
                conns = get_active_connections()
                self.after(0, self._update_scan_ui, conns)
            except Exception:
                pass

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
            self.btn_emergency.configure(text="🔓 Desactivar Modo Pánico", fg_color=ACCENT_GOLD, hover_color="#b7791f")
        else:
            self.btn_emergency.configure(text="🚨 Modo Pánico (Aislamiento)", fg_color=ACCENT_RED, hover_color="#c0392b")

    # -------------------------------------------------------------
    # MODALES: DONACIÓN, SUPPORT & MANUAL
    # -------------------------------------------------------------
    def open_donation_modal(self):
        modal = ctk.CTkToplevel(self)
        modal.title("☕ Apoyar el Proyecto KILLNet")
        modal.configure(fg_color=BG_MAIN)
        modal.transient(self)
        modal.grab_set()
        
        self._center_modal(modal, 460, 340)
        
        lbl_title = ctk.CTkLabel(modal, text="☕ Apoyar el Proyecto KILLNet", font=("Segoe UI", 16, "bold"), text_color=ACCENT_GOLD)
        lbl_title.pack(pady=(22, 10))
        
        card_info = ctk.CTkFrame(modal, fg_color=BG_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        card_info.pack(fill="x", padx=25, pady=(0, 15))
        
        lbl_desc = ctk.CTkLabel(
            card_info, text="KILLNet es una herramienta forense de red gratuita y de código abierto.\n\nSi te ha resultado útil para auditorías de telemetría y seguridad en tu sistema, puedes apoyar directamente su desarrollo continuo.",
            font=FONT_BODY, justify="center", text_color=TEXT_PRIMARY, wraplength=380
        )
        lbl_desc.pack(padx=15, pady=15)
        
        btn_cafecito = ctk.CTkButton(
            modal, text="☕ Donar en Cafecito (Argentina)", font=("Segoe UI", 11, "bold"),
            fg_color=ACCENT_GOLD, hover_color="#ca8a04", text_color="#1c1917", height=38, command=lambda: webbrowser.open("https://cafecito.app/cristian_dev")
        )
        btn_cafecito.pack(fill="x", padx=25, pady=5)
        
        btn_github = ctk.CTkButton(
            modal, text="⭐ Ver Proyecto en GitHub", font=("Segoe UI", 11, "bold"),
            fg_color=BG_CARD, hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY, border_width=1, border_color=COLOR_BORDER, height=38, command=lambda: webbrowser.open("https://github.com/CristianNLC/KILLNet")
        )
        btn_github.pack(fill="x", padx=25, pady=5)
        
        btn_close = ctk.CTkButton(modal, text="Cerrar", font=FONT_BODY, fg_color="transparent", hover_color=BG_CARD_HOVER, text_color=TEXT_MUTED, height=28, command=modal.destroy)
        btn_close.pack(pady=(10, 0))

    def open_feedback_modal(self):
        modal = ctk.CTkToplevel(self)
        modal.title("💬 Soporte & Buzón de Dudas - KILLNet")
        modal.configure(fg_color=BG_MAIN)
        modal.transient(self)
        modal.grab_set()
        
        self._center_modal(modal, 480, 510)
        
        lbl_title = ctk.CTkLabel(modal, text="💬 Soporte & Consultas", font=("Segoe UI", 16, "bold"), text_color=ACCENT_CYAN)
        lbl_title.pack(pady=(18, 5))
        
        lbl_desc = ctk.CTkLabel(
            modal, text="Envía tu duda o reporte directamente al equipo mediante la API Web3Forms.\nEl proceso se ejecuta en segundo plano.",
            font=FONT_BODY, justify="center", text_color=TEXT_MUTED
        )
        lbl_desc.pack(padx=20, pady=(0, 12))
        
        lbl_cat = ctk.CTkLabel(modal, text="Categoría:", font=("Segoe UI", 10, "bold"), text_color=TEXT_PRIMARY)
        lbl_cat.pack(anchor="w", padx=30, pady=(0, 2))
        
        option_cat = ctk.CTkOptionMenu(
            modal, values=["Duda / Consulta", "Sugerencia / Feedback", "Reporte de Error", "Otro"],
            fg_color=BG_CARD, button_color=COLOR_BORDER, button_hover_color=BG_CARD_HOVER, text_color=TEXT_PRIMARY, dropdown_fg_color=BG_CARD, dropdown_hover_color=BG_CARD_HOVER, dropdown_text_color=TEXT_PRIMARY
        )
        option_cat.pack(fill="x", padx=30, pady=(0, 10))
        
        lbl_email = ctk.CTkLabel(modal, text="Correo Electrónico (opcional para respuesta):", font=("Segoe UI", 10, "bold"), text_color=TEXT_PRIMARY)
        lbl_email.pack(anchor="w", padx=30, pady=(0, 2))
        
        entry_email = ctk.CTkEntry(modal, placeholder_text="tu_email@ejemplo.com", font=FONT_BODY, fg_color=BG_CARD, text_color=TEXT_PRIMARY, border_color=COLOR_BORDER)
        entry_email.pack(fill="x", padx=30, pady=(0, 10))
        
        lbl_msg = ctk.CTkLabel(modal, text="Mensaje o Consulta:", font=("Segoe UI", 10, "bold"), text_color=TEXT_PRIMARY)
        lbl_msg.pack(anchor="w", padx=30, pady=(0, 2))
        
        txt_msg = ctk.CTkTextbox(modal, font=FONT_BODY, height=110, fg_color=BG_CARD, text_color=TEXT_PRIMARY, corner_radius=6)
        txt_msg.pack(fill="x", padx=30, pady=(0, 15))
        
        btn_send = ctk.CTkButton(
            modal, text="🚀 Enviar Mensaje en Segundo Plano", font=("Segoe UI", 11, "bold"),
            fg_color=ACCENT_CYAN, hover_color=("#0891b2", "#0e7490"), text_color="#ffffff", height=36
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
        modal.title("Manual de Usuario y Guía Forense - KILLNet v3.0")
        modal.geometry("820x600")
        modal.resizable(False, False)
        modal.transient(self)
        modal.grab_set()

        self._center_modal(modal, 820, 600)

        head_frame = ctk.CTkFrame(modal, fg_color="transparent")
        head_frame.pack(fill="x", padx=24, pady=(20, 10))
        ctk.CTkLabel(
            head_frame, text="📖 Manual de Usuario y Defensa Perimetral",
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"), text_color=ACCENT_CYAN
        ).pack(anchor="w")

        tabs = ctk.CTkTabview(modal, width=770, height=450, corner_radius=10)
        tabs.pack(padx=24, pady=(0, 10), fill="both", expand=True)

        tab_fing = tabs.add("Red Fing")
        tab_sentinel = tabs.add("Centinela IDS")
        tab_auditor = tabs.add("Auditoría Host")
        tab_sockets = tabs.add("Sockets & Red")
        tab_access = tabs.add("Filtro & Whitelist")
        tab_restrictions = tabs.add("Bloqueos & DNS")
        tab_panic = tabs.add("Modo Pánico")

        def _add_section(parent, title, content_list):
            scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
            scroll.pack(fill="both", expand=True, padx=10, pady=10)
            
            lbl_t = ctk.CTkLabel(
                scroll, text=title, font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
                text_color=TEXT_PRIMARY, anchor="w"
            )
            lbl_t.pack(fill="x", pady=(0, 10))

            for item_title, desc in content_list:
                card = ctk.CTkFrame(scroll, corner_radius=8, fg_color=BG_CARD)
                card.pack(fill="x", pady=5, padx=2)
                
                ctk.CTkLabel(
                    card, text=item_title, font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                    text_color=ACCENT_CYAN, anchor="w"
                ).pack(fill="x", padx=14, pady=(10, 4))
                
                ctk.CTkLabel(
                    card, text=desc, font=ctk.CTkFont(family="Segoe UI", size=12),
                    text_color=TEXT_MUTED, justify="left", wraplength=700, anchor="w"
                ).pack(fill="x", padx=14, pady=(0, 10))

        _add_section(tab_fing, "Escáner Visual de Red Estilo Fing", [
            ("📡 Tarjetas de Dispositivos Interactivos:", "Muestra cada dispositivo detectado con su icono temático, fabricante reconocido, IP, MAC y badges de estado en vivo."),
            ("✏️ Alias Personalizables:", "Permite asignar nombres amigables a cualquier equipo (ej: 'Router Principal', 'iPhone de Julian') que se conservan de forma persistente."),
            ("🛡️ Acciones Rápidas Directas:", "Audita puertos de cualquier dispositivo con un clic o aplícale aislamiento inmediato en el firewall local.")
        ])

        _add_section(tab_sentinel, "IDS Defensivo & Centinela Wi-Fi", [
            ("🛡️ Escudo Anti-ARP Spoofing:", "Monitorea continuamente la tabla ARP de Windows para prevenir ataques Man-in-the-Middle y suplantación del gateway."),
            ("📡 Auditoría Evil Twin / Rogue AP:", "Inspecciona el espectro inalámbrico buscando redes clonadas o puntos de acceso falsos."),
            ("🔒 Hardening de Puertos Router:", "Audita servicios críticos expuestos en el router (Telnet, UPnP, FTP, HTTP) señalando riesgos.")
        ])

        _add_section(tab_auditor, "Auditoría de Servicios & Hardening de Host", [
            ("🔍 Diagnóstico de Exposición:", "Escanea puertos TCP en hosts específicos capturando banners y detectando protocolos en texto plano."),
            ("🚫 Aislamiento Local:", "Aísla hosts sospechosos bloqueando todo su tráfico entrante y saliente mediante reglas nativas en Windows Firewall.")
        ])

        _add_section(tab_sockets, "Inspección de Sockets Forenses", [
            ("📡 Mapeo en Vivo:", "Inspecciona conexiones inet asociando puertos, PIDs y ejecutables en disco con resolución GeoIP/ISP."),
            ("🔍 Filtrado Dinámico:", "Filtra en tiempo real por PID, nombre de binario o IP de destino.")
        ])

        _add_section(tab_access, "Sistema de Control de Acceso (Blacklist / Whitelist)", [
            ("🛡️ Reglas Persistentes:", "Almacena políticas locales y aplica bloqueos de entrada/salida en el Firewall de Windows con netsh."),
            ("⚡ Alternancia de Política:", "Conmuta entre modo Blacklist (permitir todo salvo lista negra) y Whitelist (bloquear todo salvo autorizados).")
        ])

        _add_section(tab_restrictions, "Diagnóstico y Bypass de Restricciones", [
            ("🌐 Comprobación de Servicios:", "Evalúa conectividad a servicios clave diferenciando bloqueos DNS de Firewall."),
            ("🔓 Desbloqueo Automático:", "Aplica DNS seguros (Cloudflare 1.1.1.1) y limpia redirecciones espurias en el archivo hosts.")
        ])

        _add_section(tab_panic, "Aislamiento Forense de Emergencia", [
            ("🚨 Modo Pánico:", "Bloquea inmediatamente todo el tráfico saliente ante sospecha de intrusión o malware."),
            ("📄 Auditoría Forense:", "Exporta volcados completos de sockets en formato CSV o JSON.")
        ])

        btn_close = ctk.CTkButton(modal, text="Entendido", width=120, height=34, command=modal.destroy)
        btn_close.pack(pady=(0, 16))

    open_manual_modal = open_user_manual
