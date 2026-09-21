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

from core.network_monitor import get_active_connections
from core.ip_reputation import lookup_ip
from core.network_blocker import is_admin, kill_process_by_pid, block_remote_ip, toggle_panic_mode
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
        "version": "1.0.0",
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
        
        # Configuración de ventana centrándola en 1100x720
        self.title("KILLNet - Suite Forense y Telemetría de Red Local")
        self.geometry("1100x720")
        self.minsize(1020, 640)
        self.configure(fg_color=COLOR_BG)
        self._center_window(1100, 720)
        
        # Estado interno
        self.is_admin_user = is_admin()
        self.is_auto_monitoring = False
        self.is_emergency_isolated = False
        self.auto_monitor_thread = None
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.current_connections = []
        self.active_status_filter = "ALL"  # "ALL", "ESTABLISHED", "LISTEN"
        self.search_query = ""
        self.is_console_collapsed = False
        
        # Resolver modo efectivo
        effective_mode = ctk.get_appearance_mode()
        
        # Configurar estilos de Treeview para Tkinter adaptados al tema
        configure_treeview_style(effective_mode)
        
        # Construcción de la interfaz
        self._build_layout(saved_theme)
        self._update_treeview_tags(effective_mode)
        
        # Mensaje de bienvenida e inspección de privilegios
        self.log_message(f"=== KILLNet Suite Inicializada [{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ===")
        self.log_message(f"[CONFIG] Tema cargado desde config.json: '{saved_theme}' (Efectivo: '{effective_mode}').", "INFO")
        if self.is_admin_user:
            self.log_message("[ENTORNO] Ejecutándose con privilegios de Administrador. Control de Firewall y Kill habilitados.", "SUCCESS")
        else:
            self.log_message("[ADVERTENCIA] Ejecutándose SIN privilegios de Administrador. netsh firewall requerirá elevación.", "WARNING")
            
        # Escaneo inicial automático
        self.start_scan_async()

    def _center_window(self, width: int = 1100, height: int = 720):
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
        # Grid principal: Sidebar a la izquierda, área central a la derecha
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # -------------------------------------------------------------
        # 1. SIDEBAR LATERAL IZQUIERDO
        # -------------------------------------------------------------
        self.sidebar = ctk.CTkFrame(self, width=230, corner_radius=0, fg_color=COLOR_SIDEBAR)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(13, weight=1)  # Espaciador inferior flexible
        
        # Header Sidebar
        self.lbl_title = ctk.CTkLabel(
            self.sidebar,
            text="⚡ KILLNet",
            font=("Segoe UI", 22, "bold"),
            text_color=COLOR_CYAN
        )
        self.lbl_title.grid(row=0, column=0, padx=20, pady=(18, 0), sticky="w")
        
        self.lbl_subtitle = ctk.CTkLabel(
            self.sidebar,
            text="Network Forensics v1.0",
            font=("Segoe UI", 10),
            text_color=COLOR_TEXT_MUTED
        )
        self.lbl_subtitle.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")
        
        # Badge de privilegios Admin
        admin_text = "🛡️ Modo Admin (Elevado)" if self.is_admin_user else "⚠️ Modo Usuario (Limitado)"
        admin_color = COLOR_SUCCESS if self.is_admin_user else COLOR_WARNING
        self.lbl_admin_badge = ctk.CTkLabel(
            self.sidebar,
            text=admin_text,
            font=("Segoe UI", 9, "bold"),
            text_color=admin_color,
            fg_color=COLOR_CARD,
            corner_radius=6,
            height=24
        )
        self.lbl_admin_badge.grid(row=2, column=0, padx=15, pady=(0, 12), sticky="ew")
        
        # Separador superior
        sep1 = ctk.CTkFrame(self.sidebar, height=2, fg_color=COLOR_BORDER)
        sep1.grid(row=3, column=0, padx=15, pady=(0, 10), sticky="ew")
        
        # Acciones Principales de Red
        self.btn_scan = ctk.CTkButton(
            self.sidebar,
            text="🔍 Escanear Red Ahora",
            font=("Segoe UI", 11, "bold"),
            fg_color=COLOR_CARD,
            hover_color=COLOR_HOVER,
            text_color=COLOR_ACCENT,
            anchor="w",
            command=self.start_scan_async
        )
        self.btn_scan.grid(row=4, column=0, padx=15, pady=4, sticky="ew")
        
        self.btn_auto_monitor = ctk.CTkButton(
            self.sidebar,
            text="📡 Monitoreo En Vivo [OFF]",
            font=("Segoe UI", 11, "bold"),
            fg_color=COLOR_CARD,
            hover_color=COLOR_HOVER,
            text_color=COLOR_TEXT_MAIN,
            anchor="w",
            command=self.toggle_auto_monitor
        )
        self.btn_auto_monitor.grid(row=5, column=0, padx=15, pady=4, sticky="ew")
        
        self.btn_block_ip = ctk.CTkButton(
            self.sidebar,
            text="🚫 Bloquear IP Seleccionada",
            font=("Segoe UI", 11, "bold"),
            fg_color=COLOR_CARD,
            hover_color=COLOR_HOVER,
            text_color=COLOR_WARNING,
            anchor="w",
            command=self.on_block_ip_clicked
        )
        self.btn_block_ip.grid(row=6, column=0, padx=15, pady=4, sticky="ew")
        
        self.btn_kill_proc = ctk.CTkButton(
            self.sidebar,
            text="💀 Terminar Proceso (Kill)",
            font=("Segoe UI", 11, "bold"),
            fg_color=COLOR_CARD,
            hover_color=COLOR_HOVER,
            text_color=COLOR_DANGER,
            anchor="w",
            command=self.on_kill_proc_clicked
        )
        self.btn_kill_proc.grid(row=7, column=0, padx=15, pady=4, sticky="ew")
        
        self.btn_emergency = ctk.CTkButton(
            self.sidebar,
            text="🚨 Modo Pánico (Aislamiento)",
            font=("Segoe UI", 11, "bold"),
            fg_color=COLOR_DANGER,
            hover_color="#c0392b",
            text_color="#ffffff",
            anchor="w",
            command=self.on_toggle_emergency_isolation
        )
        self.btn_emergency.grid(row=8, column=0, padx=15, pady=(8, 10), sticky="ew")
        
        # Separador intermedio (Componentes Estándar Suite KILL)
        sep2 = ctk.CTkFrame(self.sidebar, height=2, fg_color=COLOR_BORDER)
        sep2.grid(row=9, column=0, padx=15, pady=(0, 10), sticky="ew")
        
        # Botones Estándar Suite KILL
        self.btn_donate = ctk.CTkButton(
            self.sidebar,
            text="☕ Apoyar el Proyecto",
            font=("Segoe UI", 11, "bold"),
            fg_color="#eab308",
            hover_color="#ca8a04",
            text_color="#1c1917",
            anchor="w",
            command=self.open_donation_modal
        )
        self.btn_donate.grid(row=10, column=0, padx=15, pady=4, sticky="ew")
        
        self.btn_feedback = ctk.CTkButton(
            self.sidebar,
            text="💬 Soporte & Dudas",
            font=("Segoe UI", 11, "bold"),
            fg_color=COLOR_CARD,
            hover_color=COLOR_HOVER,
            text_color=COLOR_CYAN,
            anchor="w",
            command=self.open_feedback_modal
        )
        self.btn_feedback.grid(row=11, column=0, padx=15, pady=4, sticky="ew")
        
        self.btn_manual = ctk.CTkButton(
            self.sidebar,
            text="📖 Manual de Usuario",
            font=("Segoe UI", 11, "bold"),
            fg_color=COLOR_CARD,
            hover_color=COLOR_HOVER,
            text_color=COLOR_TEXT_MAIN,
            anchor="w",
            command=self.open_manual_modal
        )
        self.btn_manual.grid(row=12, column=0, padx=15, pady=4, sticky="ew")
        
        # Espaciador en fila 13
        spacer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        spacer.grid(row=13, column=0, sticky="nsew")
        
        # Selector de Tema en la parte inferior de la Sidebar
        self.lbl_theme = ctk.CTkLabel(
            self.sidebar,
            text="🎨 Modo de Tema:",
            font=("Segoe UI", 10, "bold"),
            text_color=COLOR_TEXT_MUTED,
            anchor="w"
        )
        self.lbl_theme.grid(row=14, column=0, padx=15, pady=(10, 2), sticky="w")
        
        self.option_theme = ctk.CTkOptionMenu(
            self.sidebar,
            values=["Dark", "Light", "System"],
            command=self._on_theme_changed,
            fg_color=COLOR_CARD,
            button_color=COLOR_BORDER,
            button_hover_color=COLOR_HOVER,
            text_color=COLOR_TEXT_MAIN,
            dropdown_fg_color=COLOR_CARD,
            dropdown_hover_color=COLOR_HOVER,
            dropdown_text_color=COLOR_TEXT_MAIN
        )
        self.option_theme.set(current_theme)
        self.option_theme.grid(row=15, column=0, padx=15, pady=(0, 15), sticky="ew")

        # -------------------------------------------------------------
        # 2. PANEL CENTRAL PRINCIPAL
        # -------------------------------------------------------------
        self.main_panel = ctk.CTkFrame(self, fg_color=COLOR_BG, corner_radius=0)
        self.main_panel.grid(row=0, column=1, sticky="nsew", padx=15, pady=15)
        self.main_panel.grid_columnconfigure(0, weight=1)
        self.main_panel.grid_rowconfigure(1, weight=1)  # La tabla de conexiones se expande
        
        # ------------------- METRICAS (CARDS TOP) -------------------
        self.cards_frame = ctk.CTkFrame(self.main_panel, fg_color="transparent")
        self.cards_frame.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        for i in range(4):
            self.cards_frame.grid_columnconfigure(i, weight=1)
            
        self.card_total = self._create_metric_card(self.cards_frame, 0, "TOTAL CONEXIONES", "0", COLOR_ACCENT)
        self.card_remote = self._create_metric_card(self.cards_frame, 1, "REMOTAS ACTIVAS", "0", COLOR_CYAN)
        self.card_procs = self._create_metric_card(self.cards_frame, 2, "PROCESOS RED", "0", COLOR_SUCCESS)
        self.card_public = self._create_metric_card(self.cards_frame, 3, "IPs PÚBLICAS / WAN", "0", COLOR_WARNING)
        
        # ------------------- TABLA DE CONEXIONES Y FILTROS -------------------
        self.table_container = ctk.CTkFrame(self.main_panel, fg_color=COLOR_CARD, corner_radius=8)
        self.table_container.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        self.table_container.grid_columnconfigure(0, weight=1)
        self.table_container.grid_rowconfigure(1, weight=1)
        
        # Header de la tabla con busqueda rápida y botones de acción
        table_header = ctk.CTkFrame(self.table_container, fg_color="transparent")
        table_header.grid(row=0, column=0, sticky="ew", padx=12, pady=10)
        table_header.grid_columnconfigure(0, weight=1)
        
        # Sub-contenedor Fila Superior del Header (Título + Botón Exportar + Estado)
        header_top = ctk.CTkFrame(table_header, fg_color="transparent")
        header_top.pack(fill="x", expand=True, pady=(0, 8))
        
        tbl_title = ctk.CTkLabel(
            header_top,
            text="📡 Matriz Forense de Sockets y Procesos",
            font=FONT_SUBTITLE,
            text_color=COLOR_TEXT_MAIN
        )
        tbl_title.pack(side="left")
        
        self.lbl_status = ctk.CTkLabel(
            header_top,
            text="Listo",
            font=FONT_BODY,
            text_color=COLOR_TEXT_MUTED
        )
        self.lbl_status.pack(side="right", padx=(10, 0))
        
        self.btn_export = ctk.CTkButton(
            header_top,
            text="📄 Exportar Auditoría",
            font=("Segoe UI", 10, "bold"),
            fg_color=COLOR_CARD_INNER,
            hover_color=COLOR_HOVER,
            text_color=COLOR_CYAN,
            width=140,
            height=26,
            command=self.on_export_audit_clicked
        )
        self.btn_export.pack(side="right")
        
        # Sub-contenedor Fila Inferior (Barra de Búsqueda y Filtros Rápidos)
        header_controls = ctk.CTkFrame(table_header, fg_color="transparent")
        header_controls.pack(fill="x", expand=True)
        
        # Botones de Filtro Rápido
        self.btn_filter_all = ctk.CTkButton(
            header_controls,
            text="Todas",
            width=75,
            height=28,
            font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_HOVER,
            text_color="#ffffff",
            command=lambda: self._set_status_filter("ALL")
        )
        self.btn_filter_all.pack(side="left", padx=(0, 4))
        
        self.btn_filter_estab = ctk.CTkButton(
            header_controls,
            text="Conectadas",
            width=90,
            height=28,
            font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_CARD_INNER,
            hover_color=COLOR_HOVER,
            text_color=COLOR_TEXT_MAIN,
            command=lambda: self._set_status_filter("ESTABLISHED")
        )
        self.btn_filter_estab.pack(side="left", padx=(0, 4))
        
        self.btn_filter_listen = ctk.CTkButton(
            header_controls,
            text="En Escucha",
            width=90,
            height=28,
            font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_CARD_INNER,
            hover_color=COLOR_HOVER,
            text_color=COLOR_TEXT_MAIN,
            command=lambda: self._set_status_filter("LISTEN")
        )
        self.btn_filter_listen.pack(side="left", padx=(0, 10))
        
        # Entry de Búsqueda Dinámica
        self.entry_search = ctk.CTkEntry(
            header_controls,
            placeholder_text="🔍 Filtrar en vivo por nombre de binario, PID o IP...",
            font=FONT_BODY,
            height=28,
            fg_color=COLOR_CARD_INNER,
            text_color=COLOR_TEXT_MAIN,
            border_color=COLOR_BORDER
        )
        self.entry_search.pack(side="left", fill="x", expand=True)
        self.entry_search.bind("<KeyRelease>", self._on_search_key_release)

        # Treeview Widget
        columns = ("pid", "process", "protocol", "remote_ip", "remote_port", "geo_isp", "status")
        self.tree = ttk.Treeview(
            self.table_container,
            columns=columns,
            show="headings",
            style="Cyber.Treeview",
            selectmode="browse"
        )
        
        # Definición de encabezados y anchos
        self.tree.heading("pid", text="PID", anchor="center")
        self.tree.heading("process", text="Proceso", anchor="w")
        self.tree.heading("protocol", text="Proto", anchor="center")
        self.tree.heading("remote_ip", text="IP Remota", anchor="w")
        self.tree.heading("remote_port", text="Puerto", anchor="center")
        self.tree.heading("geo_isp", text="País / ISP / GeoIP", anchor="w")
        self.tree.heading("status", text="Estado", anchor="center")
        
        self.tree.column("pid", width=70, minwidth=60, anchor="center")
        self.tree.column("process", width=180, minwidth=120, anchor="w")
        self.tree.column("protocol", width=70, minwidth=50, anchor="center")
        self.tree.column("remote_ip", width=140, minwidth=110, anchor="w")
        self.tree.column("remote_port", width=70, minwidth=50, anchor="center")
        self.tree.column("geo_isp", width=260, minwidth=180, anchor="w")
        self.tree.column("status", width=110, minwidth=80, anchor="center")
        
        # Scrollbar vertical
        scrollbar = ttk.Scrollbar(self.table_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=1, column=0, sticky="nsew", padx=(10, 0), pady=(0, 10))
        scrollbar.grid(row=1, column=1, sticky="ns", padx=(0, 10), pady=(0, 10))

        # ------------------- CONSOLA DE AUDITORIA INFERIOR -------------------
        self.console_container = ctk.CTkFrame(self.main_panel, fg_color=COLOR_CARD, corner_radius=8, height=130)
        self.console_container.grid(row=2, column=0, sticky="ew")
        self.console_container.grid_columnconfigure(0, weight=1)
        self.console_container.grid_rowconfigure(1, weight=1)
        
        # Header Consola
        console_bar = ctk.CTkFrame(self.console_container, fg_color="transparent", height=26)
        console_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(4, 0))
        console_bar.grid_columnconfigure(0, weight=1)
        
        lbl_console_title = ctk.CTkLabel(
            console_bar,
            text="💻 Consola de Auditoría y Eventos CTI",
            font=("Segoe UI", 10, "bold"),
            text_color=COLOR_TEXT_MUTED
        )
        lbl_console_title.grid(row=0, column=0, sticky="w")
        
        btn_clear_console = ctk.CTkButton(
            console_bar,
            text="Limpiar Logs",
            width=70,
            height=20,
            font=("Segoe UI", 9),
            fg_color=COLOR_CARD_INNER,
            hover_color=COLOR_HOVER,
            text_color=COLOR_TEXT_MAIN,
            command=self.clear_log_console
        )
        btn_clear_console.grid(row=0, column=1, sticky="e", padx=5)

        self.txt_console = ctk.CTkTextbox(
            self.console_container,
            font=FONT_CONSOLE,
            fg_color=COLOR_CARD_INNER,
            text_color=COLOR_TEXT_MAIN,
            height=90,
            corner_radius=4
        )
        self.txt_console.grid(row=1, column=0, sticky="nsew", padx=10, pady=(4, 8))

    def _create_metric_card(self, parent, col, title, value, accent_color):
        card = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        card.grid(row=0, column=col, padx=4 if col > 0 else (0, 4), sticky="ew")
        
        lbl_val = ctk.CTkLabel(card, text=value, font=FONT_CARD_NUM, text_color=accent_color)
        lbl_val.pack(pady=(10, 0), padx=12)
        
        lbl_title = ctk.CTkLabel(card, text=title, font=FONT_CARD_LABEL, text_color=COLOR_TEXT_MUTED)
        lbl_title.pack(pady=(0, 10), padx=12)
        
        return lbl_val

    def log_message(self, message: str, level: str = "INFO"):
        """Registra un mensaje con marca de tiempo en la consola inferior de auditoría."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        prefix = f"[{timestamp}] [{level}] "
        full_text = f"{prefix}{message}\n"
        
        self.txt_console.configure(state="normal")
        self.txt_console.insert("end", full_text)
        self.txt_console.see("end")
        self.txt_console.configure(state="disabled")

    def clear_log_console(self):
        self.txt_console.configure(state="normal")
        self.txt_console.delete("1.0", "end")
        self.txt_console.configure(state="disabled")

    # -------------------------------------------------------------
    # CAMBIO Y PERSISTENCIA DE TEMA
    # -------------------------------------------------------------
    def _update_treeview_tags(self, effective_mode: str):
        is_light = str(effective_mode).lower() == "light"
        even_bg = "#ffffff" if is_light else "#0f172a"
        odd_bg = "#f1f5f9" if is_light else "#1e293b"
        pub_fg = "#0284c7" if is_light else "#38bdf8"
        blk_fg = "#dc2626" if is_light else "#f85149"
        
        self.tree.tag_configure("even", background=even_bg)
        self.tree.tag_configure("odd", background=odd_bg)
        self.tree.tag_configure("public", foreground=pub_fg)
        self.tree.tag_configure("blocked", foreground=blk_fg)

    def _on_theme_changed(self, new_theme: str):
        ctk.set_appearance_mode(new_theme)
        effective_mode = ctk.get_appearance_mode()
        
        # Re-estilar Treeview para el modo efectivo
        configure_treeview_style(effective_mode)
        self._update_treeview_tags(effective_mode)
        self._apply_table_filters()
        
        self.config["theme"] = new_theme
        save_config(self.config)
        self.log_message(f"[CONFIG] Modo de apariencia cambiado a '{new_theme}' (Efectivo: '{effective_mode}') y guardado.", "INFO")

    # -------------------------------------------------------------
    # ESCANEO ASÍNCRONO DE CONEXIONES Y CTI
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
            
            # Consultar GeoIP para IPs públicas en paralelo
            geo_results = {}
            if public_ips:
                futures = {ip: self.executor.submit(lookup_ip, ip) for ip in public_ips}
                for ip, f in futures.items():
                    try:
                        geo_results[ip] = f.result()
                    except Exception:
                        geo_results[ip] = {"country": "Error", "city": "Error", "isp": "N/A"}
            
            # Formatear datos finales
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
            self.after(0, self.log_message, f"Error durante el escaneo: {str(e)}", "ERROR")
            self.after(0, self._reset_scan_button)

    def _update_ui_with_connections(self, connections):
        self.current_connections = connections
        
        # Calcular estadísticas globales
        total_count = len(connections)
        remote_active_count = sum(1 for c in connections if c["remote_ip"] != "-")
        pids_connected = len(set(c["pid"] for c in connections if c["pid"] > 0))
        public_count = sum(1 for c in connections if not c["is_private"] and c["remote_ip"] != "-")
        
        # Actualizar métricas top
        self.card_total.configure(text=str(total_count))
        self.card_remote.configure(text=str(remote_active_count))
        self.card_procs.configure(text=str(pids_connected))
        self.card_public.configure(text=str(public_count))
        
        self.lbl_status.configure(text=f"Último escaneo: {datetime.datetime.now().strftime('%H:%M:%S')}", text_color=COLOR_SUCCESS)
        self.log_message(f"Escaneo completado. Total: {total_count} sockets, {remote_active_count} remotos, {public_count} IPs públicas.")
        
        # Renderizar tabla aplicando filtros y búsqueda
        self._apply_table_filters()
        self._reset_scan_button()

    def _reset_scan_button(self):
        self.btn_scan.configure(state="normal", text="🔍 Escanear Red Ahora")

    # -------------------------------------------------------------
    # FILTRADO Y BÚSQUEDA EN TIEMPO REAL
    # -------------------------------------------------------------
    def _set_status_filter(self, filter_mode: str):
        self.active_status_filter = filter_mode
        
        # Actualizar aspecto de botones de filtro
        self.btn_filter_all.configure(
            fg_color=COLOR_ACCENT if filter_mode == "ALL" else COLOR_CARD_INNER,
            text_color="#ffffff" if filter_mode == "ALL" else COLOR_TEXT_MAIN
        )
        self.btn_filter_estab.configure(
            fg_color=COLOR_ACCENT if filter_mode == "ESTABLISHED" else COLOR_CARD_INNER,
            text_color="#ffffff" if filter_mode == "ESTABLISHED" else COLOR_TEXT_MAIN
        )
        self.btn_filter_listen.configure(
            fg_color=COLOR_ACCENT if filter_mode == "LISTEN" else COLOR_CARD_INNER,
            text_color="#ffffff" if filter_mode == "LISTEN" else COLOR_TEXT_MAIN
        )
        
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

            # Filtro por estado
            if self.active_status_filter == "ESTABLISHED":
                if status != "ESTABLISHED" and remote_ip == "-":
                    continue
            elif self.active_status_filter == "LISTEN":
                if status != "LISTEN":
                    continue

            # Búsqueda por texto (nombre, PID, IP, puerto, etc.)
            if query:
                pid_str = str(conn.get("pid", ""))
                proc_name = str(conn.get("process_name", "")).lower()
                proc_path = str(conn.get("process_path", "")).lower()
                remote_ip_str = str(conn.get("remote_ip", "")).lower()
                local_addr = str(conn.get("local_address", "")).lower()
                protocol = str(conn.get("protocol", "")).lower()
                geo_str = str(conn.get("geo_str", "")).lower()

                match = (
                    query in pid_str
                    or query in proc_name
                    or query in proc_path
                    or query in remote_ip_str
                    or query in local_addr
                    or query in protocol
                    or query in geo_str
                )
                if not match:
                    continue

            filtered.append(conn)

        for idx, conn in enumerate(filtered):
            pid = conn["pid"]
            proc = conn["process_name"]
            proto = conn["protocol"]
            remote_ip = conn["remote_ip"]
            remote_port = conn["remote_port"]
            geo = conn["geo_str"]
            status = conn["status"]

            tag = "even" if idx % 2 == 0 else "odd"
            if not conn["is_private"] and remote_ip != "-":
                tag = "public"

            self.tree.insert(
                "",
                "end",
                values=(pid, proc, proto, remote_ip, remote_port, geo, status),
                tags=(tag,)
            )

    # -------------------------------------------------------------
    # EXPORTACIÓN FORENSE DE AUDITORÍA
    # -------------------------------------------------------------
    def on_export_audit_clicked(self):
        if not self.current_connections:
            messagebox.showwarning("Sin Datos", "No hay conexiones capturadas para exportar.")
            return

        filepath = filedialog.asksaveasfilename(
            title="Exportar Auditoría Forense de Red",
            defaultextension=".csv",
            filetypes=[
                ("Archivo CSV (*.csv)", "*.csv"),
                ("Archivo JSON (*.json)", "*.json"),
                ("Todos los Archivos (*.*)", "*.*")
            ]
        )
        if not filepath:
            return

        try:
            if filepath.lower().endswith(".json"):
                export_data = {
                    "suite": "KILLNet Network Forensics",
                    "export_timestamp": datetime.datetime.now().isoformat(),
                    "admin_privileges": self.is_admin_user,
                    "emergency_isolated": self.is_emergency_isolated,
                    "total_sockets_captured": len(self.current_connections),
                    "connections": self.current_connections
                }
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
            else:
                with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        "PID", "Proceso", "Ruta_Ejecutable", "Protocolo",
                        "Direccion_Local", "Direccion_Remota", "IP_Remota", "Puerto_Remoto",
                        "Estado", "GeoIP_CTI", "Es_Privada"
                    ])
                    for c in self.current_connections:
                        writer.writerow([
                            c.get("pid", 0),
                            c.get("process_name", ""),
                            c.get("process_path", ""),
                            c.get("protocol", ""),
                            c.get("local_address", ""),
                            c.get("remote_address", ""),
                            c.get("remote_ip", ""),
                            c.get("remote_port", ""),
                            c.get("status", ""),
                            c.get("geo_str", ""),
                            c.get("is_private", True)
                        ])

            filename_only = os.path.basename(filepath)
            self.log_message(f"[AUDITORÍA] Snapshot exportado exitosamente a '{filename_only}'.", "SUCCESS")
            messagebox.showinfo("Exportación Exitosa", f"Se exportó la auditoría forense correctamente en:\n\n{filepath}")
        except Exception as e:
            self.log_message(f"[ERROR] Error al exportar auditoría: {str(e)}", "ERROR")
            messagebox.showerror("Error de Exportación", f"No se pudo guardar el archivo:\n{str(e)}")

    # -------------------------------------------------------------
    # MONITOREO AUTOMÁTICO EN VIVO
    # -------------------------------------------------------------
    def toggle_auto_monitor(self):
        self.is_auto_monitoring = not self.is_auto_monitoring
        if self.is_auto_monitoring:
            self.btn_auto_monitor.configure(
                text="📡 Monitoreo En Vivo [ON]",
                fg_color=COLOR_SUCCESS,
                text_color="#ffffff"
            )
            self.log_message("[MONITOREO] Monitoreo automático en vivo ACTIVADO (Intervalo: 3s).", "SUCCESS")
            self._schedule_auto_scan()
        else:
            self.btn_auto_monitor.configure(
                text="📡 Monitoreo En Vivo [OFF]",
                fg_color=COLOR_CARD,
                text_color=COLOR_TEXT_MAIN
            )
            self.log_message("[MONITOREO] Monitoreo automático DESACTIVADO.")

    def _schedule_auto_scan(self):
        if self.is_auto_monitoring:
            self.start_scan_async()
            self.after(3000, self._schedule_auto_scan)

    # -------------------------------------------------------------
    # ACCIONES: BLOQUEAR IP Y TERMINAR PROCESO
    # -------------------------------------------------------------
    def _get_selected_row(self):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Selección Requerida", "Por favor, seleccione una fila de la tabla para realizar esta acción.")
            return None
        values = self.tree.item(selected_items[0], "values")
        return values

    def on_block_ip_clicked(self):
        row = self._get_selected_row()
        if not row:
            return
            
        pid, proc, proto, remote_ip, remote_port, geo, status = row
        
        if not remote_ip or remote_ip in ("-", "*", "127.0.0.1", "0.0.0.0"):
            messagebox.showerror("IP Inválida", "La conexión seleccionada no posee una IP remota válida para bloquear.")
            return
            
        confirm = messagebox.askyesno(
            "Confirmar Bloqueo de IP",
            f"¿Está seguro de agregar una regla de salida en el Firewall de Windows para la IP:\n\n{remote_ip} ({geo})?"
        )
        if not confirm:
            return
            
        threading.Thread(target=self._block_ip_worker, args=(remote_ip,), daemon=True).start()

    def _block_ip_worker(self, ip_address):
        success, msg = block_remote_ip(ip_address)
        level = "SUCCESS" if success else "ERROR"
        self.after(0, self.log_message, msg, level)
        if success:
            self.after(0, messagebox.showinfo, "Bloqueo Exitoso", msg)
        else:
            self.after(0, messagebox.showerror, "Fallo de Bloqueo", msg)
        self.start_scan_async()

    def on_kill_proc_clicked(self):
        row = self._get_selected_row()
        if not row:
            return
            
        pid_str, proc_name, proto, remote_ip, remote_port, geo, status = row
        try:
            pid = int(pid_str)
        except ValueError:
            messagebox.showerror("PID Inválido", "No se puede obtener el PID del proceso seleccionado.")
            return
            
        if pid <= 0:
            messagebox.showerror("Proceso de Sistema", "No es posible terminar procesos del kernel o PID 0.")
            return
            
        confirm = messagebox.askyesno(
            "Confirmar Terminación Forzosa (KILL)",
            f"⚠️ ¿Está seguro de terminar forzosamente el proceso:\n\nNombre: {proc_name}\nPID: {pid}?"
        )
        if not confirm:
            return
            
        threading.Thread(target=self._kill_proc_worker, args=(pid,), daemon=True).start()

    def _kill_proc_worker(self, pid):
        success, msg = kill_process_by_pid(pid)
        level = "SUCCESS" if success else "ERROR"
        self.after(0, self.log_message, msg, level)
        if success:
            self.after(0, messagebox.showinfo, "Proceso Terminado", msg)
        else:
            self.after(0, messagebox.showerror, "Fallo al Terminar Proceso", msg)
        self.start_scan_async()

    # -------------------------------------------------------------
    # MODO PÁNICO Y AISLAMIENTO DE RED
    # -------------------------------------------------------------
    def on_toggle_emergency_isolation(self):
        if not self.is_emergency_isolated:
            confirm = messagebox.askyesno(
                "🚨 ALERTA: Modo Pánico / Aislamiento Total",
                "⚠️ ¿DESEA ACTIVAR EL MODO PÁNICO Y CORTAR TODO EL TRÁFICO DE RED SALIENTE?\n\n"
                "Se creará una regla global temporaria en Windows Firewall (KILLNet_Panic_Mode) "
                "que bloqueará inmediatamente cualquier intento de exfiltración.",
                icon="warning"
            )
            if not confirm:
                return
            threading.Thread(target=self._isolate_worker, args=(True,), daemon=True).start()
        else:
            confirm = messagebox.askyesno(
                "Restaurar Conectividad",
                "¿Desea desactivar el Modo Pánico y restaurar el tráfico de red?"
            )
            if not confirm:
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
            self.btn_emergency.configure(
                text="🔓 Desactivar Modo Pánico",
                fg_color=COLOR_WARNING,
                hover_color="#b7791f"
            )
        else:
            self.btn_emergency.configure(
                text="🚨 Modo Pánico (Aislamiento)",
                fg_color=COLOR_DANGER,
                hover_color="#c0392b"
            )

    # -------------------------------------------------------------
    # MODAL 1: "☕ Apoyar el Proyecto" (Formato limpio y seguro)
    # -------------------------------------------------------------
    def open_donation_modal(self):
        modal = ctk.CTkToplevel(self)
        modal.title("☕ Apoyar el Proyecto KILLNet")
        modal.configure(fg_color=COLOR_BG)
        modal.transient(self)
        modal.grab_set()
        
        self._center_modal(modal, 460, 340)
        
        lbl_title = ctk.CTkLabel(
            modal,
            text="☕ Apoyar el Proyecto KILLNet",
            font=("Segoe UI", 16, "bold"),
            text_color="#eab308"
        )
        lbl_title.pack(pady=(22, 10))
        
        card_info = ctk.CTkFrame(modal, fg_color=COLOR_CARD, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        card_info.pack(fill="x", padx=25, pady=(0, 15))
        
        lbl_desc = ctk.CTkLabel(
            card_info,
            text="KILLNet es una herramienta forense de red gratuita y de código abierto.\n\n"
                 "Si te ha resultado útil para auditorías de telemetría y seguridad en tu sistema, "
                 "puedes apoyar directamente su desarrollo continuo.",
            font=FONT_BODY,
            justify="center",
            text_color=COLOR_TEXT_MAIN,
            wraplength=380
        )
        lbl_desc.pack(padx=15, pady=15)
        
        # Botón 1: Cafecito
        btn_cafecito = ctk.CTkButton(
            modal,
            text="☕ Donar en Cafecito (Argentina)",
            font=("Segoe UI", 11, "bold"),
            fg_color="#eab308",
            hover_color="#ca8a04",
            text_color="#1c1917",
            height=38,
            command=lambda: webbrowser.open("https://cafecito.app/cristian_dev")
        )
        btn_cafecito.pack(fill="x", padx=25, pady=5)
        
        # Botón 2: GitHub
        btn_github = ctk.CTkButton(
            modal,
            text="⭐ Ver Proyecto en GitHub",
            font=("Segoe UI", 11, "bold"),
            fg_color=COLOR_CARD,
            hover_color=COLOR_HOVER,
            text_color=COLOR_TEXT_MAIN,
            border_width=1,
            border_color=COLOR_BORDER,
            height=38,
            command=lambda: webbrowser.open("https://github.com/CristianNLC/KILLNet")
        )
        btn_github.pack(fill="x", padx=25, pady=5)
        
        # Botón 3: Cerrar
        btn_close = ctk.CTkButton(
            modal,
            text="Cerrar",
            font=FONT_BODY,
            fg_color="transparent",
            hover_color=COLOR_HOVER,
            text_color=COLOR_TEXT_MUTED,
            height=28,
            command=modal.destroy
        )
        btn_close.pack(pady=(10, 0))

    # -------------------------------------------------------------
    # MODAL 2: "💬 Soporte & Dudas" (Web3Forms API POST)
    # -------------------------------------------------------------
    def open_feedback_modal(self):
        modal = ctk.CTkToplevel(self)
        modal.title("💬 Soporte & Buzón de Dudas - KILLNet")
        modal.configure(fg_color=COLOR_BG)
        modal.transient(self)
        modal.grab_set()
        
        self._center_modal(modal, 480, 510)
        
        lbl_title = ctk.CTkLabel(
            modal,
            text="💬 Soporte & Consultas",
            font=("Segoe UI", 16, "bold"),
            text_color=COLOR_CYAN
        )
        lbl_title.pack(pady=(18, 5))
        
        lbl_desc = ctk.CTkLabel(
            modal,
            text="Envía tu duda o reporte directamente al equipo mediante la API Web3Forms.\nEl proceso se ejecuta en segundo plano.",
            font=FONT_BODY,
            justify="center",
            text_color=COLOR_TEXT_MUTED
        )
        lbl_desc.pack(padx=20, pady=(0, 12))
        
        # Categoría
        lbl_cat = ctk.CTkLabel(modal, text="Categoría:", font=("Segoe UI", 10, "bold"), text_color=COLOR_TEXT_MAIN)
        lbl_cat.pack(anchor="w", padx=30, pady=(0, 2))
        
        option_cat = ctk.CTkOptionMenu(
            modal,
            values=["Duda / Consulta", "Sugerencia / Feedback", "Reporte de Error", "Otro"],
            fg_color=COLOR_CARD,
            button_color=COLOR_BORDER,
            button_hover_color=COLOR_HOVER,
            text_color=COLOR_TEXT_MAIN,
            dropdown_fg_color=COLOR_CARD,
            dropdown_hover_color=COLOR_HOVER,
            dropdown_text_color=COLOR_TEXT_MAIN
        )
        option_cat.pack(fill="x", padx=30, pady=(0, 10))
        
        # Correo Opcional
        lbl_email = ctk.CTkLabel(modal, text="Correo Electrónico (opcional para respuesta):", font=("Segoe UI", 10, "bold"), text_color=COLOR_TEXT_MAIN)
        lbl_email.pack(anchor="w", padx=30, pady=(0, 2))
        
        entry_email = ctk.CTkEntry(
            modal,
            placeholder_text="tu_email@ejemplo.com",
            font=FONT_BODY,
            fg_color=COLOR_CARD,
            text_color=COLOR_TEXT_MAIN,
            border_color=COLOR_BORDER
        )
        entry_email.pack(fill="x", padx=30, pady=(0, 10))
        
        # Mensaje
        lbl_msg = ctk.CTkLabel(modal, text="Mensaje o Consulta:", font=("Segoe UI", 10, "bold"), text_color=COLOR_TEXT_MAIN)
        lbl_msg.pack(anchor="w", padx=30, pady=(0, 2))
        
        txt_msg = ctk.CTkTextbox(
            modal,
            font=FONT_BODY,
            height=110,
            fg_color=COLOR_CARD,
            text_color=COLOR_TEXT_MAIN,
            corner_radius=6
        )
        txt_msg.pack(fill="x", padx=30, pady=(0, 15))
        
        btn_send = ctk.CTkButton(
            modal,
            text="🚀 Enviar Mensaje en Segundo Plano",
            font=("Segoe UI", 11, "bold"),
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_HOVER,
            text_color="#ffffff",
            height=36
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
                        self.after(0, self.log_message, f"[FEEDBACK] Mensaje enviado correctamente ({cat}).", "SUCCESS")
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

    # -------------------------------------------------------------
    # MODAL 3: "📖 Manual de Usuario" (Estructurado)
    # -------------------------------------------------------------
    def open_user_manual(self):
        modal = ctk.CTkToplevel(self)
        modal.title("Manual de Usuario y Guía Forense - KILLNet")
        modal.geometry("780x560")
        modal.resizable(False, False)
        modal.transient(self)
        modal.grab_set()

        # Centrar sobre la ventana principal
        modal.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - 390
        y = self.winfo_y() + (self.winfo_height() // 2) - 280
        modal.geometry(f"+{max(0, x)}+{max(0, y)}")

        # Header
        head_frame = ctk.CTkFrame(modal, fg_color="transparent")
        head_frame.pack(fill="x", padx=24, pady=(20, 10))
        ctk.CTkLabel(
            head_frame,
            text="📖 Manual de Usuario y Telemetría Forense",
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"),
            text_color=("#0f172a", "#38bdf8")
        ).pack(anchor="w")

        # Contenedor con Tabs (Pestañas)
        tabs = ctk.CTkTabview(modal, width=730, height=410, corner_radius=10)
        tabs.pack(padx=24, pady=(0, 10), fill="both", expand=True)

        tab_sockets = tabs.add("Sockets & Red")
        tab_cti = tabs.add("GeoIP & CTI")
        tab_kill = tabs.add("Kill Switch & Bloqueo")
        tab_panic = tabs.add("Modo Pánico")

        def _add_section(parent, title, content_list):
            scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
            scroll.pack(fill="both", expand=True, padx=10, pady=10)
            
            lbl_t = ctk.CTkLabel(
                scroll,
                text=title,
                font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
                text_color=("#0f172a", "#f8fafc"),
                anchor="w"
            )
            lbl_t.pack(fill="x", pady=(0, 10))

            for item_title, desc in content_list:
                card = ctk.CTkFrame(scroll, corner_radius=8, fg_color=("#e2e8f0", "#1e293b"))
                card.pack(fill="x", pady=5, padx=2)
                
                ctk.CTkLabel(
                    card,
                    text=item_title,
                    font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                    text_color=("#1e293b", "#38bdf8"),
                    anchor="w"
                ).pack(fill="x", padx=14, pady=(10, 4))
                
                ctk.CTkLabel(
                    card,
                    text=desc,
                    font=ctk.CTkFont(family="Segoe UI", size=12),
                    text_color=("#334155", "#cbd5e1"),
                    justify="left",
                    wraplength=660,
                    anchor="w"
                ).pack(fill="x", padx=14, pady=(0, 10))

        # Tab 1: Sockets
        _add_section(tab_sockets, "Inspección de Sockets y Conexiones Activas", [
            ("📡 Mapeo en Vivo:", "KILLNet inspecciona periódicamente la tabla de conexiones inet (TCP y UDP) mediante psutil, asociando cada puerto al PID y ejecutable responsable en disco."),
            ("🔍 Estados de Conexión:", "ESTABLISHED (transferencia bidireccional de datos), LISTEN (puerto abierto a la espera de peticiones entrantes), CLOSE_WAIT / TIME_WAIT (sockets en proceso de liberación)."),
            ("⚡ Búsqueda Rápida:", "Usa la barra superior de filtrado para encontrar al instante sockets por PID, nombre de proceso (.exe) o dirección IP.")
        ])

        # Tab 2: GeoIP & CTI
        _add_section(tab_cti, "Inteligencia de Amenazas y Geolocalización", [
            ("🌍 Resolución WAN / Pública:", "Las IPs externas que no pertenecen a rangos privados o de loopback (127.0.0.1, 192.168.x.x) se consultan contra el servicio de telemetría para determinar País, Ciudad e ISP."),
            ("🛡️ Detección de C2 (Command & Control):", "Permite identificar si procesos desconocidos mantienen canales de comunicación con servidores remotos o nubes en el extranjero sin tu consentimiento.")
        ])

        # Tab 3: Kill Switch & Bloqueo
        _add_section(tab_kill, "Respuesta y Neutralización de Amenazas", [
            ("💀 Terminar Proceso (Kill Switch):", "Finaliza forzosamente el proceso sospechoso vinculado al socket seleccionado, liberando el puerto y cortando la transmisión."),
            ("🚫 Bloqueo de IP en Firewall:", "Crea una regla de bloqueo saliente en el Firewall de Windows nativo (netsh advfirewall), impidiendo todo tráfico futuro hacia la IP remota seleccionada.")
        ])

        # Tab 4: Modo Pánico
        _add_section(tab_panic, "Aislamiento Forense de Emergencia", [
            ("🚨 Modo Pánico:", "Bloquea de inmediato todo el tráfico saliente no local de la máquina ante una sospecha activa de exfiltración de datos o ransomware."),
            ("📄 Exportar Auditoría:", "Genera un volcado forense completo de las conexiones y procesos activos en formato CSV o JSON para análisis posterior.")
        ])

        # Footer con botón Cerrar
        btn_close = ctk.CTkButton(modal, text="Entendido", width=120, height=34, command=modal.destroy)
        btn_close.pack(pady=(0, 16))

    # Alias de compatibilidad
    open_manual_modal = open_user_manual


