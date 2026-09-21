import tkinter as tk
from tkinter import ttk

# Paleta adaptativa CustomTkinter (Modo Claro, Modo Oscuro)
COLOR_BG = ("#f8fafc", "#0f172a")
COLOR_BG_DARK = COLOR_BG  # retrocompatibilidad
COLOR_SIDEBAR = ("#f1f5f9", "#161b22")
COLOR_CARD = ("#ffffff", "#1e293b")
COLOR_CARD_INNER = ("#f1f5f9", "#0f172a")

COLOR_ACCENT = ("#0284c7", "#38bdf8")
COLOR_CYAN = ("#0284c7", "#38bdf8")
COLOR_DANGER = ("#dc2626", "#f85149")
COLOR_SUCCESS = ("#16a34a", "#3fb950")
COLOR_WARNING = ("#d97706", "#d29922")

COLOR_TEXT_PRIMARY = ("#0f172a", "#f8fafc")
COLOR_TEXT_MAIN = ("#0f172a", "#f8fafc")
COLOR_TEXT_MUTED = ("#64748b", "#cbd5e1")
COLOR_BORDER = ("#cbd5e1", "#334155")
COLOR_HOVER = ("#e2e8f0", "#334155")

FONT_TITLE = ("Segoe UI", 18, "bold")
FONT_SUBTITLE = ("Segoe UI", 12, "bold")
FONT_CARD_NUM = ("Segoe UI", 22, "bold")
FONT_CARD_LABEL = ("Segoe UI", 10, "bold")
FONT_BODY = ("Segoe UI", 10)
FONT_MANUAL_HEADER = ("Segoe UI", 14, "bold")
FONT_MANUAL_BODY = ("Segoe UI", 12)
FONT_CONSOLE = ("Consolas", 9)

def configure_treeview_style(appearance_mode="Dark"):
    """
    Configura los estilos de ttk.Treeview para adaptarse armónicamente
    a la paleta (Dark/Light) de CustomTkinter.
    """
    style = ttk.Style()
    style.theme_use("clam")
    
    is_light = str(appearance_mode).lower() == "light"
    
    bg_color = "#ffffff" if is_light else "#0f172a"
    fg_color = "#0f172a" if is_light else "#f8fafc"
    heading_bg = "#f1f5f9" if is_light else "#1e293b"
    heading_fg = "#0284c7" if is_light else "#38bdf8"
    selected_bg = "#e0f2fe" if is_light else "#334155"
    selected_fg = "#0284c7" if is_light else "#38bdf8"

    # Configuración de la tabla
    style.configure(
        "Cyber.Treeview",
        background=bg_color,
        foreground=fg_color,
        fieldbackground=bg_color,
        borderwidth=0,
        font=FONT_BODY,
        rowheight=26
    )
    
    # Configuración del encabezado
    style.configure(
        "Cyber.Treeview.Heading",
        background=heading_bg,
        foreground=heading_fg,
        borderwidth=1,
        relief="flat",
        font=("Segoe UI", 10, "bold")
    )
    
    style.map(
        "Cyber.Treeview.Heading",
        background=[("active", selected_bg)],
        foreground=[("active", selected_fg)]
    )
    
    style.map(
        "Cyber.Treeview",
        background=[("selected", selected_bg)],
        foreground=[("selected", selected_fg)]
    )
