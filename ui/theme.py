import tkinter as tk
from tkinter import ttk

# =====================================================================
# KILLNet v3.0 - PALETA ADAPTATIVA MODERNA ESTILO FING (LIGHT / DARK)
# =====================================================================
BG_MAIN = ("#f1f5f9", "#0b0f19")
BG_CARD = ("#ffffff", "#161f30")
BG_CARD_HOVER = ("#e2e8f0", "#1e293b")
TEXT_PRIMARY = ("#0f172a", "#f8fafc")
TEXT_MUTED = ("#64748b", "#94a3b8")
ACCENT_CYAN = "#06b6d4"
ACCENT_GREEN = "#10b981"
ACCENT_RED = "#ef4444"
ACCENT_GOLD = "#eab308"

# Retrocompatibilidad y alias de interfaz
COLOR_BG = BG_MAIN
COLOR_BG_DARK = BG_MAIN
COLOR_SIDEBAR = ("#f8fafc", "#0f1422")
COLOR_CARD = BG_CARD
COLOR_CARD_INNER = ("#f1f5f9", "#0b0f19")

COLOR_ACCENT = ACCENT_CYAN
COLOR_CYAN = ACCENT_CYAN
COLOR_DANGER = ACCENT_RED
COLOR_SUCCESS = ACCENT_GREEN
COLOR_WARNING = ACCENT_GOLD

COLOR_TEXT_PRIMARY = TEXT_PRIMARY
COLOR_TEXT_MAIN = TEXT_PRIMARY
COLOR_TEXT_MUTED = TEXT_MUTED
COLOR_BORDER = ("#cbd5e1", "#1e293b")
COLOR_HOVER = BG_CARD_HOVER

# Tipografías del Sistema
FONT_TITLE = ("Segoe UI", 18, "bold")
FONT_SUBTITLE = ("Segoe UI", 12, "bold")
FONT_CARD_NUM = ("Segoe UI", 18, "bold")
FONT_CARD_LABEL = ("Segoe UI", 9, "bold")
FONT_BODY = ("Segoe UI", 10)
FONT_BODY_BOLD = ("Segoe UI", 10, "bold")
FONT_BADGE = ("Segoe UI", 8, "bold")
FONT_MANUAL_HEADER = ("Segoe UI", 14, "bold")
FONT_MANUAL_BODY = ("Segoe UI", 12)
FONT_CONSOLE = ("Consolas", 9)

def configure_treeview_style(appearance_mode="Dark"):
    """
    Configura los estilos de ttk.Treeview adaptándose armónicamente
    a la paleta moderna Dark/Light estilo Fing de KILLNet v3.0.
    """
    style = ttk.Style()
    style.theme_use("clam")
    
    is_light = str(appearance_mode).lower() == "light"
    
    bg_color = "#ffffff" if is_light else "#161f30"
    fg_color = "#0f172a" if is_light else "#f8fafc"
    heading_bg = "#f1f5f9" if is_light else "#0b0f19"
    heading_fg = "#06b6d4"
    selected_bg = "#e2e8f0" if is_light else "#1e293b"
    selected_fg = "#06b6d4"

    # Configuración de la tabla
    style.configure(
        "Cyber.Treeview",
        background=bg_color,
        foreground=fg_color,
        fieldbackground=bg_color,
        borderwidth=0,
        font=FONT_BODY,
        rowheight=28
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
