import os
import sys
import datetime
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

IS_WINDOWS = sys.platform.startswith("win")
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 40
RISK_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


def _risk_color(risk_level: str) -> tuple:
    """Retorna el color RGB asociado a un nivel de riesgo para el informe PDF."""
    level = str(risk_level or "LOW").upper()
    if level == "CRITICAL" or level == "HIGH":
        return (0.93, 0.27, 0.27)   # Rojo
    if level == "MEDIUM":
        return (0.92, 0.71, 0.09)   # Dorado
    return (0.07, 0.72, 0.44)       # Verde


def export_audit_to_pdf(connections: list, path: str) -> tuple[bool, str]:
    """
    Genera un informe forense en PDF (A4) con la matriz de sockets capturada.
    Incluye título, resumen de riesgos y tabla de conexiones detectadas.
    Retorna (True, mensaje) o (False, mensaje de error).
    """
    if not connections:
        return False, "No hay conexiones capturadas para generar el informe PDF."
        
    try:
        c = canvas.Canvas(path, pagesize=A4)
        y = PAGE_HEIGHT - MARGIN
        
        # ---- Título ----
        c.setFont("Helvetica-Bold", 16)
        c.drawString(MARGIN, y, "KILLNet - Informe Forense de Red")
        c.setFont("Helvetica", 9)
        c.drawString(MARGIN, y - 14, f"Generado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        y -= 30
        
        # ---- Resumen de riesgos ----
        risky = [c2 for c2 in connections if str(c2.get("risk_level") or "LOW").upper() in ("HIGH", "CRITICAL")]
        c.setFont("Helvetica-Bold", 11)
        c.drawString(MARGIN, y, f"Resumen: {len(connections)} conexiones analizadas | {len(risky)} con riesgo ALTO/CRÍTICO")
        y -= 18
        
        # ---- Encabezado de tabla ----
        headers = ["PID", "Proceso", "Proto", "IP Remota", "Puerto", "Estado", "Riesgo", "País/ISP"]
        col_widths = [30, 90, 28, 80, 35, 75, 70, 77]
        col_x = [MARGIN]
        for w in col_widths[:-1]:
            col_x.append(col_x[-1] + w + 6)
        col_x.append(col_x[-1] + col_widths[-1] + 6)
        
        c.setFillColorRGB(0.12, 0.16, 0.24)   # Fondo cabecera
        c.rect(MARGIN, y - 12, PAGE_WIDTH - 2 * MARGIN, 16, fill=1, stroke=0)
        c.setFillColorRGB(0.05, 0.75, 0.9)
        c.setFont("Helvetica-Bold", 8)
        cx = MARGIN + 3
        for i, h in enumerate(headers):
            c.drawString(cx, y - 11, h)
            cx += col_widths[i] + 6
        y -= 24
        
        # ---- Filas de conexión ----
        c.setFont("Helvetica", 8)
        for conn in connections:
            level = str(conn.get("risk_level") or "LOW").upper()
            if y < MARGIN + 40:
                c.showPage()
                y = PAGE_HEIGHT - MARGIN
            
            row_h = 12
            text_color = _risk_color(level)
            c.setFillColorRGB(*text_color)
            cx = MARGIN + 3
            values = [
                str(conn.get("pid") or 0),
                str(conn.get("process_name") or "N/A")[:20],
                str(conn.get("protocol") or "-"),
                str(conn.get("remote_ip") or "-"),
                str(conn.get("remote_port") or "-"),
                str(conn.get("status") or "-"),
                level,
                str(conn.get("geo_isp") or "-")[:15],
            ]
            for i, v in enumerate(values):
                c.drawString(cx, y - 10, v)
                cx += col_widths[i] + 6
            y -= row_h + 2
        
        c.setFillColorRGB(0.9, 0.9, 0.9)
        c.save()
        return True, f"Informe PDF generado con {len(connections)} conexiones."
    except Exception as e:
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
        return False, f"Error al generar el PDF: {str(e)}"


def get_forensic_summary(connections: list) -> dict:
    """
    Genera un resumen ejecutivo del reporte: conteos por nivel de riesgo.
    """
    summary = {
        "total": len(connections) if connections else 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    for conn in connections or []:
        level = str(conn.get("risk_level") or "LOW").upper().lower()
        if level in summary:
            summary[level] += 1
    return summary
