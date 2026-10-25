import os
import sys
import threading
from PIL import Image, ImageDraw

try:
    import pystray
except ImportError:
    pystray = None

try:
    from plyer import notification
except ImportError:
    notification = None

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS_DIR = os.path.join(BASE_DIR, "assets")

def _send_toast(title: str, message: str, app_name: str = "KILLNet v3.1.0"):
    """Función en segundo plano para emitir notificaciones nativas de Windows de forma segura."""
    def _worker():
        if not notification:
            return
        try:
            ico_path = os.path.join(ASSETS_DIR, "icon.ico")
            kwargs = {
                "title": title,
                "message": message,
                "app_name": app_name,
                "timeout": 5
            }
            if os.path.exists(ico_path):
                kwargs["app_icon"] = ico_path
            notification.notify(**kwargs)
        except Exception:
            pass

    threading.Thread(target=_worker, daemon=True).start()

def notify_new_device(ip: str, mac: str, vendor: str):
    """Dispara un toast nativo al detectarse un nuevo host en la red."""
    vendor_clean = vendor if vendor and vendor != "Desconocido" else "Dispositivo"
    title = "🛡️ KILLNet — Nuevo Dispositivo Detectado"
    message = f"Se ha conectado {ip} ({vendor_clean}) [{mac}]"
    _send_toast(title, message)

def notify_mitm_alert(gateway_ip: str, spoofed_mac: str):
    """Dispara un toast crítico de alerta IDS por posible suplantación ARP / MitM."""
    title = "🚨 KILLNet — Alerta Crítica IDS"
    message = f"¡Ataque MitM / ARP Spoofing detectado en el router {gateway_ip}! MAC atacante: {spoofed_mac}"
    _send_toast(title, message)

def notify_tray_minimized():
    """Notificación discreta al minimizar la aplicación a la bandeja del sistema."""
    title = "KILLNet v3.1.0 — Modo Centinela"
    message = "KILLNet continúa vigilando la red en segundo plano desde la bandeja del sistema."
    _send_toast(title, message)

def notify_generic(title: str, message: str):
    """Notificación toast genérica."""
    _send_toast(title, message)

class TraySentinelManager:
    """
    Gestor de la bandeja del sistema (System Tray) mediante pystray.
    Mantiene el icono con menú contextual y soporte para restaurar la ventana o salir.
    """
    def __init__(self):
        self.tray_icon = None
        self.is_running = False
        self._thread = None
        self._show_callback = None
        self._exit_callback = None

    def _create_fallback_image(self):
        """Genera un icono circular de respaldo en memoria si no se encuentra el archivo."""
        img = Image.new("RGBA", (64, 64), color=(0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.ellipse((4, 4, 60, 60), fill="#06b6d4", outline="#0891b2", width=3)
        draw.rectangle((26, 18, 38, 46), fill="#ffffff")
        return img

    def _load_tray_image(self):
        """Carga el icono oficial de KILLNet desde assets."""
        for filename in ("icon.png", "icon.ico"):
            path = os.path.join(ASSETS_DIR, filename)
            if os.path.exists(path):
                try:
                    return Image.open(path)
                except Exception:
                    pass
        return self._create_fallback_image()

    def setup_tray(self, show_window_callback, exit_app_callback):
        """
        Configura el icono del tray y sus opciones de menú.
        show_window_callback: función para restaurar la ventana de KILLNet.
        exit_app_callback: función para cerrar completamente la aplicación.
        """
        if not pystray:
            return

        self._show_callback = show_window_callback
        self._exit_callback = exit_app_callback

        def _on_open_clicked(icon, item):
            if self._show_callback:
                self._show_callback()

        def _on_exit_clicked(icon, item):
            self.stop_tray()
            if self._exit_callback:
                self._exit_callback()

        menu = pystray.Menu(
            pystray.MenuItem("Abrir KILLNet v3.1.0", _on_open_clicked, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Cerrar completamente", _on_exit_clicked)
        )

        image = self._load_tray_image()
        self.tray_icon = pystray.Icon(
            name="KILLNet",
            icon=image,
            title="KILLNet v3.1.0 — Centinela & Auditoría",
            menu=menu
        )

    def show_icon(self):
        """Inicia el icono en un hilo daemon para no bloquear la interfaz gráfica Tkinter."""
        if not self.tray_icon or self.is_running:
            return

        def _run():
            self.is_running = True
            try:
                self.tray_icon.run()
            except Exception as e:
                print(f"[TRAY] Error ejecutando icono de bandeja: {e}")
            finally:
                self.is_running = False

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()

    def stop_tray(self):
        """Detiene y remueve el icono de la bandeja del sistema."""
        if self.tray_icon and self.is_running:
            try:
                self.tray_icon.stop()
            except Exception:
                pass
            self.is_running = False
