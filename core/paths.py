"""Resolución centralizada de rutas para KILLNet.

Separa dos tipos de rutas:

- ``resource_path()``: recursos empaquetados de sólo lectura (assets, ui, etc.).
  En un binario onefile de PyInstaller viven en la carpeta temporal ``_MEIPASS``.
- ``data_path()``: datos escribibles y persistentes (config, inventario de
  dispositivos, reglas de acceso, alias). NUNCA se escriben dentro de la
  carpeta de instalación ni en ``_MEIPASS``: en el ejecutable se usa
  ``%APPDATA%\\KILLNet\\data`` para sobrevivir a reinicios y actualizaciones
  y para no requerir privilegios de administrador al guardar.
"""

import os
import sys

APP_NAME = "KILLNet"


def is_frozen() -> bool:
    """True cuando se ejecuta como binario empaquetado (PyInstaller)."""
    return bool(getattr(sys, "frozen", False))


def project_root() -> str:
    """Raíz del proyecto en desarrollo o carpeta de recursos en el binario."""
    if is_frozen():
        return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.executable)))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resource_path(*parts: str) -> str:
    """Ruta a un recurso empaquetado de sólo lectura."""
    return os.path.join(project_root(), *parts)


def data_dir() -> str:
    """Devuelve (y crea si hace falta) el directorio de datos escribibles."""
    if is_frozen():
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        path = os.path.join(base, APP_NAME, "data")
    else:
        path = os.path.join(project_root(), "data")
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass
    return path


def data_path(*parts: str) -> str:
    """Ruta a un archivo de datos escribible y persistente."""
    return os.path.join(data_dir(), *parts)
