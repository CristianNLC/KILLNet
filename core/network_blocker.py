import subprocess
import ctypes
import psutil

def is_admin() -> bool:
    """Verifica si el proceso actual se ejecuta con privilegios de Administrador en Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def kill_process_by_pid(pid: int) -> tuple[bool, str]:
    """
    Termina forzosamente un proceso por su PID utilizando psutil.
    """
    if pid <= 0:
        return False, "PID inválido o de sistema no terminable (PID <= 0)."
        
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        proc.kill()
        return True, f"Proceso '{proc_name}' (PID: {pid}) terminado exitosamente."
    except psutil.NoSuchProcess:
        return False, f"El proceso con PID {pid} ya no existe."
    except psutil.AccessDenied:
        return False, f"Acceso denegado al intentar terminar el PID {pid}. Ejecute como Administrador."
    except Exception as e:
        return False, f"Error al terminar el proceso {pid}: {str(e)}"

def block_remote_ip(ip_address: str) -> tuple[bool, str]:
    """
    Añade una regla de bloqueo de salida en el Firewall de Windows para una IP específica.
    """
    if not ip_address or ip_address in ("-", "*", "127.0.0.1", "0.0.0.0"):
        return False, "No se puede bloquear una IP local, nula o de loopback."
        
    rule_name = f"KILLNet_Block_{ip_address.replace(':', '_')}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=out",
        "action=block",
        f"remoteip={ip_address}"
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True,
            check=False
        )
        if result.returncode == 0:
            return True, f"Regla de firewall creada: Salida a {ip_address} bloqueada."
        else:
            err_msg = result.stderr.strip() or result.stdout.strip()
            if "se requieren privilegios" in err_msg.lower() or "requires elevation" in err_msg.lower() or result.returncode != 0:
                return False, f"Fallo al agregar regla netsh (¿Faltan privilegios de Administrador?): {err_msg}"
            return False, f"Error netsh ({result.returncode}): {err_msg}"
    except Exception as e:
        return False, f"Excepción al ejecutar comando de firewall: {str(e)}"

def unblock_remote_ip(ip_address: str) -> tuple[bool, str]:
    """
    Elimina la regla de bloqueo en el Firewall de Windows para la IP especificada.
    """
    rule_name = f"KILLNet_Block_{ip_address.replace(':', '_')}"
    cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True, check=False)
        if result.returncode == 0:
            return True, f"Regla de firewall eliminada para {ip_address}."
        else:
            return False, f"Error al eliminar regla de firewall: {result.stderr.strip() or result.stdout.strip()}"
    except Exception as e:
        return False, f"Excepción al desbloquear IP: {str(e)}"

def toggle_panic_mode(block: bool = True) -> tuple[bool, str]:
    """
    Modo Pánico / Bloqueo Total (Aislamiento Forense):
    Añade o remueve una regla temporal de Windows Firewall bloqueando tráfico saliente
    ante sospecha de exfiltración masiva de datos.
    """
    rule_name = "KILLNet_Panic_Mode"
    if block:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, check=False)
            if result.returncode == 0:
                return True, "🚨 MODO PÁNICO ACTIVADO: Tráfico saliente bloqueado en Windows Firewall."
            else:
                err_msg = result.stderr.strip() or result.stdout.strip()
                return False, f"Fallo al activar Modo Pánico: {err_msg}"
        except Exception as e:
            return False, f"Excepción en Modo Pánico: {str(e)}"
    else:
        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, check=False)
            if result.returncode == 0:
                return True, "✅ MODO PÁNICO DESACTIVADO: Regla de bloqueo total removida."
            else:
                err_msg = result.stderr.strip() or result.stdout.strip()
                return False, f"Fallo al desactivar Modo Pánico: {err_msg}"
        except Exception as e:
            return False, f"Excepción al remover Modo Pánico: {str(e)}"

