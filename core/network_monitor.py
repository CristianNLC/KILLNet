import ipaddress
import socket
import psutil

def is_private_ip(ip_str: str) -> bool:
    """
    Determina si una dirección IP dada pertenece a rangos privados, de loopback o de enlace local.
    """
    if not ip_str or ip_str == "-" or ip_str == "*":
        return True
    
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        )
    except ValueError:
        # En caso de hostname o formato no reconocido, tratar con precaución
        return True

def get_active_connections() -> list[dict]:
    """
    Inspecciona todos los sockets inet activos en el sistema y correlaciona
    información del proceso asociado (PID, nombre de ejecutable, ruta completa en disco).
    """
    connections = []
    
    try:
        net_conns = psutil.net_connections(kind='inet')
    except Exception as e:
        # En caso de fallas de permisos globales en psutil
        net_conns = []

    for conn in net_conns:
        # Protocolo
        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP" if conn.type == socket.SOCK_DGRAM else f"PROTO_{conn.type}"
        
        # Dirección Local
        local_ip = conn.laddr.ip if conn.laddr else "-"
        local_port = conn.laddr.port if conn.laddr else "-"
        local_addr_str = f"{local_ip}:{local_port}" if local_ip != "-" else "-"
        
        # Dirección Remota
        remote_ip = conn.raddr.ip if conn.raddr else "-"
        remote_port = conn.raddr.port if conn.raddr else "-"
        remote_addr_str = f"{remote_ip}:{remote_port}" if remote_ip != "-" else "-"
        
        status = conn.status if conn.status else ("LISTEN" if remote_ip == "-" else "NONE")
        pid = conn.pid
        
        proc_name = "N/A"
        proc_path = "N/A"
        
        if pid and pid > 0:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                try:
                    proc_path = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    proc_path = "Acceso Denegado"
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                proc_name = "Proceso Terminado / Sistema"
                proc_path = "N/A"
        elif pid == 0:
            proc_name = "System Idle Process"
            proc_path = "kernel"

        is_priv = is_private_ip(remote_ip)
        
        connections.append({
            "pid": pid if pid is not None else 0,
            "process_name": proc_name,
            "process_path": proc_path,
            "protocol": proto,
            "local_address": local_addr_str,
            "local_ip": local_ip,
            "local_port": str(local_port),
            "remote_address": remote_addr_str,
            "remote_ip": remote_ip,
            "remote_port": str(remote_port),
            "status": status,
            "is_private": is_priv
        })
        
    return connections
