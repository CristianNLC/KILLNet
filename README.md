# 🌐 KILLNet v1.0 — Network Forensics & Sockets Telemetry Suite

**KILLNet** es una suite de telemetría de red local y auditoría forense para sistemas operativos Windows, desarrollada con Python y CustomTkinter. Proporciona visibilidad en tiempo real sobre sockets activos, mapeo directo a binarios ejecutables, geolocalización CTI y aislamiento ante incidentes.

---

## 🚀 Capacidades Principales

- **Inspección de Sockets en Vivo:** Mapeo de conexiones TCP y UDP activas asociando IP local/remota, puertos, estado y PID con su respectivo ejecutable (.exe) y ruta absoluta en disco.
- **Inteligencia CTI & GeoIP:** Resolución automática de IPs públicas/WAN (País, Ciudad, ISP) omitiendo rangos de red privada o loopback.
- **Filtros Forenses & Búsqueda Dinámica:** Filtrado en tiempo real por nombre de proceso, PID o dirección IP, con selectores rápidos por estado (*Conectadas / ESTABLISHED*, *A la escucha / LISTEN*).
- **Respuesta a Incidentes (Kill Switch):** Finalización inmediata de procesos anómalos o maliciosos vinculados a sockets sospechosos.
- **Bloqueo Perimetral:** Creación automatizada de reglas de bloqueo saliente en el Firewall nativo de Windows (*netsh advfirewall*).
- **Modo Pánico (Aislamiento de Red):** Bloqueo de emergencia de todo el tráfico de red no esencial ante exfiltración de datos o actividad de ransomware.
- **Exportación de Evidencia:** Volcado forense de la matriz de sockets a formatos estándar (CSV/JSON).

---

## 🛠️ Instalación y Uso

### Instalador Oficial
Descarga el instalador compilado desde el apartado de **Releases** (KILLNet_Setup.exe) e instálalo con privilegios de administrador.

### Ejecución desde Código Fuente
`ash
git clone [https://github.com/CristianNLC/KILLNet.git](https://github.com/CristianNLC/KILLNet.git)
cd KILLNet
pip install -r requirements.txt
python app.pyw
`
