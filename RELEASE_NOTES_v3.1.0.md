# 🛡️ KILLNet v3.1.0 — Threat Intelligence, Motor de Riesgo y Autotriage

**Fecha de lanzamiento:** 25 de octubre de 2026
**Tipo:** Actualización mayor de funcionalidades (feature release)

KILLNet pasa de ser un visor de sockets a una **suite de respuesta ante incidentes**: ahora cada conexión y cada dispositivo de la red obtiene una **puntuación de riesgo 0–100**, se contrasta contra **tres fuentes de Threat Intelligence** y, en los casos críticos, la aplicación puede **actuar por sí sola** (matar el proceso y bloquear la IP remota) previa confirmación.

---

## ✨ Novedades principales

### 🎯 Motor de Riesgo (0–100)
- Puntuación de riesgo por conexión y por dispositivo, con cuatro niveles: **BAJO / MEDIO / ALTO / CRÍTICO**.
- El cálculo combina: reputación de la IP, IP pública vs. privada, puerto remoto sospechoso, proceso sin firma/ruta atípica, señales de Threat Intelligence y confirmación de IP maliciosa.
- Una IP confirmada como maliciosa suma **+70 puntos**, garantizando nivel **CRÍTICO** cuando además es pública.
- Nueva columna **Riesgo** en la tabla de sockets, con colores y etiquetas por nivel, y **badge de riesgo** en cada tarjeta de dispositivo.

### 🌐 Threat Intelligence unificada (3 fuentes)
- Nuevo módulo `core/threat_intel.py` que consulta y consolida:
  - **AbuseIPDB** (reputación y reportes de abuso)
  - **VirusTotal** (detecciones de motores antivirus)
  - **AlienVault OTX** (pulsos de amenaza)
- Funcionamiento **degradado y seguro**: si no hay claves API configuradas, la app sigue funcionando sin errores y sin bloquear la interfaz.
- Caché de resultados para reducir consultas y respetar los límites de las APIs.
- Claves opcionales mediante variables de entorno: `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY`.

### ⚡ Autotriage ante conexiones críticas
- Cuando se detecta una conexión **CRÍTICA**, KILLNet solicita confirmación y aplica respuesta automática: **finaliza el proceso** y **bloquea la IP remota** en el Firewall de Windows.
- Interruptor para activar o desactivar el autotriage; la preferencia se guarda en la configuración.

### 📄 Informe forense en PDF
- Nueva exportación a **PDF** (`reportlab`) además de CSV/JSON.
- El informe incluye **resumen ejecutivo por nivel de riesgo**, tabla de conexiones, datos de geolocalización/CTI y marcas de tiempo para cadena de custodia.

### 🛡️ Escudo Anti-ARP con auto-inicio
- El **escudo Anti-ARP** ahora se activa automáticamente al abrir la aplicación (configurable).
- Estado del escudo sincronizado en el panel principal y posibilidad de **desactivarlo manualmente** en cualquier momento.
- Persistencia de la preferencia `auto_start_shield`.

### 🔍 Detalle completo del dispositivo
- **Un clic en cualquier parte de la tarjeta** abre un modal con toda la información recopilada: IP, MAC, fabricante, alias, primer/último avistamiento, riesgo, reglas de acceso y acciones rápidas.
- El modal aparece **siempre en primer plano**, encima de la ventana principal.

### 🧹 Privacidad y seguridad (importante)
- **El instalador ya no incluye datos de tu red.** Antes se empaquetaban `known_devices.json` y `access_rules.json` con MACs, IPs y fabricantes reales.
- Los datos de ejecución se guardan ahora en **`%APPDATA%\KILLNet\data\`** (escribible sin privilegios de administrador y persistente entre actualizaciones).
- `data/*.json` queda **excluido del repositorio** mediante `.gitignore`.
- Nuevo módulo `core/paths.py` que centraliza la resolución de rutas (recursos de sólo lectura vs. datos escribibles), corrigiendo además la pérdida de configuración en binarios *onefile* de PyInstaller.

---

## 🐞 Correcciones

- Corregido `NameError`/`AttributeError` al renderizar tarjetas de dispositivo (bindings de clic).
- Corregido `NameError: FONT_BODY_BOLD` en el modal de detalle.
- Corregido `kill_process_by_pid` para aceptar el nombre del proceso desde la interfaz.
- Corregida la ruta del binario en `installer.iss` (`dist\KILLNet.exe`, build *onefile*).
- Corregida la detección del compilador de Inno Setup y metadatos del instalador (versión, icono de desinstalación).

---

## 📦 Instalación

1. Descarga **`KILLNet_Setup.exe`** desde los *Assets* de esta release.
2. Ejecútalo como administrador (requerido para Firewall y escudo Anti-ARP).
3. Al primer arranque se crean automáticamente los datos en `%APPDATA%\KILLNet\data\`.
4. Para usar Threat Intelligence, define las claves API como variables de entorno antes de abrir la app.

> **Actualización desde v3.0:** el instalador no sobrescribe datos de usuario; la configuración previa en la carpeta de instalación no se migra automáticamente, por lo que la app generará una configuración limpia en `%APPDATA%`.

---

## ✅ Verificación

- Compilación de todos los módulos: **OK**
- Suites de pruebas (`risk_engine`, `threat_intel`, `evidence_exporter`): **en verde**
- BuildPyInstaller (*onefile*) + instalador Inno Setup: **exitosos**
- Instalador verificado: **sin archivos de datos personales**

---

## 🔜 Próximos pasos

- Firma digital del binario (evitar advertencias de SmartScreen).
- Historial de eventos persistente y panel de línea de tiempo.
- Reglas de riesgo personalizables por el usuario.
