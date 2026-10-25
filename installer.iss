; Script de Inno Setup para KILLNet v3.1
[Setup]
AppId={{C518D1F3-149B-4982-A721-5079E3354DF2}
AppName=KILLNet
AppVersion=3.1
AppVerName=KILLNet v3.1.0
AppPublisher=KILLSecurity Suite
AppPublisherURL=https://github.com/CristianNLC/KILLNet
DefaultDirName={autopf}\KILLNet
DefaultGroupName=KILLNet
UninstallDisplayIcon={app}\assets\icon.ico
VersionInfoVersion=3.1.0.0
OutputDir=dist_installer
OutputBaseFilename=KILLNet_Setup
SetupIconFile=assets\icon.ico
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; Binario principal (onefile generado por PyInstaller)
Source: "dist\KILLNet.exe"; DestDir: "{app}"; Flags: ignoreversion
; Recursos gráficos de sólo lectura (NO se distribuyen datos de usuario)
Source: "assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs
; NOTA: data\config.json, data\known_devices.json, data\access_rules.json y
; data\device_aliases.json NO se empaquetan. Contienen información privada de la
; red del usuario (MACs, IPs, fabricantes). La aplicación los genera por sí sola
; en %APPDATA%\KILLNet\data la primera vez que se ejecuta.

[Icons]
Name: "{group}\KILLNet"; Filename: "{app}\KILLNet.exe"; IconFilename: "{app}\assets\icon.ico"
Name: "{group}\Desinstalar KILLNet"; Filename: "{uninstallexe}"
Name: "{autodesktop}\KILLNet"; Filename: "{app}\KILLNet.exe"; Tasks: desktopicon; IconFilename: "{app}\assets\icon.ico"

[Run]
Filename: "{app}\KILLNet.exe"; Description: "{cm:LaunchProgram,KILLNet}"; Flags: nowait postinstall skipifsilent