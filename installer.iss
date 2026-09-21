; Script de Inno Setup para KILLNet v1.0
[Setup]
AppId={{C518D1F3-149B-4982-A721-5079E3354DF2}
AppName=KILLNet
AppVersion=1.0
AppPublisher=KILLSecurity Suite
AppPublisherURL=https://github.com/CristianNLC/KILLNet
DefaultDirName={autopf}\KILLNet
DefaultGroupName=KILLNet
OutputDir=dist_installer
OutputBaseFilename=KILLNet_Setup
SetupIconFile=assets\icon.ico
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; Binario compilado principal
Source: "dist\KILLNet.exe"; DestDir: "{app}"; Flags: ignoreversion
; Datos de configuración y recursos gráficos
Source: "data\*"; DestDir: "{app}\data"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\KILLNet"; Filename: "{app}\KILLNet.exe"; IconFilename: "{app}\assets\icon.ico"
Name: "{group}\Desinstalar KILLNet"; Filename: "{uninstallexe}"
Name: "{autodesktop}\KILLNet"; Filename: "{app}\KILLNet.exe"; Tasks: desktopicon; IconFilename: "{app}\assets\icon.ico"

[Run]
Filename: "{app}\KILLNet.exe"; Description: "{cm:LaunchProgram,KILLNet}"; Flags: nowait postinstall skipifsilent