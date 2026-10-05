; Installateur SecureWall Security — Inno Setup 6/7 (https://jrsoftware.org/isinfo.php)
; Génération : installer\build-installer.ps1  (publie les projets puis appelle ISCC.exe)
;
; L'installateur :
;   - installe l'application et le service privilégié dans « Program Files » (dossier modifiable uniquement par les administrateurs) ;
;   - enregistre le service Windows « SecureWallPrivilegedService » (démarrage automatique) ;
;   - ne modifie AUCUN paramètre de sécurité : ni Microsoft Defender, ni le pare-feu, ni exclusion, ni certificat (il n'installe aucun certificat sur votre PC).

#define AppName "SecureWall Security"
#define AppVersion "2.0.1"
#define AppExe "SecureWall.exe"
#define ServiceExe "SecureWall.PrivilegedService.exe"
#define ServiceName "SecureWallPrivilegedService"

[Setup]
AppId={{6C1E2B4A-3F5D-4A8E-9B7C-5D2E8F1A9C30}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=SecureWall Security
DefaultDirName={autopf}\SecureWall
DefaultGroupName=SecureWall Security
DisableProgramGroupPage=yes
OutputDir=..\publish
OutputBaseFilename=SecureWall-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
MinVersion=10.0.19041
UninstallDisplayIcon={app}\{#AppExe}
SetupIconFile=..\src\SecureWall.App\Resources\securewall.ico
WizardStyle=modern
InfoBeforeFile=info-avant-installation.txt
#ifdef Sign
; Signature (Authenticode) de l'installateur ET du désinstalleur : commande « sw » fournie par build-installer.ps1 (/Ssw=…).
SignTool=sw
SignedUninstaller=yes
#endif
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "Créer un raccourci sur le Bureau"; Flags: unchecked
Name: "startup"; Description: "Démarrer SecureWall avec Windows (dans la zone de notification)"; Flags: unchecked

[Files]
; Application + service : publiés (dotnet publish, win-x64, autonome) dans le même dossier.
Source: "..\publish\SecureWall\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\SecureWall Security"; Filename: "{app}\{#AppExe}"
Name: "{group}\Désinstaller SecureWall Security"; Filename: "{uninstallexe}"
Name: "{autodesktop}\SecureWall Security"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
; Démarrage avec Windows : choix explicite de l'utilisateur, visible dans le Gestionnaire des tâches.
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SecureWall"; \
    ValueData: """{app}\{#AppExe}"" --minimized"; Flags: uninsdeletevalue; Tasks: startup

[Run]
; Service privilégié : compte LocalSystem, démarrage automatique, redémarrage en cas d'échec.
Filename: "{sys}\sc.exe"; Parameters: "create {#ServiceName} binPath= ""{app}\{#ServiceExe}"" start= auto DisplayName= ""SecureWall - Service privilégié"""; Flags: runhidden; StatusMsg: "Installation du service privilégié…"
Filename: "{sys}\sc.exe"; Parameters: "description {#ServiceName} ""Exécute uniquement les opérations SecureWall nécessitant des droits administrateur (pare-feu, quarantaine Defender, mode urgence). Liste blanche stricte, tube nommé local authentifié."""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "failure {#ServiceName} reset= 86400 actions= restart/5000/restart/30000//"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "start {#ServiceName}"; Flags: runhidden; StatusMsg: "Démarrage du service privilégié…"
Filename: "{app}\{#AppExe}"; Description: "Lancer SecureWall Security"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; L'application peut tourner dans la zone de notification : on la ferme avant la suppression des fichiers (sinon ils restent verrouillés et sont laissés sur le disque).
Filename: "{sys}\taskkill.exe"; Parameters: "/F /T /IM {#AppExe}"; Flags: runhidden; RunOnceId: "KillApp"
Filename: "{sys}\sc.exe"; Parameters: "stop {#ServiceName}"; Flags: runhidden; RunOnceId: "StopSvc"
Filename: "{sys}\sc.exe"; Parameters: "delete {#ServiceName}"; Flags: runhidden; RunOnceId: "DeleteSvc"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /T /IM {#ServiceExe}"; Flags: runhidden; RunOnceId: "KillSvc"

[UninstallDelete]
; Les journaux du service sont supprimés ; les SAUVEGARDES DU PARE-FEU (C:\ProgramData\SecureWall\FirewallBackups) sont conservées volontairement.
Type: filesandordirs; Name: "{commonappdata}\SecureWall\logs"

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    MsgBox('SecureWall est désinstallé.' + #13#10#13#10 +
           'Vos données personnelles (historique, réglages) restent dans %LocalAppData%\SecureWall et les sauvegardes du pare-feu dans %ProgramData%\SecureWall\FirewallBackups : supprimez-les manuellement si vous le souhaitez.' + #13#10 +
           'Les analyses planifiées éventuelles (Planificateur de tâches, dossier « SecureWall ») sont à supprimer depuis l''application avant la désinstallation ou depuis le Planificateur.',
           mbInformation, MB_OK);
end;
