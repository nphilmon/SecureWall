using Microsoft.Extensions.Logging;
using SecureWall.Core.Interfaces;
using SecureWall.Infrastructure.Configuration;
using SecureWall.Infrastructure.Logging;
using SecureWall.Infrastructure.Windows;
using SecureWall.Security.Hardening;
using SecureWall.PrivilegedService;
using SecureWall.PrivilegedService.Antivirus;
using SecureWall.PrivilegedService.Firewall;
using SecureWall.PrivilegedService.SystemOperations;
using SecureWall.Security.Firewall;

// Service Windows (SecureWallPrivilegedService). En développement : SecureWall.PrivilegedService.exe --console (terminal administrateur).
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = AppPaths.ServiceName);

var logDir = Path.Combine(AppPaths.ServiceDataDir, "logs");
// Dossier de données : propriétaire vérifié, droits stricts, fichiers étrangers supprimés — AVANT d'ouvrir le moindre journal.
IReadOnlyList<string> hardeningWarnings = Array.Empty<string>();
if (Elevation.IsAdmin) hardeningWarnings = DataDirectoryGuard.Secure(AppPaths.ServiceDataDir, AppPaths.FirewallBackupDir, logDir);
else { Directory.CreateDirectory(logDir); Directory.CreateDirectory(AppPaths.FirewallBackupDir); }
builder.Logging.ClearProviders();
builder.Logging.AddProvider(new FileLoggerProvider(logDir, "service"));
if (OperatingSystem.IsWindows() && Environment.UserInteractive == false) builder.Logging.AddEventLog(s => s.SourceName = "SecureWall");
else builder.Logging.AddConsole();

builder.Services.AddSingleton<IFirewallPolicy, ComFirewallPolicy>();
builder.Services.AddSingleton<FirewallBackupManager>();
builder.Services.AddSingleton<IFirewallBackup>(sp => sp.GetRequiredService<FirewallBackupManager>());
builder.Services.AddSingleton<EmergencyExecutor>();
builder.Services.AddSingleton<FirewallHandler>();
builder.Services.AddSingleton<DefenderHandler>();
builder.Services.AddSingleton<SystemHandler>();
builder.Services.AddSingleton<SecureWall.Security.DnsConfig.IDnsSystem, SecureWall.Security.DnsConfig.WindowsDnsSystem>();
builder.Services.AddSingleton<SecureWall.Security.DnsConfig.DnsConfigurator>();
builder.Services.AddSingleton<DnsHandler>();
builder.Services.AddSingleton<RequestDispatcher>();
builder.Services.AddSingleton<ClientAuthenticator>();
builder.Services.AddHostedService<PipeServerWorker>();
builder.Services.AddHostedService<EmergencyWatchdogWorker>();

var host = builder.Build();
var hardeningLog = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Hardening");
foreach (var w in hardeningWarnings) hardeningLog.LogWarning("{Warning}", w);
host.Run();
