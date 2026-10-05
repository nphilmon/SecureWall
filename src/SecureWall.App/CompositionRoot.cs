using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureWall.App.Services;
using SecureWall.Infrastructure.Configuration;
using SecureWall.Infrastructure.Database;
using SecureWall.Infrastructure.Logging;
using SecureWall.Infrastructure.Notifications;
using SecureWall.Infrastructure.Windows;
using SecureWall.Security.Devices;
using SecureWall.Security.Monitoring;
using SecureWall.Security.Processes;

namespace SecureWall.App;

/// <summary>Racine de composition : tous les services de sécurité sont indépendants de l'interface (projets Core / Security / Infrastructure).</summary>
public static class CompositionRoot
{
    public static IServiceProvider Build()
    {
        var s = new ServiceCollection();

        s.AddLogging(b => b.AddProvider(new FileLoggerProvider(AppPaths.LogDir, "securewall")));

        // Infrastructure
        s.AddSingleton<SqliteSecurityStore>(_ => new SqliteSecurityStore(AppPaths.DbFile));
        s.AddSingleton<ISecurityStore>(p => p.GetRequiredService<SqliteSecurityStore>());
        s.AddSingleton<IAuditLog>(p => p.GetRequiredService<SqliteSecurityStore>());
        s.AddSingleton<ISettingsStore, SettingsStore>();
        s.AddSingleton<INotificationService, NotificationService>();
        s.AddSingleton<IPrivilegedClient, PrivilegedPipeClient>();

        // Antivirus (Microsoft Defender)
        s.AddSingleton<IDefenderGateway, DefenderGateway>();
        s.AddSingleton<ThreatSync>();
        s.AddSingleton<IDefenderService, DefenderService>();
        s.AddSingleton<ISignatureService, DigitalSignatureService>();
        s.AddSingleton<QuarantineService>();
        s.AddSingleton<ScheduledScanService>();

        // Pare-feu
        s.AddSingleton<IFirewallPolicy, ComFirewallPolicy>();
        s.AddSingleton<IFirewallService, FirewallService>();
        s.AddSingleton<IFirewallRuleService, FirewallRuleService>();
        s.AddSingleton<INetworkProfileService, NetworkProfileService>();
        s.AddSingleton<BaselineRulesService>();
        s.AddSingleton<SecureWall.Security.Network.ReverseDnsService>(_ => new SecureWall.Security.Network.ReverseDnsService());
        s.AddSingleton<SecureWall.Security.Network.GeoLocationService>(sp => new SecureWall.Security.Network.GeoLocationService(sp.GetRequiredService<ISecurityStore>(), sp.GetRequiredService<ISettingsStore>()));
        s.AddSingleton<SecureWall.Security.DnsConfig.IDnsSystem, SecureWall.Security.DnsConfig.WindowsDnsSystem>();
        s.AddSingleton<SecureWall.Security.DnsConfig.DnsService>();
        s.AddSingleton<SecureWall.Security.Updates.AppUpdateService>(sp => new SecureWall.Security.Updates.AppUpdateService(sp.GetRequiredService<IAuditLog>()));
        s.AddSingleton<EmergencyModeService>();

        // Réseau, processus, périphériques, surveillance
        s.AddSingleton<ProcessIdentityCache>();
        s.AddSingleton<IConnectionSource, IpHelperConnectionSource>();
        s.AddSingleton<INetworkMonitor, NetworkMonitor>();
        s.AddSingleton<IProcessService, ProcessService>();
        s.AddSingleton<IStartupService, StartupService>();
        s.AddSingleton<IUsbMonitor, UsbMonitor>();
        s.AddSingleton<SecurityMonitor>();
        s.AddSingleton<SecurityStateService>();

        // Interface
        s.AddSingleton<IDialogService, DialogService>();
        s.AddSingleton<ThemeService>();
        s.AddSingleton<ProgramActions>();
        s.AddSingleton<RuleWizardLauncher>();
        s.AddSingleton<EmergencyController>();
        s.AddSingleton<UsbCoordinator>();
        s.AddSingleton<NewAppAlertCoordinator>();
        s.AddSingleton<MainViewModel>();
        s.AddSingleton<INavigator>(p => p.GetRequiredService<MainViewModel>());

        foreach (var t in new[]
                 {
                     typeof(DashboardViewModel), typeof(AntivirusDashboardViewModel), typeof(ScanViewModel), typeof(ThreatsViewModel),
                     typeof(QuarantineViewModel), typeof(ProcessMonitorViewModel), typeof(ConnectionsViewModel), typeof(ApplicationsViewModel),
                     typeof(FirewallViewModel), typeof(RulesViewModel), typeof(UsbViewModel), typeof(StartupViewModel), typeof(HistoryViewModel),
                     typeof(StatisticsViewModel), typeof(SecurityCenterViewModel), typeof(SettingsViewModel), typeof(DnsViewModel), typeof(WorldMapViewModel), typeof(WhatsNewViewModel),
                 })
            s.AddSingleton(t);
        s.AddTransient<ProgramAnalysisViewModel>();
        s.AddTransient<FirstRunViewModel>();

        return s.BuildServiceProvider();
    }
}


