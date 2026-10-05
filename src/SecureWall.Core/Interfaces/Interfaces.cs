using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Models;

namespace SecureWall.Core.Interfaces;

public interface IDefenderService
{
    Task<DefenderStatus> GetStatusAsync(CancellationToken ct = default);
    Task<DefenderPreferences> GetPreferencesAsync(CancellationToken ct = default);
    Task<RealtimeProtectionStatus> GetRealtimeProtectionStatusAsync(CancellationToken ct = default);
    Task<SignatureVersionInfo> GetSignatureVersionAsync(CancellationToken ct = default);
    Task<OperationResult> UpdateSignaturesAsync(CancellationToken ct = default);
    Task<ScanResult> StartQuickScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default);
    Task<ScanResult> StartFullScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default);
    Task<ScanResult> StartCustomScanAsync(IReadOnlyList<string> paths, IProgress<ScanProgress>? progress = null, CancellationToken ct = default);
    /// <summary>Menaces non résolues (actives ou en échec d'action).</summary>
    Task<IReadOnlyList<DefenderThreat>> GetThreatsAsync(CancellationToken ct = default);
    /// <summary>Historique complet de protection tenu par Microsoft Defender.</summary>
    Task<IReadOnlyList<DefenderThreat>> GetProtectionHistoryAsync(CancellationToken ct = default);
}

/// <summary>Accès bas niveau à Microsoft Defender (WMI / MpCmdRun). Abstrait pour les tests.</summary>
public interface IDefenderGateway
{
    DefenderStatus ReadStatus();
    DefenderPreferences ReadPreferences();
    IReadOnlyList<DefenderThreat> ReadDetections();
    Task<(int ExitCode, string Output)> RunScanAsync(IReadOnlyList<string> args, Action<System.Diagnostics.Process>? onStart, CancellationToken ct);
    Task<(int ExitCode, string Output)> CancelScanAsync();
    Task<(int ExitCode, string Output)> UpdateSignaturesAsync(CancellationToken ct);
}

public interface IFirewallPolicy
{
    IReadOnlyList<FirewallProfileInfo> GetProfiles();
    void SetProfileEnabled(FirewallProfiles profile, bool enabled);
    IReadOnlyList<FirewallRule> GetRules();
    int GetRuleCount();
    FirewallRule? FindRule(string name);
    void AddRule(FirewallRuleSpec spec, string group);
    void UpdateRule(string originalName, FirewallRuleSpec spec);
    void RemoveRule(string name);
    void SetRuleEnabled(string name, bool enabled);
}

public interface IFirewallService
{
    Task<IReadOnlyList<FirewallProfileInfo>> GetProfilesAsync(CancellationToken ct = default);
    Task<bool> IsActiveProfileProtectedAsync(CancellationToken ct = default);
    Task<OperationResult> SetProfileEnabledAsync(FirewallProfiles profile, bool enabled, CancellationToken ct = default);
    Task<OperationResult> CreateBackupAsync(CancellationToken ct = default);
    Task<IReadOnlyList<string>> ListBackupsAsync(CancellationToken ct = default);
    Task<OperationResult> RestoreBackupAsync(string name, CancellationToken ct = default);
}

public interface IFirewallRuleService
{
    Task<IReadOnlyList<FirewallRule>> GetRulesAsync(CancellationToken ct = default);
    Task<OperationResult> CreateRuleAsync(FirewallRuleSpec spec, CancellationToken ct = default);
    Task<OperationResult> UpdateRuleAsync(string originalName, FirewallRuleSpec spec, CancellationToken ct = default);
    Task<OperationResult> SetRuleEnabledAsync(string name, bool enabled, CancellationToken ct = default);
    Task<OperationResult> DeleteRuleAsync(string name, CancellationToken ct = default);
    Task<OperationResult> DuplicateRuleAsync(FirewallRule rule, CancellationToken ct = default);
    Task<string> ExportRulesJsonAsync(bool onlySecureWall, CancellationToken ct = default);
    Task<OperationResult> ImportRulesJsonAsync(string json, CancellationToken ct = default);
}

public interface INetworkProfileService
{
    Task<IReadOnlyList<NetworkProfileInfo>> GetNetworkProfilesAsync(CancellationToken ct = default);
}

public interface IConnectionSource
{
    IReadOnlyList<NetConnection> Read();
}

public interface INetworkMonitor
{
    Task<IReadOnlyList<NetConnection>> GetConnectionsAsync(CancellationToken ct = default);
    NetworkSample? LastSample { get; }
    IReadOnlyList<NetworkSample> History { get; }
    /// <summary>Déclenché la première fois qu'une application (hors composants Windows critiques) établit une connexion externe.</summary>
    event Action<NetworkAppInfo, NetConnection>? NewApplicationDetected;
    void Start();
    void Stop();
}

public interface IProcessService
{
    Task<IReadOnlyList<ProcessEntry>> GetProcessesAsync(CancellationToken ct = default);
}

public interface ISignatureService
{
    /// <summary>Retourne le résultat en cache ou Pending (et planifie la vérification).</summary>
    SignatureInfo GetOrQueue(string path);
    Task<SignatureInfo> VerifyAsync(string path, CancellationToken ct = default);
    event Action? Updated;
}

public interface IStartupService
{
    Task<IReadOnlyList<StartupEntry>> GetEntriesAsync(CancellationToken ct = default);
    Task<OperationResult> SetEnabledAsync(StartupEntry entry, bool enabled, CancellationToken ct = default);
}

public interface IUsbMonitor
{
    IReadOnlyList<UsbDevice> Connected { get; }
    event Action<UsbDevice>? DeviceConnected;
    event Action<string>? DeviceRemoved;
    void Start();
    void Stop();
}

public interface IPrivilegedClient
{
    Task<bool> IsAvailableAsync(CancellationToken ct = default);
    Task<PipeResponse> SendAsync(PrivilegedOperation op, Dictionary<string, string>? args = null, CancellationToken ct = default);
}

public interface INotificationService
{
    void Notify(NotificationKind kind, string title, string message, AppPage page = AppPage.Dashboard);
    event Action<AppPage>? OpenRequested;
}

public interface ISettingsStore
{
    AppSettings Current { get; }
    void Save();
    string ExportJson();
    OperationResult ImportJson(string json);
    event Action? Changed;
}

public interface IAuditLog
{
    void Write(string action, string details);
}

public interface ISecurityStore
{
    // Applications / connexions
    long UpsertApplication(string name, string path, string publisher, string signatureStatus, out bool isNew);
    ApplicationRecord? GetApplication(string path);
    List<ApplicationRecord> GetApplications();
    void AddConnections(long applicationId, IEnumerable<ConnectionRecord> rows);
    // Pare-feu
    void AddFirewallEvents(IEnumerable<FirewallEventRecord> rows);
    List<FirewallEventRecord> GetFirewallEvents(DateTime since, int limit = 1000);
    // Analyses
    long StartScan(string type, string? target);
    void FinishScan(long id, int? files, int threats, string status);
    List<ScanRecord> GetScans(int limit = 200, int offset = 0);
    // Menaces
    (bool Inserted, string? PreviousStatus) UpsertThreat(DefenderThreat threat);
    List<ThreatRecord> GetThreats(int limit = 500, int offset = 0, string? status = null);
    // Événements
    void AddEvent(string type, string description, string severity = "Information");
    List<SecurityEventRecord> GetEvents(int limit = 200, int offset = 0, string? search = null);
    // Périphériques
    DeviceRecord? GetDevice(string identifier);
    void SeenDevice(string name, string identifier);
    void MarkDeviceScanned(string identifier);
    List<DeviceRecord> GetDevices();
    // Audit
    void AddAudit(string user, string action, string details);
    List<AuditLogRecord> GetAudit(int limit = 200, int offset = 0);
    // Statistiques
    Dictionary<string, int> TopApplications(DateTime since, int take);
    Dictionary<string, int> ConnectionsByHour(DateTime since);
    Dictionary<string, int> TopPorts(DateTime since, int take);
    Dictionary<string, int> TopDestinations(DateTime since, int take);
    Dictionary<string, int> BlockedByApplication(DateTime since, int take);
    int CountScans(DateTime since);
    int CountThreats(DateTime since);
    int CountBlocked(DateTime since);
    // Destinations et localisation (cache pays des adresses publiques)
    List<RemoteTraffic> GetRemoteTraffic(DateTime since, int limit = 20000);
    Dictionary<string, GeoCacheEntry> GetGeoCache(IEnumerable<string> addresses);
    void SetGeoCache(IEnumerable<GeoCacheEntry> rows);
    int ClearGeoCache();
    // Maintenance
    void PurgeOlderThan(DateTime limit);
    void ClearHistory();
    // Paramètres clé/valeur
    string? GetSetting(string key);
    void SetSetting(string key, string value);
}

public interface IFirewallBackup
{
    Task<(bool Ok, string Name, string Message)> BackupAsync(string suffix = "", CancellationToken ct = default);
    IReadOnlyList<string> List();
    Task<(bool Ok, string Message)> RestoreAsync(string name, CancellationToken ct = default);
}
