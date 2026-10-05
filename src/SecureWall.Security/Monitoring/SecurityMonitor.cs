using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Logic;
using SecureWall.Core.Models;
using SecureWall.Infrastructure.Configuration;
using SecureWall.Security.Antivirus;

namespace SecureWall.Security.Monitoring;

/// <summary>
/// Surveille les changements sensibles (pare-feu, Defender, exclusions, règles, démarrage) en comparant des instantanés
/// à une base de référence mémorisée. La première exécution ne génère aucune alerte. Messages factuels, sans alarmisme.
/// </summary>
public sealed class SecurityMonitor : IDisposable
{
    readonly IDefenderGateway _defender;
    readonly IFirewallPolicy _firewall;
    readonly IStartupService _startup;
    readonly ISecurityStore _store;
    readonly INotificationService _notify;
    readonly ISettingsStore _settings;
    readonly IPrivilegedClient _client;
    readonly ThreatSync _threatSync;
    readonly ILogger<SecurityMonitor>? _log;

    CancellationTokenSource? _cts;
    SecuritySnapshot? _baseline;
    DateTime _lastRuleScan = DateTime.MinValue;
    int _lastRuleCount = -1;
    Dictionary<string, string> _lastRules = new();
    DateTime _lastBlockedRead = DateTime.Now.AddMinutes(-5);
    DateTime _lastSignatureNotice = DateTime.MinValue;
    public bool BlockedConnectionsReadable { get; private set; }
    public bool BlockedConnectionsAuditing { get; private set; }

    public event Action? Changed;

    public SecurityMonitor(IDefenderGateway defender, IFirewallPolicy firewall, IStartupService startup, ISecurityStore store,
        INotificationService notify, ISettingsStore settings, IPrivilegedClient client, ThreatSync threatSync, ILogger<SecurityMonitor>? log = null)
    {
        _defender = defender; _firewall = firewall; _startup = startup; _store = store; _notify = notify; _settings = settings;
        _client = client; _threatSync = threatSync; _log = log;
    }

    public void Start()
    {
        if (_cts != null) return;
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        _baseline = LoadBaseline();
        _ = Task.Run(async () =>
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(45));
            try
            {
                await CycleAsync(ct).ConfigureAwait(false);
                while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false)) await CycleAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { /* arrêt */ }
        }, ct);
    }

    public void Stop() { _cts?.Cancel(); _cts = null; }
    public void Dispose() => Stop();

    async Task CycleAsync(CancellationToken ct)
    {
        try
        {
            _threatSync.Sync();   // nouvelles détections, quarantaine, suppressions
            if (_settings.Current.MonitorSecurityChanges) await DetectChangesAsync(ct).ConfigureAwait(false);
            CheckSignatureAge();
            await ReadBlockedConnectionsAsync(ct).ConfigureAwait(false);
            if (DateTime.Now.Minute == 0 || _lastPurge < DateTime.Now.AddHours(-12)) Purge();
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { _log?.LogWarning(ex, "Cycle de surveillance"); }
    }

    DateTime _lastPurge = DateTime.MinValue;
    void Purge()
    {
        _lastPurge = DateTime.Now;
        try { _store.PurgeOlderThan(DateTime.Now.AddDays(-_settings.Current.RetentionDays)); } catch { /* non bloquant */ }
    }

    async Task DetectChangesAsync(CancellationToken ct)
    {
        var snap = await Task.Run(() => BuildSnapshot(ct), ct).ConfigureAwait(false);
        var changes = SecurityChangeDetector.Compare(_baseline, snap);
        foreach (var c in changes)
        {
            _store.AddEvent(c.EventType, c.Description, c.Severity);
            if (c.Notify is { } kind)
            {
                var page = kind switch { NotificationKind.FirewallDisabled => AppPage.Firewall, NotificationKind.DefenderDisabled => AppPage.Antivirus, _ => AppPage.History };
                _notify.Notify(kind, kind switch
                {
                    NotificationKind.FirewallDisabled => "Pare-feu désactivé",
                    NotificationKind.DefenderDisabled => "Protection antivirus désactivée",
                    _ => "Modification de sécurité",
                }, c.Description, page);
            }
        }
        if (changes.Count > 0) Changed?.Invoke();
        _baseline = snap;
        SaveBaseline(snap);
    }

    SecuritySnapshot BuildSnapshot(CancellationToken ct)
    {
        var d = _defender.ReadStatus();
        var p = _defender.ReadPreferences();
        var profiles = _firewall.GetProfiles();

        // Les règles ne sont relues en détail que si leur nombre change, ou toutes les 3 minutes (modification de règle existante).
        var count = _firewall.GetRuleCount();
        if (count != _lastRuleCount || (DateTime.Now - _lastRuleScan).TotalMinutes >= 3)
        {
            _lastRules = _firewall.GetRules().GroupBy(r => r.Name).ToDictionary(g => g.Key, g => Hash(g.First()));
            _lastRuleCount = count;
            _lastRuleScan = DateTime.Now;
        }

        var startup = _startup.GetEntriesAsync(ct).GetAwaiter().GetResult();

        return new SecuritySnapshot
        {
            DefenderEnabled = d.Available && d.AntivirusEnabled && !d.PassiveMode,
            RealTimeEnabled = d.Available && d.RealTime,
            FirewallDomain = profiles.FirstOrDefault(x => x.Profile == FirewallProfiles.Domain)?.Enabled ?? true,
            FirewallPrivate = profiles.FirstOrDefault(x => x.Profile == FirewallProfiles.Private)?.Enabled ?? true,
            FirewallPublic = profiles.FirstOrDefault(x => x.Profile == FirewallProfiles.Public)?.Enabled ?? true,
            Exclusions = p.Exclusions.ToHashSet(),
            ExclusionsKnown = p.Available && p.ExclusionsVisible,
            Rules = _lastRules,
            StartupKeys = startup.Select(s => s.Key).ToHashSet(),
            DefenderPrefsSignature = p.Available ? $"{p.CloudReporting}|{p.SampleConsent}|{p.PuaProtection}|{p.BehaviorDisabled}|{p.DownloadsDisabled}" : "",
        };
    }

    static string Hash(FirewallRule r)
    {
        var s = $"{r.Enabled}|{r.Direction}|{r.Action}|{r.ProtocolNumber}|{r.LocalPorts}|{r.RemotePorts}|{r.LocalAddresses}|{r.RemoteAddresses}|{r.Program}|{r.ProfilesMask}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s)))[..12];
    }

    void CheckSignatureAge()
    {
        var d = _defender.ReadStatus();
        if (!d.Available || d.SignatureAgeDays is not { } age) return;
        if (age > _settings.Current.SignatureMaxAgeDays && (DateTime.Now - _lastSignatureNotice).TotalHours >= 24)
        {
            _lastSignatureNotice = DateTime.Now;
            _store.AddEvent("Antivirus", $"Les signatures antivirus datent de {age} jours.", "Attention");
            _notify.Notify(NotificationKind.SignaturesOutdated, "Signatures antivirus obsolètes",
                $"Dernière mise à jour il y a {age} jours. Recherchez les mises à jour.", AppPage.Antivirus);
        }
    }

    /// <summary>Connexions bloquées : journal de sécurité Windows (événements 5152/5157), lu par le service privilégié.</summary>
    async Task ReadBlockedConnectionsAsync(CancellationToken ct)
    {
        if (!await _client.IsAvailableAsync(ct).ConfigureAwait(false)) { BlockedConnectionsReadable = false; return; }
        var since = _lastBlockedRead;
        var r = await _client.SendAsync(PrivilegedOperation.FirewallReadBlockedConnections,
            new() { ["since"] = since.ToUniversalTime().ToString("o") }, ct).ConfigureAwait(false);
        if (!r.Success || string.IsNullOrEmpty(r.Data)) return;
        var report = JsonSerializer.Deserialize<BlockedConnectionsReport>(r.Data);
        if (report == null) return;
        BlockedConnectionsReadable = report.Readable;
        BlockedConnectionsAuditing = report.AuditingEnabled;
        _lastBlockedRead = DateTime.Now.AddSeconds(-2);
        if (report.Entries.Count == 0) return;
        _store.AddFirewallEvents(report.Entries.Select(e => new FirewallEventRecord
        {
            Application = string.IsNullOrEmpty(e.Application) ? "" : Path.GetFileName(e.Application),
            Action = "Bloquée", Direction = e.Direction, Protocol = e.Protocol, RemoteAddress = e.RemoteAddress, RemotePort = e.RemotePort,
            RuleName = "", Timestamp = e.Time,
        }));
        Changed?.Invoke();
    }

    // ---------- Base de référence ----------
    static SecuritySnapshot? LoadBaseline()
    {
        try
        {
            if (File.Exists(AppPaths.BaselineFile))
                return JsonSerializer.Deserialize<SecuritySnapshot>(File.ReadAllText(AppPaths.BaselineFile));
        }
        catch { /* référence corrompue : nouvelle référence */ }
        return null;
    }

    static void SaveBaseline(SecuritySnapshot s)
    {
        try { File.WriteAllText(AppPaths.BaselineFile, JsonSerializer.Serialize(s)); } catch { /* non bloquant */ }
    }
}
