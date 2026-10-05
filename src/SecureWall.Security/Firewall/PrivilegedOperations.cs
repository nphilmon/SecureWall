using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Models;
using SecureWall.Infrastructure.Configuration;
using SecureWall.Infrastructure.Windows;
using SecureWall.Security.Network;

namespace SecureWall.Security.Firewall;

// Ces classes sont exécutées UNIQUEMENT par le service privilégié (SYSTEM), après validation stricte de la requête.

/// <summary>Sauvegardes complètes de la politique de pare-feu (netsh advfirewall export/import, outil officiel Windows).</summary>
public sealed class FirewallBackupManager : IFirewallBackup
{
    static readonly Regex NamePattern = new(@"^fw-\d{8}-\d{6}(-[a-z]+)?\.wfw$", RegexOptions.Compiled);
    const int MaxBackups = 25;
    readonly string _dir;

    public FirewallBackupManager(string? dir = null) => _dir = dir ?? AppPaths.FirewallBackupDir;

    public static bool IsValidBackupName(string name) => NamePattern.IsMatch(name);

    public async Task<(bool Ok, string Name, string Message)> BackupAsync(string suffix = "", CancellationToken ct = default)
    {
        Directory.CreateDirectory(_dir);
        var name = $"fw-{DateTime.Now:yyyyMMdd-HHmmss}{(suffix.Length > 0 ? "-" + suffix : "")}.wfw";
        var r = await ProcessRunner.RunAsync("netsh.exe", new[] { "advfirewall", "export", Path.Combine(_dir, name) }, ct, TimeSpan.FromSeconds(60)).ConfigureAwait(false);
        if (!r.Ok) return (false, "", "Sauvegarde du pare-feu impossible : " + (r.Output + r.Error).Trim());
        Prune();
        return (true, name, "Sauvegarde créée.");
    }

    public IReadOnlyList<string> List() =>
        Directory.Exists(_dir)
            ? Directory.GetFiles(_dir, "*.wfw").Select(Path.GetFileName).Where(n => n != null && NamePattern.IsMatch(n!)).Select(n => n!).OrderByDescending(n => n).ToList()
            : new List<string>();

    public async Task<(bool Ok, string Message)> RestoreAsync(string name, CancellationToken ct = default)
    {
        if (!IsValidBackupName(name)) return (false, "Nom de sauvegarde invalide.");
        var path = Path.Combine(_dir, name);
        if (!File.Exists(path)) return (false, "Sauvegarde introuvable.");
        var pre = await BackupAsync("avant", ct).ConfigureAwait(false);   // filet de sécurité avant restauration
        if (!pre.Ok) return (false, pre.Message);
        var r = await ProcessRunner.RunAsync("netsh.exe", new[] { "advfirewall", "import", path }, ct, TimeSpan.FromSeconds(60)).ConfigureAwait(false);
        return r.Ok ? (true, $"Pare-feu restauré depuis {name}. (État précédent conservé : {pre.Name})") : (false, "Restauration impossible : " + (r.Output + r.Error).Trim());
    }

    void Prune()
    {
        foreach (var f in Directory.GetFiles(_dir, "*.wfw").OrderByDescending(f => f).Skip(MaxBackups))
            try { File.Delete(f); } catch { /* ignoré */ }
    }
}

/// <summary>Mode urgence : deux règles de blocage (entrant/sortant vers Internet), supprimables en un clic. Rien d'autre n'est modifié.</summary>
public sealed class EmergencyExecutor
{
    public const string OutName = "SecureWall Emergency - Bloquer le trafic sortant vers Internet";
    public const string InName = "SecureWall Emergency - Bloquer le trafic entrant depuis Internet";

    public const int MaxAutoRestoreMinutes = 24 * 60;

    readonly IFirewallPolicy _policy;
    readonly IFirewallBackup _backups;
    readonly string _stateFile;
    readonly SemaphoreSlim _gate = new(1, 1);

    public EmergencyExecutor(IFirewallPolicy policy, IFirewallBackup backups, string? stateFile = null)
    {
        _policy = policy; _backups = backups; _stateFile = stateFile ?? AppPaths.EmergencyStateFile;
    }

    public EmergencyState GetState()
    {
        var active = _policy.FindRule(OutName) != null && _policy.FindRule(InName) != null;
        if (!active) return new EmergencyState();
        try
        {
            if (File.Exists(_stateFile))
                return JsonSerializer.Deserialize<EmergencyState>(File.ReadAllText(_stateFile)) is { } s
                    ? new EmergencyState { Active = true, Since = s.Since, BackupName = s.BackupName, AutoRestoreAt = s.AutoRestoreAt }
                    : new EmergencyState { Active = true };
        }
        catch { /* état illisible */ }
        return new EmergencyState { Active = true };
    }

    /// <param name="autoRestoreMinutes">Durée après laquelle Internet est rétabli automatiquement (null = jamais).</param>
    public async Task<(bool Ok, string Message)> CutoffAsync(CancellationToken ct, int? autoRestoreMinutes = null)
    {
        if (autoRestoreMinutes is < 1 or > MaxAutoRestoreMinutes)
            return (false, $"La durée de rétablissement automatique doit être comprise entre 1 et {MaxAutoRestoreMinutes} minutes.");

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (GetState().Active) return (true, "Le mode urgence est déjà actif.");
            var disabled = _policy.GetProfiles().Where(p => p.IsCurrent && !p.Enabled).Select(p => p.Name).ToList();
            if (disabled.Count > 0)
                return (false, $"Le pare-feu Windows est désactivé pour le profil {string.Join(", ", disabled)} : les règles de blocage ne seraient pas appliquées. Activez d'abord le pare-feu.");

            var backup = await _backups.BackupAsync("urgence", ct).ConfigureAwait(false);
            if (!backup.Ok) return (false, backup.Message);

            try
            {
                RemoveEmergencyRules(); // reste éventuel d'une tentative interrompue
                AddBlockRule(OutName, FirewallDirection.Outbound);
                AddBlockRule(InName, FirewallDirection.Inbound);

                var now = DateTime.Now;
                Directory.CreateDirectory(Path.GetDirectoryName(_stateFile)!);
                File.WriteAllText(_stateFile, JsonSerializer.Serialize(new EmergencyState
                {
                    Active = true, Since = now, BackupName = backup.Name,
                    AutoRestoreAt = autoRestoreMinutes is { } m ? now.AddMinutes(m) : null,
                }));
            }
            catch (Exception ex)
            {
                // Tout ou rien : on ne laisse jamais une seule des deux règles en place.
                try { RemoveEmergencyRules(); } catch { /* meilleur effort */ }
                try { if (File.Exists(_stateFile)) File.Delete(_stateFile); } catch { /* ignoré */ }
                return (false, "Impossible de créer les règles de blocage, aucune modification n'a été conservée : " + ex.Message);
            }
            return (true, autoRestoreMinutes is { } min
                ? $"Connexions Internet coupées pour {min} minute(s), puis rétablies automatiquement. Le réseau local reste disponible."
                : "Connexions Internet coupées. Le réseau local reste disponible.");
        }
        finally { _gate.Release(); }
    }

    public (bool Ok, string Message) Restore()
    {
        _gate.Wait();
        try
        {
            RemoveEmergencyRules();
            try { if (File.Exists(_stateFile)) File.Delete(_stateFile); } catch { /* ignoré */ }
            return (true, "Connexions Internet rétablies : l'état précédent du pare-feu est restauré.");
        }
        finally { _gate.Release(); }
    }

    /// <summary>Rétablit Internet si le délai choisi est écoulé. Appelé périodiquement par le service. Retourne vrai si une restauration a eu lieu.</summary>
    public bool RestoreIfExpired(DateTime? now = null)
    {
        var s = GetState();
        if (!s.Active || s.AutoRestoreAt is not { } at || at > (now ?? DateTime.Now)) return false;
        Restore();
        return true;
    }

    void AddBlockRule(string name, FirewallDirection direction) => _policy.AddRule(new FirewallRuleSpec
    {
        Name = name, Description = "Créée par SecureWall (mode urgence). Supprimez-la avec « Restaurer Internet ».",
        Direction = direction, Action = FirewallAction.Block, Protocol = FirewallProtocol.Any,
        RemoteAddresses = "Internet", Profiles = FirewallProfiles.All, Enabled = true,
    }, RuleGroups.Emergency);

    void RemoveEmergencyRules()
    {
        foreach (var n in new[] { OutName, InName })
            if (_policy.FindRule(n) is { } r && r.Group == RuleGroups.Emergency) _policy.RemoveRule(n);
    }
}

/// <summary>Connexions bloquées par le pare-feu : événements 5152/5157 du journal Sécurité (audit "Plateforme de filtrage").</summary>
public static class BlockedConnectionReader
{
    const string FilteringPlatformConnectionGuid = "{0CCE9226-69AE-11D9-BED3-505054503030}";

    public static async Task<BlockedConnectionsReport> ReadAsync(DateTime sinceUtc, CancellationToken ct)
    {
        var report = new BlockedConnectionsReport { AuditingEnabled = await IsAuditingEnabledAsync(ct).ConfigureAwait(false) };
        try
        {
            var since = sinceUtc.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            var q = new EventLogQuery("Security", PathType.LogName,
                $"*[System[(EventID=5152 or EventID=5157) and TimeCreated[@SystemTime>='{since}']]]");
            using var reader = new EventLogReader(q);
            report.Readable = true;
            var dos = DosDeviceMap();
            for (EventRecord? e = reader.ReadEvent(); e != null && report.Entries.Count < 2000; e = reader.ReadEvent())
            {
                using (e)
                {
                    ct.ThrowIfCancellationRequested();
                    var p = e.Properties;
                    if (p.Count < 8) continue;
                    var dir = Convert.ToString(p[2].Value) is "%%14593" ? "Sortante" : "Entrante";
                    // Les événements de rejet peuvent concerner du trafic purement local (boucle, diffusion) : on ne garde que le trafic réel.
                    var remote = dir == "Sortante" ? Convert.ToString(p[5].Value) ?? "" : Convert.ToString(p[3].Value) ?? "";
                    var rport = dir == "Sortante" ? Convert.ToInt32(p[6].Value) : Convert.ToInt32(p[4].Value);
                    report.Entries.Add(new BlockedConnectionEntry
                    {
                        Time = e.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
                        Application = ToDosPath(Convert.ToString(p[1].Value) ?? "", dos),
                        Direction = dir, RemoteAddress = remote, RemotePort = rport,
                        Protocol = Convert.ToInt32(p[7].Value) switch { 6 => "TCP", 17 => "UDP", 1 => "ICMP", var n => n.ToString() },
                    });
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (UnauthorizedAccessException) { report.Readable = false; }
        catch (EventLogException) { report.Readable = false; }
        return report;
    }

    public static async Task<bool> IsAuditingEnabledAsync(CancellationToken ct)
    {
        var r = await ProcessRunner.RunAsync("auditpol.exe", new[] { "/get", "/subcategory:" + FilteringPlatformConnectionGuid, "/r" }, ct, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
        if (!r.Ok) return false;
        var line = r.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Skip(1).FirstOrDefault() ?? "";
        // Le libellé du paramètre est localisé ("Failure"/"Échec"/"Success and Failure"…). "No Auditing"/"Pas d'audit" = désactivé.
        var l = line.ToLowerInvariant();
        return (l.Contains("fail") || l.Contains("chec") || l.Contains("success") || l.Contains("ussite")) && !l.Contains("no auditing") && !l.Contains("pas d'audit");
    }

    /// <summary>Active (ou désactive) l'audit des connexions bloquées — uniquement sur demande explicite de l'utilisateur.</summary>
    public static async Task<(bool Ok, string Message)> SetAuditingAsync(bool enabled, CancellationToken ct)
    {
        var r = await ProcessRunner.RunAsync("auditpol.exe",
            new[] { "/set", "/subcategory:" + FilteringPlatformConnectionGuid, enabled ? "/failure:enable" : "/failure:disable" }, ct, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
        return r.Ok ? (true, enabled ? "Audit des connexions bloquées activé." : "Audit des connexions bloquées désactivé.") : (false, (r.Output + r.Error).Trim());
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint QueryDosDevice(string deviceName, StringBuilder target, int max);

    static Dictionary<string, string> DosDeviceMap()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var c = 'A'; c <= 'Z'; c++)
        {
            var sb = new StringBuilder(260);
            if (QueryDosDevice(c + ":", sb, sb.Capacity) > 0) map[sb.ToString()] = c + ":";
        }
        return map;
    }

    static string ToDosPath(string device, Dictionary<string, string> map)
    {
        foreach (var kv in map)
            if (device.StartsWith(kv.Key + "\\", StringComparison.OrdinalIgnoreCase)) return kv.Value + device[kv.Key.Length..];
        return device;
    }
}

/// <summary>Octets envoyés/reçus par connexion TCP IPv4 (statistiques ESTATS de Windows, activées à la demande).</summary>
public static class TcpTrafficReader
{
    [DllImport("iphlpapi.dll")]
    static extern uint SetPerTcpConnectionEStats(ref MibTcpRow row, int type, byte[] rw, uint rwVersion, uint rwSize, uint offset);

    [DllImport("iphlpapi.dll")]
    static extern uint GetPerTcpConnectionEStats(ref MibTcpRow row, int type, IntPtr rw, uint rwVersion, uint rwSize,
        IntPtr ros, uint rosVersion, uint rosSize, IntPtr rod, uint rodVersion, uint rodSize);

    [StructLayout(LayoutKind.Sequential)]
    struct MibTcpRow { public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort; }

    const int TcpConnectionEstatsData = 1;
    const int RodSize = 96;

    public static List<TcpTrafficEntry> Read()
    {
        var result = new List<TcpTrafficEntry>();
        var rod = Marshal.AllocHGlobal(RodSize);
        try
        {
            foreach (var r in IpHelper.ReadTcp4().Where(r => r.State == 5).Take(2000))
            {
                var row = new MibTcpRow { State = r.State, LocalAddr = r.LocalAddr, LocalPort = r.LocalPortRaw, RemoteAddr = r.RemoteAddr, RemotePort = r.RemotePortRaw };
                SetPerTcpConnectionEStats(ref row, TcpConnectionEstatsData, new byte[] { 1 }, 0, 1, 0);   // idempotent
                Marshal.Copy(new byte[RodSize], 0, rod, RodSize);
                var rc = GetPerTcpConnectionEStats(ref row, TcpConnectionEstatsData, IntPtr.Zero, 0, 0, IntPtr.Zero, 0, 0, rod, 0, RodSize);
                if (rc != 0) continue;
                result.Add(new TcpTrafficEntry
                {
                    LocalAddress = new System.Net.IPAddress(r.LocalAddr).ToString(), LocalPort = Port(r.LocalPortRaw),
                    RemoteAddress = new System.Net.IPAddress(r.RemoteAddr).ToString(), RemotePort = Port(r.RemotePortRaw),
                    BytesSent = Marshal.ReadInt64(rod, 0), BytesReceived = Marshal.ReadInt64(rod, 16),
                });
            }
        }
        finally { Marshal.FreeHGlobal(rod); }
        return result;
    }

    static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));
}
