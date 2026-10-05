using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Models;
using SecureWall.Infrastructure.Database;

namespace SecureWall.Tests;

// Doublures de test : aucune ne touche au pare-feu, à Defender ni au système de la machine de développement.

public sealed class FakeFirewallPolicy : IFirewallPolicy
{
    public List<FirewallRule> Rules { get; } = new();
    public List<FirewallProfileInfo> Profiles { get; } = new()
    {
        new() { Profile = FirewallProfiles.Domain, Name = "Domaine", Enabled = true },
        new() { Profile = FirewallProfiles.Private, Name = "Privé", Enabled = true },
        new() { Profile = FirewallProfiles.Public, Name = "Public", Enabled = true, IsCurrent = true },
    };
    public List<string> Calls { get; } = new();

    public IReadOnlyList<FirewallProfileInfo> GetProfiles() => Profiles.ToList();

    public void SetProfileEnabled(FirewallProfiles profile, bool enabled)
    {
        Calls.Add($"profile:{profile}:{enabled}");
        var i = Profiles.FindIndex(p => p.Profile == profile);
        var p = Profiles[i];
        Profiles[i] = new FirewallProfileInfo { Profile = p.Profile, Name = p.Name, Enabled = enabled, IsCurrent = p.IsCurrent };
    }

    public IReadOnlyList<FirewallRule> GetRules() => Rules.ToList();
    public int GetRuleCount() => Rules.Count;
    public FirewallRule? FindRule(string name) => Rules.FirstOrDefault(r => r.Name == name);

    /// <summary>Simule un refus de Windows (E_INVALIDARG…) à l'ajout de la règle portant ce nom.</summary>
    public string? FailAddFor { get; set; }

    public void AddRule(FirewallRuleSpec s, string group)
    {
        if (s.Name == FailAddFor) throw new ArgumentException("Value does not fall within the expected range.");
        Calls.Add("add:" + s.Name);
        Rules.Add(new FirewallRule
        {
            Name = s.Name, Description = s.Description, Enabled = s.Enabled, Direction = s.Direction, Action = s.Action, ProtocolNumber = (int)s.Protocol,
            LocalPorts = s.LocalPorts, RemotePorts = s.RemotePorts, LocalAddresses = s.LocalAddresses, RemoteAddresses = s.RemoteAddresses,
            Program = s.Program, ProfilesMask = (int)s.Profiles, Group = group,
        });
    }

    public void UpdateRule(string originalName, FirewallRuleSpec s)
    {
        Calls.Add("update:" + originalName);
        var i = Rules.FindIndex(r => r.Name == originalName);
        var g = Rules[i].Group;
        Rules.RemoveAt(i);
        AddRule(s, g);
    }

    public void RemoveRule(string name) { Calls.Add("remove:" + name); Rules.RemoveAll(r => r.Name == name); }

    public void SetRuleEnabled(string name, bool enabled)
    {
        Calls.Add($"enable:{name}:{enabled}");
        var i = Rules.FindIndex(r => r.Name == name);
        var r = Rules[i];
        Rules[i] = new FirewallRule
        {
            Name = r.Name, Enabled = enabled, Direction = r.Direction, Action = r.Action, ProtocolNumber = r.ProtocolNumber, Program = r.Program, Group = r.Group,
            ProfilesMask = r.ProfilesMask,
        };
    }
}

public sealed class FakeFirewallBackup : IFirewallBackup
{
    public int BackupCount;
    public bool Fail;
    public Task<(bool Ok, string Name, string Message)> BackupAsync(string suffix = "", CancellationToken ct = default)
    {
        BackupCount++;
        return Task.FromResult(Fail ? (false, "", "échec") : (true, $"fw-20260101-000000-{suffix}.wfw", "ok"));
    }
    public IReadOnlyList<string> List() => new[] { "fw-20260101-000000.wfw" };
    public Task<(bool Ok, string Message)> RestoreAsync(string name, CancellationToken ct = default) => Task.FromResult((true, "restauré " + name));
}

public sealed class FakePrivilegedClient : IPrivilegedClient
{
    public bool Available = true;
    public List<(PrivilegedOperation Op, Dictionary<string, string> Args)> Requests { get; } = new();
    public Func<PrivilegedOperation, PipeResponse>? Responder;

    public Task<bool> IsAvailableAsync(CancellationToken ct = default) => Task.FromResult(Available);

    public Task<PipeResponse> SendAsync(PrivilegedOperation op, Dictionary<string, string>? args = null, CancellationToken ct = default)
    {
        Requests.Add((op, args ?? new()));
        if (!Available) return Task.FromResult(PipeResponse.Fail("", "unavailable", "Le service privilégié SecureWall ne répond pas."));
        return Task.FromResult(Responder?.Invoke(op) ?? PipeResponse.Ok("x", "ok"));
    }
}

public sealed class FakeAudit : IAuditLog
{
    public List<(string Action, string Details)> Entries { get; } = new();
    public void Write(string action, string details) => Entries.Add((action, details));
}

public sealed class FakeNotifications : INotificationService
{
    public List<(NotificationKind Kind, string Title, string Message, AppPage Page)> Sent { get; } = new();
    public event Action<AppPage>? OpenRequested;
    public void Notify(NotificationKind kind, string title, string message, AppPage page = AppPage.Dashboard) => Sent.Add((kind, title, message, page));
    public void Raise(AppPage p) => OpenRequested?.Invoke(p);
}

public sealed class FakeDefenderGateway : IDefenderGateway
{
    public DefenderStatus Status { get; set; } = new()
    {
        Available = true, ServiceEnabled = true, AntivirusEnabled = true, RealTime = true, OnAccess = true, Downloads = true, Behavior = true,
        SignatureVersion = "1.0.0.0", SignatureUpdated = DateTime.Now, SignatureAgeDays = 0, LastQuickScan = DateTime.Now.AddDays(-1),
    };
    public DefenderPreferences Prefs { get; set; } = new() { Available = true, CloudReporting = 2, PuaProtection = 1, ExclusionsVisible = true };
    public List<DefenderThreat> Detections { get; } = new();
    public List<string[]> ScanCalls { get; } = new();
    public int ScanExitCode;
    public Action? OnScan;
    public bool CancelCalled;
    public TimeSpan ScanDuration = TimeSpan.Zero;
    public int UpdateExit;

    public DefenderStatus ReadStatus() => Status;
    public DefenderPreferences ReadPreferences() => Prefs;
    public IReadOnlyList<DefenderThreat> ReadDetections() => Detections.ToList();

    public async Task<(int ExitCode, string Output)> RunScanAsync(IReadOnlyList<string> args, Action<System.Diagnostics.Process>? onStart, CancellationToken ct)
    {
        ScanCalls.Add(args.ToArray());
        OnScan?.Invoke();
        try { if (ScanDuration > TimeSpan.Zero) await Task.Delay(ScanDuration, ct); }
        catch (OperationCanceledException) { return (-2, "annulé"); }
        return (ScanExitCode, "");
    }

    public Task<(int ExitCode, string Output)> CancelScanAsync() { CancelCalled = true; return Task.FromResult((0, "")); }
    public Task<(int ExitCode, string Output)> UpdateSignaturesAsync(CancellationToken ct) => Task.FromResult((UpdateExit, UpdateExit == 0 ? "" : "erreur réseau"));
}

public sealed class FakeConnectionSource : IConnectionSource
{
    public List<NetConnection> Connections { get; } = new();
    public IReadOnlyList<NetConnection> Read() => Connections.Select(c => new NetConnection
    {
        Protocol = c.Protocol, LocalAddress = c.LocalAddress, LocalPort = c.LocalPort, RemoteAddress = c.RemoteAddress, RemotePort = c.RemotePort,
        State = c.State, Pid = c.Pid, IsExternal = c.IsExternal, IsListening = c.IsListening, IsEstablished = c.IsEstablished,
        ProcessName = c.ProcessName, ProcessPath = c.ProcessPath,
    }).ToList();
}

public sealed class FakeSignatures : ISignatureService
{
    public event Action? Updated;
    public SignatureInfo Info { get; set; } = new() { Status = SignatureStatus.SignedValid, Publisher = "Éditeur Test" };
    public SignatureInfo GetOrQueue(string path) => Info;
    public Task<SignatureInfo> VerifyAsync(string path, CancellationToken ct = default) => Task.FromResult(Info);
    public void Raise() => Updated?.Invoke();
}

/// <summary>Base SQLite temporaire, supprimée à la fin du test.</summary>
public sealed class TempDb : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "securewall-test-" + Guid.NewGuid().ToString("N") + ".db");
    public SqliteSecurityStore Store { get; }

    public TempDb() => Store = new SqliteSecurityStore(Path);

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        foreach (var f in new[] { Path, Path + "-wal", Path + "-shm" })
            try { File.Delete(f); } catch { /* ignoré */ }
    }
}
