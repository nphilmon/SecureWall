using System.Diagnostics;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Models;
using SecureWall.Infrastructure.Windows;

namespace SecureWall.Security.Antivirus;

/// <summary>
/// Accès officiel à Microsoft Defender : classes WMI du fournisseur MSFT_Mp* (espace root\Microsoft\Windows\Defender)
/// et l'outil en ligne de commande MpCmdRun.exe livré avec Windows. Aucun moteur propriétaire.
/// </summary>
public sealed class DefenderGateway : IDefenderGateway
{
    public static string? ResolveMpCmdRun()
    {
        var platform = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Windows Defender", "Platform");
        if (Directory.Exists(platform))
        {
            var best = Directory.GetDirectories(platform)
                .Select(d => (Dir: d, Ver: Version.TryParse(Path.GetFileName(d).Split('-')[0], out var v) ? v : new Version(0, 0)))
                .OrderByDescending(x => x.Ver)
                .Select(x => Path.Combine(x.Dir, "MpCmdRun.exe"))
                .FirstOrDefault(File.Exists);
            if (best != null) return best;
        }
        var legacy = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        return File.Exists(legacy) ? legacy : null;
    }

    public DefenderStatus ReadStatus()
    {
        try
        {
            var rows = Wmi.Query(Wmi.DefenderScope, "SELECT * FROM MSFT_MpComputerStatus");
            if (rows.Count == 0) return DefenderStatus.Unavailable("Microsoft Defender n'a renvoyé aucune information.");
            var r = rows[0];
            var mode = r.Str("AMRunningMode");
            var updated = r.Date("AntivirusSignatureLastUpdated");
            return new DefenderStatus
            {
                Available = true,
                ServiceEnabled = r.Bool("AMServiceEnabled"),
                AntivirusEnabled = r.Bool("AntivirusEnabled"),
                RunningMode = mode,
                PassiveMode = mode.Contains("Passive", StringComparison.OrdinalIgnoreCase) || mode.Contains("Passif", StringComparison.OrdinalIgnoreCase),
                RealTime = r.Bool("RealTimeProtectionEnabled"),
                OnAccess = r.Bool("OnAccessProtectionEnabled"),
                Downloads = r.Bool("IoavProtectionEnabled"),
                Behavior = r.Bool("BehaviorMonitorEnabled"),
                NetworkInspection = r.Bool("NISEnabled"),
                TamperProtected = r.Bool("IsTamperProtected"),
                ProductVersion = r.Str("AMProductVersion"),
                EngineVersion = r.Str("AMEngineVersion"),
                SignatureVersion = r.Str("AntivirusSignatureVersion"),
                SignatureUpdated = updated,
                SignatureAgeDays = updated is { } u ? (int)Math.Max(0, (DateTime.Now - u).TotalDays) : (r.Long("AntivirusSignatureAge") is var a and > 0 ? (int)a : null),
                LastQuickScan = r.Date("QuickScanEndTime"),
                LastFullScan = r.Date("FullScanEndTime"),
            };
        }
        catch (Exception ex)
        {
            return DefenderStatus.Unavailable("Impossible d'interroger Microsoft Defender : " + ex.Message);
        }
    }

    public DefenderPreferences ReadPreferences()
    {
        try
        {
            var rows = Wmi.Query(Wmi.DefenderScope, "SELECT * FROM MSFT_MpPreference");
            if (rows.Count == 0) return new DefenderPreferences();
            var r = rows[0];
            var exclusions = new List<string>();
            var visible = true;
            void Add(string label, string[] values)
            {
                foreach (var v in values)
                {
                    if (v.StartsWith("N/A", StringComparison.OrdinalIgnoreCase)) { visible = false; continue; }
                    exclusions.Add($"{label} : {v}");
                }
            }
            Add("Dossier/fichier", r.Arr("ExclusionPath"));
            Add("Extension", r.Arr("ExclusionExtension"));
            Add("Processus", r.Arr("ExclusionProcess"));
            return new DefenderPreferences
            {
                Available = true,
                CloudReporting = (int)r.Long("MAPSReporting"),
                SampleConsent = (int)r.Long("SubmitSamplesConsent"),
                PuaProtection = (int)r.Long("PUAProtection"),
                BehaviorDisabled = r.Bool("DisableBehaviorMonitoring"),
                DownloadsDisabled = r.Bool("DisableIOAVProtection"),
                RealTimeDisabled = r.Bool("DisableRealtimeMonitoring"),
                ExclusionsVisible = visible,
                Exclusions = exclusions,
            };
        }
        catch { return new DefenderPreferences(); }
    }

    public IReadOnlyList<DefenderThreat> ReadDetections()
    {
        try
        {
            var threats = Wmi.Query(Wmi.DefenderScope, "SELECT * FROM MSFT_MpThreat")
                .ToDictionary(t => t.Long("ThreatID"), t => t, EqualityComparer<long>.Default);
            var list = new List<DefenderThreat>();
            foreach (var d in Wmi.Query(Wmi.DefenderScope, "SELECT * FROM MSFT_MpThreatDetection"))
            {
                var tid = d.Long("ThreatID");
                threats.TryGetValue(tid, out var t);
                var resources = d.Arr("Resources");
                list.Add(new DefenderThreat
                {
                    DetectionId = d.Str("DetectionID"),
                    ThreatId = tid,
                    Name = t?.Str("ThreatName") is { Length: > 0 } n ? n : $"Menace #{tid}",
                    CategoryId = (int)(t?.Long("CategoryID") ?? 0),
                    SeverityId = (int)(t?.Long("SeverityID") ?? 0),
                    IsActive = t?.Bool("IsActive") ?? false,
                    FilePath = resources.Select(ParseResource).FirstOrDefault(p => !string.IsNullOrEmpty(p)) ?? "",
                    DetectionTime = d.Date("InitialDetectionTime") ?? DateTime.MinValue,
                    Process = d.Str("ProcessName"),
                    StatusId = (int)d.Long("ThreatStatusID"),
                    ActionId = (int)d.Long("CleaningActionID"),
                    User = d.Str("DomainUser"),
                });
            }
            return list.Where(x => !string.IsNullOrEmpty(x.DetectionId)).OrderByDescending(x => x.DetectionTime).ToList();
        }
        catch { return Array.Empty<DefenderThreat>(); }
    }

    /// <summary>"file:_C:\x\y.exe" / "containerfile:_…" / "webfile:_…|https://…" → chemin local.</summary>
    internal static string ParseResource(string res)
    {
        var i = res.IndexOf(":_", StringComparison.Ordinal);
        var path = i >= 0 ? res[(i + 2)..] : res;
        var cut = path.IndexOfAny(new[] { '|', '>' });
        if (cut > 0) path = path[..cut];
        path = path.TrimEnd('-', ' ');
        return path;
    }

    public Task<(int ExitCode, string Output)> RunScanAsync(IReadOnlyList<string> args, Action<Process>? onStart, CancellationToken ct) =>
        RunMp(args, ct, onStart, null);

    public async Task<(int ExitCode, string Output)> CancelScanAsync() =>
        await RunMp(new[] { "-Scan", "-Cancel" }, CancellationToken.None, null, TimeSpan.FromSeconds(30)).ConfigureAwait(false);

    public Task<(int ExitCode, string Output)> UpdateSignaturesAsync(CancellationToken ct) =>
        RunMp(new[] { "-SignatureUpdate" }, ct, null, TimeSpan.FromMinutes(5));

    static async Task<(int, string)> RunMp(IReadOnlyList<string> args, CancellationToken ct, Action<Process>? onStart, TimeSpan? timeout)
    {
        var exe = ResolveMpCmdRun();
        if (exe == null) return (-1, "MpCmdRun.exe introuvable : Microsoft Defender n'est pas installé.");
        var r = await ProcessRunner.RunAsync(exe, args, ct, timeout, onStart).ConfigureAwait(false);
        return (r.Cancelled ? -2 : r.ExitCode, r.Output + r.Error);
    }
}
