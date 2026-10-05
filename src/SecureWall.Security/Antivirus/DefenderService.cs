using System.Diagnostics;
using Microsoft.Extensions.Logging;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Models;

namespace SecureWall.Security.Antivirus;

/// <summary>Synchronise les détections Defender vers la base locale et émet les notifications correspondantes.</summary>
public sealed class ThreatSync
{
    readonly IDefenderGateway _gateway;
    readonly ISecurityStore _store;
    readonly INotificationService? _notify;
    readonly object _lock = new();
    bool _baselineDone;

    public ThreatSync(IDefenderGateway gateway, ISecurityStore store, INotificationService? notify = null)
    {
        _gateway = gateway; _store = store; _notify = notify;
    }

    /// <summary>Premier appel = référence silencieuse. Appels suivants : notifie les nouvelles détections et changements de statut.</summary>
    public IReadOnlyList<DefenderThreat> Sync()
    {
        lock (_lock)
        {
            var list = _gateway.ReadDetections();
            foreach (var t in list)
            {
                var (inserted, previous) = _store.UpsertThreat(t);
                if (!_baselineDone) continue;
                var changed = inserted || previous != t.Status;
                if (!changed) continue;

                switch (t.StatusId)
                {
                    case 3:
                        _store.AddEvent("Antivirus", $"Élément placé en quarantaine : {t.Name}", "Attention");
                        _notify?.Notify(NotificationKind.Quarantined, "Élément placé en quarantaine", $"{t.Name} — {t.FileName}", AppPage.Quarantine);
                        break;
                    case 4:
                        _store.AddEvent("Antivirus", $"Menace supprimée : {t.Name}", "Succès");
                        _notify?.Notify(NotificationKind.ThreatRemoved, "Menace supprimée", $"{t.Name} — {t.FileName}", AppPage.History);
                        break;
                    default:
                        if (inserted)
                        {
                            _store.AddEvent("Antivirus", $"Menace détectée par Microsoft Defender : {t.Name} ({t.FileName})", "Alerte");
                            _notify?.Notify(NotificationKind.ThreatDetected, "Menace détectée", $"{t.Name} — {t.FileName}", AppPage.Threats);
                        }
                        break;
                }
            }
            _baselineDone = true;
            return list;
        }
    }
}

public sealed class DefenderService : IDefenderService
{
    readonly IDefenderGateway _gateway;
    readonly ISecurityStore _store;
    readonly ThreatSync _sync;
    readonly INotificationService? _notify;
    readonly IAuditLog? _audit;
    readonly ILogger<DefenderService>? _log;
    readonly SemaphoreSlim _gate = new(1, 1);

    public DefenderService(IDefenderGateway gateway, ISecurityStore store, ThreatSync sync,
        INotificationService? notify = null, IAuditLog? audit = null, ILogger<DefenderService>? log = null)
    {
        _gateway = gateway; _store = store; _sync = sync; _notify = notify; _audit = audit; _log = log;
    }

    public Task<DefenderStatus> GetStatusAsync(CancellationToken ct = default) => Task.Run(_gateway.ReadStatus, ct);
    public Task<DefenderPreferences> GetPreferencesAsync(CancellationToken ct = default) => Task.Run(_gateway.ReadPreferences, ct);

    public async Task<RealtimeProtectionStatus> GetRealtimeProtectionStatusAsync(CancellationToken ct = default)
    {
        var s = await GetStatusAsync(ct).ConfigureAwait(false);
        var p = await GetPreferencesAsync(ct).ConfigureAwait(false);
        FeatureState F(bool? on) => on is null ? FeatureState.Unavailable : on.Value ? FeatureState.On : FeatureState.Off;
        bool? Av(bool v) => s.Available ? v : null;

        var cloud = p.Available ? (bool?)(p.CloudReporting > 0) : null;
        var pua = p.Available ? (bool?)(p.PuaProtection == 1) : null;
        return new RealtimeProtectionStatus
        {
            RealTimeEnabled = s.Available && s.RealTime,
            Features =
            {
                new() { Name = "Protection en temps réel", State = F(Av(s.RealTime)), Description = "Analyse les fichiers et programmes lorsqu'ils sont ouverts ou exécutés." },
                new() { Name = "Surveillance des fichiers (accès)", State = F(Av(s.OnAccess)), Description = "Contrôle les accès aux fichiers par les applications." },
                new() { Name = "Protection des téléchargements", State = F(Av(s.Downloads)), Description = "Analyse les fichiers téléchargés et les pièces jointes (IOAV)." },
                new() { Name = "Protection cloud", State = F(cloud), Description = "Envoie des informations à Microsoft pour une détection plus rapide. Fonction Microsoft Defender : SecureWall n'envoie rien." },
                new() { Name = "Analyse comportementale", State = F(Av(s.Behavior)), Description = "Surveille le comportement des programmes en cours d'exécution." },
                new() { Name = "Applications potentiellement indésirables", State = F(pua), Description = p.PuaProtection == 2 ? "Mode audit : détecte sans bloquer." : "Bloque les logiciels publicitaires et indésirables." },
                new() { Name = "Protection du réseau (inspection)", State = F(Av(s.NetworkInspection)), Description = "Inspection du trafic réseau par Microsoft Defender." },
                new() { Name = "Protection contre les falsifications", State = F(Av(s.TamperProtected)), Description = "Empêche les modifications non autorisées des paramètres de Defender." },
            },
        };
    }

    public async Task<SignatureVersionInfo> GetSignatureVersionAsync(CancellationToken ct = default)
    {
        var s = await GetStatusAsync(ct).ConfigureAwait(false);
        return new SignatureVersionInfo { Version = s.SignatureVersion, EngineVersion = s.EngineVersion, LastUpdated = s.SignatureUpdated, AgeDays = s.SignatureAgeDays };
    }

    public async Task<OperationResult> UpdateSignaturesAsync(CancellationToken ct = default)
    {
        var (code, output) = await _gateway.UpdateSignaturesAsync(ct).ConfigureAwait(false);
        _audit?.Write("Mise à jour des signatures", code == 0 ? "Réussie" : $"Code {code}");
        return code == 0
            ? OperationResult.Ok("Les signatures sont à jour.")
            : OperationResult.Fail("La mise à jour a échoué (code " + code + "). " + FirstLine(output));
    }

    public Task<ScanResult> StartQuickScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
        RunAsync(ScanKind.Quick, new[] { new ScanJob("Zones principales du système (analyse gérée par Microsoft Defender)", new[] { "-Scan", "-ScanType", "1" }) }, "Système", progress, ct);

    public Task<ScanResult> StartFullScanAsync(IProgress<ScanProgress>? progress = null, CancellationToken ct = default) =>
        RunAsync(ScanKind.Full, new[] { new ScanJob("Analyse complète du système (gérée par Microsoft Defender)", new[] { "-Scan", "-ScanType", "2" }) }, "Système", progress, ct);

    public Task<ScanResult> StartCustomScanAsync(IReadOnlyList<string> paths, IProgress<ScanProgress>? progress = null, CancellationToken ct = default)
    {
        var valid = paths.Where(p => !string.IsNullOrWhiteSpace(p)).Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var jobs = valid.Select(p => new ScanJob(p, new[] { "-Scan", "-ScanType", "3", "-File", p })).ToList();
        var kind = valid.Count == 1 && File.Exists(valid[0]) ? ScanKind.File : ScanKind.Custom;
        return RunAsync(kind, jobs, valid.Count == 1 ? valid[0] : $"{valid.Count} éléments", progress, ct);
    }

    public Task<IReadOnlyList<DefenderThreat>> GetThreatsAsync(CancellationToken ct = default) =>
        Task.Run<IReadOnlyList<DefenderThreat>>(() => _sync.Sync().Where(t => t.IsActive || t.StatusId is 1 or 102 or 103 or 104 or 107).ToList(), ct);

    public Task<IReadOnlyList<DefenderThreat>> GetProtectionHistoryAsync(CancellationToken ct = default) =>
        Task.Run(_sync.Sync, ct);

    // ---------- Exécution d'une analyse ----------
    sealed record ScanJob(string Label, string[] Args);

    async Task<ScanResult> RunAsync(ScanKind kind, IReadOnlyList<ScanJob> jobs, string target, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        var start = DateTime.Now;
        if (jobs.Count == 0)
            return new ScanResult { Kind = kind, Start = start, End = start, Status = "Impossible", Message = "Aucun élément à analyser.", Target = target };

        var status = await GetStatusAsync(ct).ConfigureAwait(false);
        var scanId = _store.StartScan(KindText(kind), target);
        if (!status.Available || !status.ServiceEnabled)
        {
            const string msg = "Microsoft Defender Antivirus n'est pas disponible : analyse impossible.";
            _store.FinishScan(scanId, null, 0, "Impossible");
            return new ScanResult { ScanId = scanId, Kind = kind, Start = start, End = DateTime.Now, Status = "Impossible", Message = status.Error ?? msg, Target = target };
        }

        progress?.Report(new ScanProgress { State = "En attente", Elapsed = TimeSpan.Zero });
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            start = DateTime.Now;
            var sw = Stopwatch.StartNew();
            string state = "Analyse en cours";
            string? current = jobs[0].Label;
            double? percent = null;
            int? total = null;
            var failed = false;
            string? failMessage = null;

            // Dénombrement des fichiers pour les analyses ciblées (information, sans effet sur Defender).
            Task<int?>? countTask = kind is ScanKind.Custom or ScanKind.File
                ? Task.Run(() => CountFiles(jobs.Select(j => j.Label).ToList(), ct), ct) : null;

            using var ticker = new CancellationTokenSource();
            var tick = Task.Run(async () =>
            {
                while (!ticker.IsCancellationRequested)
                {
                    if (countTask is { IsCompletedSuccessfully: true }) total = countTask.Result;
                    progress?.Report(new ScanProgress
                    {
                        State = state, CurrentItem = current, Elapsed = sw.Elapsed, FilesTotal = total, Percent = percent,
                        ThreatsFound = 0,
                    });
                    try { await Task.Delay(500, ticker.Token).ConfigureAwait(false); } catch (OperationCanceledException) { break; }
                }
            });

            var cancelled = false;
            try
            {
                for (var i = 0; i < jobs.Count; i++)
                {
                    current = jobs[i].Label;
                    percent = jobs.Count > 1 ? (double)i / jobs.Count * 100 : null;
                    using var reg = ct.Register(() => { _ = _gateway.CancelScanAsync(); });
                    var (code, output) = await _gateway.RunScanAsync(jobs[i].Args, null, ct).ConfigureAwait(false);
                    if (ct.IsCancellationRequested || code == -2) { cancelled = true; break; }
                    if (code is not (0 or 2)) { failed = true; failMessage = $"MpCmdRun a renvoyé le code {code}. {FirstLine(output)}"; break; }
                }
            }
            finally
            {
                ticker.Cancel();
                await tick.ConfigureAwait(false);
            }

            await Task.Delay(1500, CancellationToken.None).ConfigureAwait(false);   // laisse Defender publier ses détections
            var detections = _sync.Sync()
                .Where(t => t.DetectionTime >= start.AddSeconds(-5)).ToList();

            var filesCounted = countTask is { IsCompletedSuccessfully: true } ? countTask.Result : null;
            var result = new ScanResult
            {
                ScanId = scanId, Kind = kind, Start = start, End = DateTime.Now, Target = target, Threats = detections,
                FilesScanned = cancelled ? null : filesCounted,
                Status = cancelled ? "Annulée" : failed ? "Échec" : "Terminée",
                Message = failMessage,
            };
            _store.FinishScan(scanId, result.FilesScanned, result.ThreatsFound, result.Status);
            _audit?.Write("Analyse antivirus", $"{KindText(kind)} — {target} — {result.Status} — {result.ThreatsFound} menace(s)");
            progress?.Report(new ScanProgress { State = result.Status, Elapsed = sw.Elapsed, ThreatsFound = result.ThreatsFound, FilesTotal = total, FilesScanned = result.FilesScanned, Percent = 100 });

            if (result.Completed)
            {
                _store.AddEvent("Antivirus", $"Analyse {KindText(kind).ToLowerInvariant()} terminée : {result.ThreatsFound} menace(s).", result.ThreatsFound > 0 ? "Alerte" : "Succès");
                _notify?.Notify(NotificationKind.ScanCompleted, "Analyse terminée",
                    result.ThreatsFound == 0 ? $"Analyse {KindText(kind).ToLowerInvariant()} : aucune menace détectée." : $"Analyse {KindText(kind).ToLowerInvariant()} : {result.ThreatsFound} menace(s) détectée(s).",
                    result.ThreatsFound == 0 ? AppPage.Scans : AppPage.Threats);
            }
            return result;
        }
        catch (OperationCanceledException)
        {
            _store.FinishScan(scanId, null, 0, "Annulée");
            return new ScanResult { ScanId = scanId, Kind = kind, Start = start, End = DateTime.Now, Status = "Annulée", Target = target };
        }
        catch (Exception ex)
        {
            _log?.LogError(ex, "Échec de l'analyse");
            _store.FinishScan(scanId, null, 0, "Échec");
            return new ScanResult { ScanId = scanId, Kind = kind, Start = start, End = DateTime.Now, Status = "Échec", Message = ex.Message, Target = target };
        }
        finally { _gate.Release(); }
    }

    static int? CountFiles(List<string> paths, CancellationToken ct)
    {
        long n = 0;
        try
        {
            foreach (var p in paths)
            {
                if (File.Exists(p)) { n++; continue; }
                if (!Directory.Exists(p)) continue;
                var opts = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
                foreach (var _ in Directory.EnumerateFiles(p, "*", opts)) { n++; if ((n & 0x3FF) == 0) ct.ThrowIfCancellationRequested(); }
            }
            return (int)Math.Min(n, int.MaxValue);
        }
        catch (OperationCanceledException) { throw; }
        catch { return null; }
    }

    public static string KindText(ScanKind k) => k switch
    {
        ScanKind.Quick => "Rapide", ScanKind.Full => "Complète", ScanKind.File => "Fichier", _ => "Personnalisée",
    };

    static string FirstLine(string s) => s.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? "";
}
