using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Models;
using SecureWall.Infrastructure.Windows;

namespace SecureWall.Security.Antivirus;

/// <summary>
/// Quarantaine gérée par Microsoft Defender. SecureWall affiche l'état réel et demande à Defender (via le service privilégié)
/// de restaurer ou supprimer : il ne manipule jamais lui-même les fichiers mis en quarantaine.
/// </summary>
public sealed class QuarantineService
{
    readonly IDefenderService _defender;
    readonly IPrivilegedClient _client;
    readonly IAuditLog _audit;

    public QuarantineService(IDefenderService defender, IPrivilegedClient client, IAuditLog audit)
    {
        _defender = defender; _client = client; _audit = audit;
    }

    public async Task<IReadOnlyList<DefenderThreat>> GetQuarantinedAsync(CancellationToken ct = default)
    {
        var all = await _defender.GetProtectionHistoryAsync(ct).ConfigureAwait(false);
        return all.Where(t => t.IsQuarantined).ToList();
    }

    public async Task<OperationResult> RestoreAsync(DefenderThreat threat, CancellationToken ct = default)
    {
        var r = await _client.SendAsync(PrivilegedOperation.DefenderRestoreQuarantined, new() { ["name"] = threat.Name }, ct).ConfigureAwait(false);
        _audit.Write("Restauration depuis la quarantaine", $"{threat.Name} — {threat.FilePath} — {(r.Success ? "réussie" : "échec")}");
        return r.Success ? OperationResult.Ok(r.Message) : OperationResult.Fail(r.Message);
    }

    /// <summary>
    /// Demande à Defender de traiter (supprimer) les menaces ACTIVES. Windows n'expose pas d'API pour supprimer un élément déjà
    /// en quarantaine : pour cela, utilisez l'historique de protection de Windows Security (Defender purge aussi la quarantaine après 90 jours).
    /// </summary>
    public async Task<OperationResult> RemoveActiveThreatsAsync(CancellationToken ct = default)
    {
        var r = await _client.SendAsync(PrivilegedOperation.DefenderRemoveThreat, null, ct).ConfigureAwait(false);
        _audit.Write("Traitement des menaces actives", r.Success ? "Demandé à Microsoft Defender" : "Échec : " + r.Message);
        return r.Success ? OperationResult.Ok(r.Message) : OperationResult.Fail(r.Message);
    }

    public static void OpenWindowsSecurityHistory() =>
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("windowsdefender://history") { UseShellExecute = true });
}

/// <summary>Analyses planifiées via le Planificateur de tâches Windows (schtasks.exe), au niveau de l'utilisateur (aucune élévation).</summary>
public sealed class ScheduledScanService
{
    const string Folder = "SecureWall";

    public static string TaskName(ScheduleConfig c) => $"{Folder}\\{c.Id}";

    public async Task<OperationResult> ApplyAsync(ScheduleConfig c, string exePath, CancellationToken ct = default)
    {
        if (!c.Enabled) return await DeleteAsync(c, ct).ConfigureAwait(false);
        if (c.ScanKind == ScanKind.Custom && !(Directory.Exists(c.CustomPath) || File.Exists(c.CustomPath)))
            return OperationResult.Fail("Choisissez un dossier ou un fichier existant pour l'analyse personnalisée.");

        var action = $"\"{exePath}\" --scheduled-scan {c.ScanKind}" + (c.ScanKind == ScanKind.Custom ? $" --path \"{c.CustomPath}\"" : "");
        var args = new List<string> { "/Create", "/F", "/TN", TaskName(c), "/TR", action, "/ST", c.Time };
        switch (c.Frequency)
        {
            case ScheduleFrequency.Daily: args.AddRange(new[] { "/SC", "DAILY" }); break;
            case ScheduleFrequency.Weekly: args.AddRange(new[] { "/SC", "WEEKLY", "/D", DayCode(c.DayOfWeek) }); break;
            case ScheduleFrequency.Monthly: args.AddRange(new[] { "/SC", "MONTHLY", "/D", Math.Clamp(c.DayOfMonth, 1, 28).ToString() }); break;
        }
        var r = await ProcessRunner.RunAsync("schtasks.exe", args, ct, TimeSpan.FromSeconds(30)).ConfigureAwait(false);
        return r.Ok ? OperationResult.Ok("Tâche planifiée créée.") : OperationResult.Fail("Le Planificateur de tâches a refusé la tâche : " + (r.Error + r.Output).Trim());
    }

    public async Task<OperationResult> DeleteAsync(ScheduleConfig c, CancellationToken ct = default)
    {
        if (!await ExistsAsync(c, ct).ConfigureAwait(false)) return OperationResult.Ok();
        var r = await ProcessRunner.RunAsync("schtasks.exe", new[] { "/Delete", "/F", "/TN", TaskName(c) }, ct, TimeSpan.FromSeconds(30)).ConfigureAwait(false);
        return r.Ok ? OperationResult.Ok() : OperationResult.Fail((r.Error + r.Output).Trim());
    }

    public async Task<bool> ExistsAsync(ScheduleConfig c, CancellationToken ct = default)
    {
        var r = await ProcessRunner.RunAsync("schtasks.exe", new[] { "/Query", "/TN", TaskName(c) }, ct, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
        return r.Ok;
    }

    static string DayCode(DayOfWeek d) => d switch
    {
        DayOfWeek.Monday => "MON", DayOfWeek.Tuesday => "TUE", DayOfWeek.Wednesday => "WED", DayOfWeek.Thursday => "THU",
        DayOfWeek.Friday => "FRI", DayOfWeek.Saturday => "SAT", _ => "SUN",
    };
}
