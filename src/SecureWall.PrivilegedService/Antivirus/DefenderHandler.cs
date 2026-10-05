using System.Text.RegularExpressions;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Infrastructure.Windows;
using SecureWall.Security.Antivirus;

namespace SecureWall.PrivilegedService.Antivirus;

/// <summary>Opérations Defender nécessitant l'élévation : restauration de quarantaine (MpCmdRun) et traitement des menaces actives (Remove-MpThreat).</summary>
public sealed class DefenderHandler
{
    // Noms de menaces Defender : lettres, chiffres et ponctuation courante (ex. « Virus:DOS/EICAR_Test_File », « Trojan:Win32/Wacatac.B!ml »).
    static readonly Regex ThreatName = new(@"^[\p{L}\p{N}:/!._\-()@#$+=, \[\]]{1,256}$", RegexOptions.Compiled);

    public async Task<PipeResponse> HandleAsync(PipeRequest req, CancellationToken ct)
    {
        switch (req.Operation)
        {
            case PrivilegedOperation.DefenderRestoreQuarantined:
            {
                var name = req.Args.GetValueOrDefault("name") ?? "";
                if (!ThreatName.IsMatch(name)) return PipeResponse.Fail(req.Id, "invalid", "Nom de menace invalide.");
                var exe = DefenderGateway.ResolveMpCmdRun();
                if (exe == null) return PipeResponse.Fail(req.Id, "unavailable", "Microsoft Defender n'est pas installé.");
                var r = await ProcessRunner.RunAsync(exe, new[] { "-Restore", "-Name", name, "-All" }, ct, TimeSpan.FromMinutes(2)).ConfigureAwait(false);
                return r.Ok
                    ? PipeResponse.Ok(req.Id, "Élément(s) restauré(s) par Microsoft Defender.")
                    : PipeResponse.Fail(req.Id, "failed", "Microsoft Defender n'a pas pu restaurer l'élément : " + FirstLine(r.Output + r.Error));
            }

            case PrivilegedOperation.DefenderRemoveThreat:
            {
                var r = await PowerShell.RunAsync("Remove-MpThreat", ct, TimeSpan.FromMinutes(2)).ConfigureAwait(false);
                return r.Ok
                    ? PipeResponse.Ok(req.Id, "Microsoft Defender a traité les menaces actives.")
                    : PipeResponse.Fail(req.Id, "failed", "Microsoft Defender n'a pas pu traiter les menaces : " + FirstLine(r.Error + r.Output));
            }
        }
        return PipeResponse.Fail(req.Id, "invalid", "Opération non prise en charge.");
    }

    static string FirstLine(string s) => s.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? "";
}
