using System.Text.Json;
using Microsoft.Win32;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Security.Firewall;

namespace SecureWall.PrivilegedService.SystemOperations;

/// <summary>Opérations système restantes : trafic TCP par connexion et activation/désactivation d'un démarrage "machine" (StartupApproved).</summary>
public sealed class SystemHandler
{
    const string ApprovedRun = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    const string ApprovedRun32 = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32";
    const string ApprovedFolder = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";
    const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    const string Run32Key = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";

    public Task<PipeResponse> HandleAsync(PipeRequest req, CancellationToken ct)
    {
        switch (req.Operation)
        {
            case PrivilegedOperation.NetworkGetTcpTraffic:
                return Task.FromResult(PipeResponse.Ok(req.Id, "", JsonSerializer.Serialize(TcpTrafficReader.Read())));

            case PrivilegedOperation.StartupSetEnabled:
                return Task.FromResult(SetStartup(req));
        }
        return Task.FromResult(PipeResponse.Fail(req.Id, "invalid", "Opération non prise en charge."));
    }

    static PipeResponse SetStartup(PipeRequest req)
    {
        var source = req.Args.GetValueOrDefault("source") ?? "";
        var name = req.Args.GetValueOrDefault("name") ?? "";
        var flag = req.Args.GetValueOrDefault("enabled");
        if (flag is not ("0" or "1")) return PipeResponse.Fail(req.Id, "invalid", "Valeur « enabled » invalide.");
        if (name.Length is 0 or > 260 || name.Any(char.IsControl) || name.Contains('\\') || name.Contains('/'))
            return PipeResponse.Fail(req.Id, "invalid", "Nom d'entrée invalide.");

        // Seules les sources "machine" sont acceptées, et l'entrée doit réellement exister.
        string approved;
        switch (source)
        {
            case "HKLM-Run":
                if (!ValueExists(RunKey, name)) return PipeResponse.Fail(req.Id, "invalid", "Entrée de démarrage introuvable.");
                approved = ApprovedRun; break;
            case "HKLM-Run32":
                if (!ValueExists(Run32Key, name)) return PipeResponse.Fail(req.Id, "invalid", "Entrée de démarrage introuvable.");
                approved = ApprovedRun32; break;
            case "Startup-Common":
                var dir = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
                if (!File.Exists(Path.Combine(dir, name))) return PipeResponse.Fail(req.Id, "invalid", "Entrée de démarrage introuvable.");
                approved = ApprovedFolder; break;
            default:
                return PipeResponse.Fail(req.Id, "invalid", "Source de démarrage non autorisée.");
        }

        using var key = Registry.LocalMachine.CreateSubKey(approved, writable: true);
        var data = new byte[12];
        data[0] = flag == "1" ? (byte)2 : (byte)3;
        if (flag == "0") BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(data, 4);
        key.SetValue(name, data, RegistryValueKind.Binary);
        return PipeResponse.Ok(req.Id, "Entrée de démarrage mise à jour.");
    }

    static bool ValueExists(string subKey, string name)
    {
        using var k = Registry.LocalMachine.OpenSubKey(subKey);
        return k?.GetValue(name) != null;
    }
}
