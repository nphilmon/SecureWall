using Microsoft.Win32;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Models;

namespace SecureWall.Security.Monitoring;

/// <summary>
/// Programmes lancés au démarrage : clés Run (utilisateur/machine, 32 et 64 bits) et dossiers Démarrage.
/// L'état Activé/Désactivé est celui que Windows applique via StartupApproved (le même mécanisme que le Gestionnaire des tâches).
/// </summary>
public sealed class StartupService : IStartupService
{
    const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    const string Run32Key = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    const string ApprovedRun = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    const string ApprovedRun32 = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32";
    const string ApprovedFolder = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";

    readonly ISignatureService _signatures;
    readonly IPrivilegedClient _client;
    readonly IAuditLog _audit;

    public StartupService(ISignatureService signatures, IPrivilegedClient client, IAuditLog audit)
    {
        _signatures = signatures; _client = client; _audit = audit;
    }

    public Task<IReadOnlyList<StartupEntry>> GetEntriesAsync(CancellationToken ct = default) => Task.Run(() =>
    {
        var list = new List<StartupEntry>();
        ReadRun(Registry.CurrentUser, RunKey, ApprovedRun, "HKCU-Run", @"HKCU\" + RunKey, list);
        ReadRun(Registry.LocalMachine, RunKey, ApprovedRun, "HKLM-Run", @"HKLM\" + RunKey, list);
        ReadRun(Registry.LocalMachine, Run32Key, ApprovedRun32, "HKLM-Run32", @"HKLM\" + Run32Key, list);
        ReadFolder(Environment.GetFolderPath(Environment.SpecialFolder.Startup), Registry.CurrentUser, "Startup-User", list);
        ReadFolder(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), Registry.LocalMachine, "Startup-Common", list);
        foreach (var e in list) e.Signature = string.IsNullOrEmpty(e.Path) ? new SignatureInfo { Status = SignatureStatus.Unknown } : _signatures.GetOrQueue(e.Path);
        return (IReadOnlyList<StartupEntry>)list;
    }, ct);

    static void ReadRun(RegistryKey hive, string subKey, string approvedKey, string source, string display, List<StartupEntry> list)
    {
        try
        {
            using var key = hive.OpenSubKey(subKey);
            if (key == null) return;
            using var approved = hive.OpenSubKey(approvedKey);
            foreach (var name in key.GetValueNames())
            {
                var cmd = key.GetValue(name)?.ToString() ?? "";
                list.Add(new StartupEntry
                {
                    Name = name, Command = cmd, Path = ExtractExecutable(cmd), Location = display, Source = source,
                    Enabled = IsApproved(approved, name),
                });
            }
        }
        catch { /* clé inaccessible */ }
    }

    static void ReadFolder(string folder, RegistryKey hive, string source, List<StartupEntry> list)
    {
        try
        {
            if (!Directory.Exists(folder)) return;
            using var approved = hive.OpenSubKey(ApprovedFolder);
            foreach (var f in Directory.GetFiles(folder))
            {
                var fn = Path.GetFileName(f);
                if (fn.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                var target = f.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? ResolveShortcut(f) : f;
                list.Add(new StartupEntry
                {
                    Name = Path.GetFileNameWithoutExtension(f), Command = target, Path = target, Location = folder, Source = source,
                    Enabled = IsApproved(approved, fn),
                });
            }
        }
        catch { /* dossier inaccessible */ }
    }

    /// <summary>Premier octet de la valeur StartupApproved : 02/06 = activé, 03 = désactivé.</summary>
    static bool IsApproved(RegistryKey? approved, string name)
    {
        if (approved?.GetValue(name) is byte[] b && b.Length > 0) return (b[0] & 1) == 0;
        return true;
    }

    public static string ExtractExecutable(string command)
    {
        var s = Environment.ExpandEnvironmentVariables(command.Trim());
        if (s.StartsWith('"'))
        {
            var end = s.IndexOf('"', 1);
            return end > 1 ? s[1..end] : s.Trim('"');
        }
        var idx = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return idx > 0 ? s[..(idx + 4)] : s.Split(' ')[0];
    }

    static string ResolveShortcut(string lnk)
    {
        try
        {
            var shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) return lnk;
            dynamic shell = Activator.CreateInstance(shellType)!;
            dynamic sc = shell.CreateShortcut(lnk);
            string target = sc.TargetPath;
            return string.IsNullOrEmpty(target) ? lnk : target;
        }
        catch { return lnk; }
    }

    public async Task<OperationResult> SetEnabledAsync(StartupEntry entry, bool enabled, CancellationToken ct = default)
    {
        var (hive, approvedKey, valueName) = entry.Source switch
        {
            "HKCU-Run" => (Registry.CurrentUser, ApprovedRun, entry.Name),
            "HKLM-Run" => (Registry.LocalMachine, ApprovedRun, entry.Name),
            "HKLM-Run32" => (Registry.LocalMachine, ApprovedRun32, entry.Name),
            "Startup-User" => (Registry.CurrentUser, ApprovedFolder, FolderItemName(entry)),
            "Startup-Common" => (Registry.LocalMachine, ApprovedFolder, FolderItemName(entry)),
            _ => (null, "", ""),
        };
        if (hive == null) return OperationResult.Fail("Source de démarrage non prise en charge.");

        OperationResult result;
        if (hive == Registry.CurrentUser)
        {
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(approvedKey, writable: true);
                var data = new byte[12];
                data[0] = enabled ? (byte)2 : (byte)3;
                if (!enabled) BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(data, 4);
                key.SetValue(valueName, data, RegistryValueKind.Binary);
                result = OperationResult.Ok();
            }
            catch (Exception ex) { result = OperationResult.Fail("Modification impossible : " + ex.Message); }
        }
        else
        {
            var r = await _client.SendAsync(PrivilegedOperation.StartupSetEnabled,
                new() { ["source"] = entry.Source, ["name"] = valueName, ["enabled"] = enabled ? "1" : "0" }, ct).ConfigureAwait(false);
            result = r.Success ? OperationResult.Ok() : OperationResult.Fail(r.Message);
        }
        _audit.Write(enabled ? "Activation d'un programme au démarrage" : "Désactivation d'un programme au démarrage", $"{entry.Name} ({entry.Source}) : {(result.Success ? "réussi" : result.Message)}");
        return result;
    }

    static string FolderItemName(StartupEntry e)
    {
        // Le nom stocké par Windows est le nom du fichier du dossier Démarrage (avec extension).
        var dir = e.Location;
        var match = Directory.Exists(dir) ? Directory.GetFiles(dir).FirstOrDefault(f => Path.GetFileNameWithoutExtension(f) == e.Name) : null;
        return match != null ? Path.GetFileName(match) : e.Name;
    }
}
