using System.Text.Json;
using System.Text.Json.Serialization;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Models;
using SecureWall.Core.Validation;
using SecureWall.Infrastructure.Windows;

namespace SecureWall.Security.Firewall;

/// <summary>État et profils du pare-feu (lecture directe) ; modifications déléguées au service privilégié.</summary>
public sealed class FirewallService : IFirewallService
{
    readonly IFirewallPolicy _policy;
    readonly IPrivilegedClient _client;
    readonly IAuditLog _audit;

    public FirewallService(IFirewallPolicy policy, IPrivilegedClient client, IAuditLog audit)
    {
        _policy = policy; _client = client; _audit = audit;
    }

    public Task<IReadOnlyList<FirewallProfileInfo>> GetProfilesAsync(CancellationToken ct = default) =>
        Task.Run(_policy.GetProfiles, ct);

    public async Task<bool> IsActiveProfileProtectedAsync(CancellationToken ct = default)
    {
        var profiles = await GetProfilesAsync(ct).ConfigureAwait(false);
        var current = profiles.Where(p => p.IsCurrent).ToList();
        return current.Count > 0 ? current.All(p => p.Enabled) : profiles.All(p => p.Enabled);
    }

    public async Task<OperationResult> SetProfileEnabledAsync(FirewallProfiles profile, bool enabled, CancellationToken ct = default)
    {
        var r = await _client.SendAsync(PrivilegedOperation.FirewallSetProfileEnabled,
            new() { ["profile"] = ((int)profile).ToString(), ["enabled"] = enabled ? "1" : "0" }, ct).ConfigureAwait(false);
        _audit.Write("Changement de profil pare-feu", $"{profile} → {(enabled ? "activé" : "désactivé")} : {(r.Success ? "réussi" : r.Message)}");
        return r.Success ? OperationResult.Ok(r.Message) : OperationResult.Fail(r.Message);
    }

    public async Task<OperationResult> CreateBackupAsync(CancellationToken ct = default)
    {
        var r = await _client.SendAsync(PrivilegedOperation.FirewallBackup, null, ct).ConfigureAwait(false);
        return r.Success ? OperationResult.Ok(r.Data ?? "") : OperationResult.Fail(r.Message);
    }

    public async Task<IReadOnlyList<string>> ListBackupsAsync(CancellationToken ct = default)
    {
        var r = await _client.SendAsync(PrivilegedOperation.FirewallListBackups, null, ct).ConfigureAwait(false);
        if (!r.Success || string.IsNullOrEmpty(r.Data)) return Array.Empty<string>();
        try { return JsonSerializer.Deserialize<List<string>>(r.Data) ?? new(); } catch { return Array.Empty<string>(); }
    }

    public async Task<OperationResult> RestoreBackupAsync(string name, CancellationToken ct = default)
    {
        var r = await _client.SendAsync(PrivilegedOperation.FirewallRestoreBackup, new() { ["name"] = name }, ct).ConfigureAwait(false);
        _audit.Write("Restauration d'une sauvegarde du pare-feu", $"{name} : {(r.Success ? "réussie" : r.Message)}");
        return r.Success ? OperationResult.Ok(r.Message) : OperationResult.Fail(r.Message);
    }
}

public sealed class FirewallRuleService : IFirewallRuleService
{
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };

    readonly IFirewallPolicy _policy;
    readonly IPrivilegedClient _client;
    readonly IAuditLog _audit;
    IReadOnlyList<FirewallRule>? _cache;
    DateTime _cacheTime;

    public FirewallRuleService(IFirewallPolicy policy, IPrivilegedClient client, IAuditLog audit)
    {
        _policy = policy; _client = client; _audit = audit;
    }

    public async Task<IReadOnlyList<FirewallRule>> GetRulesAsync(CancellationToken ct = default)
    {
        if (_cache != null && (DateTime.Now - _cacheTime).TotalSeconds < 5) return _cache;
        var rules = await Task.Run(_policy.GetRules, ct).ConfigureAwait(false);
        _cache = rules;
        _cacheTime = DateTime.Now;
        return rules;
    }

    void Invalidate() => _cache = null;

    public async Task<OperationResult> CreateRuleAsync(FirewallRuleSpec spec, CancellationToken ct = default)
    {
        var errors = RuleValidator.Validate(spec);
        if (errors.Count > 0) return OperationResult.Fail(string.Join("\n", errors));
        var r = await _client.SendAsync(PrivilegedOperation.FirewallCreateRule, new() { ["spec"] = JsonSerializer.Serialize(spec, Json) }, ct).ConfigureAwait(false);
        Invalidate();
        _audit.Write("Création de règle pare-feu", Describe(spec) + (r.Success ? "" : " — échec : " + r.Message));
        return r.Success ? OperationResult.Ok("Règle créée.") : OperationResult.Fail(r.Message);
    }

    public async Task<OperationResult> UpdateRuleAsync(string originalName, FirewallRuleSpec spec, CancellationToken ct = default)
    {
        var errors = RuleValidator.Validate(spec);
        if (errors.Count > 0) return OperationResult.Fail(string.Join("\n", errors));
        var r = await _client.SendAsync(PrivilegedOperation.FirewallUpdateRule,
            new() { ["name"] = originalName, ["spec"] = JsonSerializer.Serialize(spec, Json) }, ct).ConfigureAwait(false);
        Invalidate();
        _audit.Write("Modification de règle pare-feu", $"{originalName} → {Describe(spec)}" + (r.Success ? "" : " — échec : " + r.Message));
        return r.Success ? OperationResult.Ok("Règle modifiée.") : OperationResult.Fail(r.Message);
    }

    public async Task<OperationResult> SetRuleEnabledAsync(string name, bool enabled, CancellationToken ct = default)
    {
        var r = await _client.SendAsync(PrivilegedOperation.FirewallSetRuleEnabled,
            new() { ["name"] = name, ["enabled"] = enabled ? "1" : "0" }, ct).ConfigureAwait(false);
        Invalidate();
        _audit.Write(enabled ? "Activation de règle pare-feu" : "Désactivation de règle pare-feu", name + (r.Success ? "" : " — échec : " + r.Message));
        return r.Success ? OperationResult.Ok() : OperationResult.Fail(r.Message);
    }

    public async Task<OperationResult> DeleteRuleAsync(string name, CancellationToken ct = default)
    {
        var r = await _client.SendAsync(PrivilegedOperation.FirewallDeleteRule, new() { ["name"] = name }, ct).ConfigureAwait(false);
        Invalidate();
        _audit.Write("Suppression de règle pare-feu", name + (r.Success ? "" : " — échec : " + r.Message));
        return r.Success ? OperationResult.Ok("Règle supprimée. Une sauvegarde du pare-feu a été conservée.") : OperationResult.Fail(r.Message);
    }

    public Task<OperationResult> DuplicateRuleAsync(FirewallRule rule, CancellationToken ct = default)
    {
        var spec = rule.ToSpec();
        spec.Name = UniqueName(rule.Name + " (copie)");
        return CreateRuleAsync(spec, ct);
    }

    string UniqueName(string baseName)
    {
        var names = (_cache ?? Array.Empty<FirewallRule>()).Select(r => r.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var n = baseName;
        for (var i = 2; names.Contains(n); i++) n = $"{baseName} {i}";
        return n.Length > RuleValidator.MaxNameLength ? n[..RuleValidator.MaxNameLength] : n;
    }

    public async Task<string> ExportRulesJsonAsync(bool onlySecureWall, CancellationToken ct = default)
    {
        var rules = await GetRulesAsync(ct).ConfigureAwait(false);
        var specs = rules.Where(r => !onlySecureWall || r.CreatedBySecureWall).Select(r => r.ToSpec()).ToList();
        return JsonSerializer.Serialize(new { Format = "SecureWall.Rules", Version = 1, ExportedAt = DateTime.Now, Rules = specs }, Json);
    }

    public async Task<OperationResult> ImportRulesJsonAsync(string json, CancellationToken ct = default)
    {
        List<FirewallRuleSpec>? specs;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("Rules", out var arr)) return OperationResult.Fail("Fichier de règles invalide (propriété « Rules » absente).");
            specs = arr.Deserialize<List<FirewallRuleSpec>>(Json);
        }
        catch (Exception ex) { return OperationResult.Fail("Fichier illisible : " + ex.Message); }
        if (specs == null || specs.Count == 0) return OperationResult.Fail("Aucune règle à importer.");
        if (specs.Count > 500) return OperationResult.Fail("Trop de règles (maximum 500 par import).");

        var existing = (await GetRulesAsync(ct).ConfigureAwait(false)).Select(r => r.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        int ok = 0, skipped = 0, failed = 0;
        var messages = new List<string>();
        foreach (var s in specs)
        {
            if (existing.Contains(s.Name)) { skipped++; continue; }
            var errs = RuleValidator.Validate(s);
            if (errs.Count > 0) { failed++; messages.Add($"{s.Name} : {errs[0]}"); continue; }
            var r = await CreateRuleAsync(s, ct).ConfigureAwait(false);
            if (r.Success) ok++; else { failed++; messages.Add($"{s.Name} : {r.Message}"); if (r.Message.Contains("service", StringComparison.OrdinalIgnoreCase)) break; }
        }
        var summary = $"{ok} règle(s) importée(s), {skipped} ignorée(s) (nom déjà présent), {failed} en échec.";
        if (messages.Count > 0) summary += "\n" + string.Join("\n", messages.Take(5));
        return failed == 0 ? OperationResult.Ok(summary) : OperationResult.Fail(summary);
    }

    public static IReadOnlyList<FirewallRule> RulesForProgram(IEnumerable<FirewallRule> rules, string path) =>
        string.IsNullOrEmpty(path) ? Array.Empty<FirewallRule>()
            : rules.Where(r => string.Equals(r.Program, path, StringComparison.OrdinalIgnoreCase)).ToList();

    static string Describe(FirewallRuleSpec s) =>
        $"{s.Name} [{(s.Action == FirewallAction.Allow ? "Autoriser" : "Bloquer")} {(s.Direction == FirewallDirection.Inbound ? "entrant" : "sortant")} {s.Protocol}" +
        (string.IsNullOrEmpty(s.Program) ? "" : $" {Path.GetFileName(s.Program)}") + "]";
}

public sealed class NetworkProfileService : INetworkProfileService
{
    public Task<IReadOnlyList<NetworkProfileInfo>> GetNetworkProfilesAsync(CancellationToken ct = default) => Task.Run<IReadOnlyList<NetworkProfileInfo>>(() =>
    {
        try
        {
            return Wmi.Query(@"root\StandardCimv2", "SELECT * FROM MSFT_NetConnectionProfile")
                .Select(r => new NetworkProfileInfo
                {
                    Name = r.Str("Name"),
                    Interface = r.Str("InterfaceAlias"),
                    Category = r.Long("NetworkCategory") switch { 0 => "Public", 1 => "Privé", 2 => "Domaine", _ => "Inconnu" },
                    Connectivity = Math.Max(r.Long("IPv4Connectivity"), r.Long("IPv6Connectivity")) switch { 4 => "Internet", 3 or 2 => "Réseau local", 1 => "Sans trafic", _ => "Déconnecté" },
                }).ToList();
        }
        catch { return Array.Empty<NetworkProfileInfo>(); }
    }, ct);
}

/// <summary>Mode urgence : coupe / rétablit les connexions Internet via le pare-feu Windows (règles de blocage réversibles).</summary>
public sealed class EmergencyModeService
{
    readonly IPrivilegedClient _client;
    readonly IAuditLog _audit;
    readonly INotificationService? _notify;

    public EmergencyModeService(IPrivilegedClient client, IAuditLog audit, INotificationService? notify = null)
    {
        _client = client; _audit = audit; _notify = notify;
    }

    public async Task<EmergencyState> GetStateAsync(CancellationToken ct = default)
    {
        var r = await _client.SendAsync(PrivilegedOperation.EmergencyStatus, null, ct).ConfigureAwait(false);
        if (!r.Success || string.IsNullOrEmpty(r.Data)) return new EmergencyState();
        try { return JsonSerializer.Deserialize<EmergencyState>(r.Data) ?? new(); } catch { return new EmergencyState(); }
    }

    public async Task<OperationResult> CutoffAsync(int? autoRestoreMinutes = null, CancellationToken ct = default)
    {
        Dictionary<string, string>? args = autoRestoreMinutes is { } m ? new() { ["minutes"] = m.ToString(System.Globalization.CultureInfo.InvariantCulture) } : null;
        var r = await _client.SendAsync(PrivilegedOperation.EmergencyCutoff, args, ct).ConfigureAwait(false);
        var until = autoRestoreMinutes is { } min ? $" (rétablissement automatique dans {min} min)" : "";
        _audit.Write("Mode urgence", r.Success ? "Connexions Internet coupées" + until : "Échec : " + r.Message);
        if (r.Success) _notify?.Notify(NotificationKind.EmergencyMode, "Mode urgence activé",
            autoRestoreMinutes is { } n ? $"Les connexions Internet sont coupées pour {n} minute(s), puis rétablies automatiquement."
                                        : "Les connexions Internet sont coupées. Utilisez « Restaurer Internet » pour les rétablir.", AppPage.Firewall);
        return r.Success ? OperationResult.Ok(r.Message) : OperationResult.Fail(r.Message);
    }

    public async Task<OperationResult> RestoreAsync(CancellationToken ct = default)
    {
        var r = await _client.SendAsync(PrivilegedOperation.EmergencyRestore, null, ct).ConfigureAwait(false);
        _audit.Write("Mode urgence", r.Success ? "Connexions Internet rétablies" : "Échec : " + r.Message);
        return r.Success ? OperationResult.Ok(r.Message) : OperationResult.Fail(r.Message);
    }
}
