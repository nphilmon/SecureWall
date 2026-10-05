using System.Text.Json;
using System.Text.Json.Serialization;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Models;
using SecureWall.Core.Validation;
using SecureWall.Infrastructure.Windows;
using SecureWall.Security.Firewall;

namespace SecureWall.PrivilegedService.Firewall;

public sealed class FirewallHandler
{
    static readonly JsonSerializerOptions Json = new() { Converters = { new JsonStringEnumConverter() } };

    readonly IFirewallPolicy _policy;
    readonly IFirewallBackup _backups;
    readonly EmergencyExecutor _emergency;

    public FirewallHandler(IFirewallPolicy policy, IFirewallBackup backups, EmergencyExecutor emergency)
    {
        _policy = policy; _backups = backups; _emergency = emergency;
    }

    public async Task<PipeResponse> HandleAsync(PipeRequest req, CancellationToken ct)
    {
        var id = req.Id;
        var a = req.Args;
        switch (req.Operation)
        {
            case PrivilegedOperation.FirewallSetProfileEnabled:
            {
                if (!int.TryParse(a.GetValueOrDefault("profile"), out var p) || p is not (1 or 2 or 4)) return Bad(id, "Profil invalide.");
                if (!TryBool(a.GetValueOrDefault("enabled"), out var enabled)) return Bad(id, "Valeur « enabled » invalide.");
                var b = await _backups.BackupAsync("auto", ct).ConfigureAwait(false);
                if (!b.Ok) return PipeResponse.Fail(id, "backup-failed", b.Message);
                _policy.SetProfileEnabled((FirewallProfiles)p, enabled);
                return PipeResponse.Ok(id, "Profil mis à jour.");
            }

            case PrivilegedOperation.FirewallCreateRule:
            {
                if (!TryParseSpec(a.GetValueOrDefault("spec"), out var spec, out var err)) return Bad(id, err);
                if (IsReserved(spec.Name)) return Bad(id, "Ce nom est réservé au mode urgence de SecureWall.");
                if (_policy.FindRule(spec.Name) != null) return Bad(id, "Une règle porte déjà ce nom.");
                var pe = CheckProgram(spec);
                if (pe != null) return Bad(id, pe);
                var b = await _backups.BackupAsync("auto", ct).ConfigureAwait(false);
                if (!b.Ok) return PipeResponse.Fail(id, "backup-failed", b.Message);
                _policy.AddRule(spec, RuleGroups.SecureWall);
                return PipeResponse.Ok(id, "Règle créée.");
            }

            case PrivilegedOperation.FirewallUpdateRule:
            {
                var name = a.GetValueOrDefault("name") ?? "";
                if (!TryParseSpec(a.GetValueOrDefault("spec"), out var spec, out var err)) return Bad(id, err);
                var guard = GuardExisting(name);
                if (guard != null) return Bad(id, guard);
                if (IsReserved(spec.Name)) return Bad(id, "Ce nom est réservé au mode urgence de SecureWall.");
                if (!string.Equals(name, spec.Name, StringComparison.OrdinalIgnoreCase) && _policy.FindRule(spec.Name) != null)
                    return Bad(id, "Une autre règle porte déjà ce nom.");
                var pe = CheckProgram(spec);
                if (pe != null) return Bad(id, pe);
                var b = await _backups.BackupAsync("auto", ct).ConfigureAwait(false);
                if (!b.Ok) return PipeResponse.Fail(id, "backup-failed", b.Message);
                _policy.UpdateRule(name, spec);
                return PipeResponse.Ok(id, "Règle modifiée.");
            }

            case PrivilegedOperation.FirewallDeleteRule:
            {
                var name = a.GetValueOrDefault("name") ?? "";
                var guard = GuardExisting(name);
                if (guard != null) return Bad(id, guard);
                var b = await _backups.BackupAsync("auto", ct).ConfigureAwait(false);
                if (!b.Ok) return PipeResponse.Fail(id, "backup-failed", b.Message);
                _policy.RemoveRule(name);
                return PipeResponse.Ok(id, "Règle supprimée.");
            }

            case PrivilegedOperation.FirewallSetRuleEnabled:
            {
                var name = a.GetValueOrDefault("name") ?? "";
                if (!TryBool(a.GetValueOrDefault("enabled"), out var enabled)) return Bad(id, "Valeur « enabled » invalide.");
                var guard = GuardExisting(name);
                if (guard != null) return Bad(id, guard);
                _policy.SetRuleEnabled(name, enabled);
                return PipeResponse.Ok(id);
            }

            case PrivilegedOperation.FirewallBackup:
            {
                var b = await _backups.BackupAsync("manuel", ct).ConfigureAwait(false);
                return b.Ok ? PipeResponse.Ok(id, "Sauvegarde créée.", b.Name) : PipeResponse.Fail(id, "backup-failed", b.Message);
            }

            case PrivilegedOperation.FirewallListBackups:
                return PipeResponse.Ok(id, "", JsonSerializer.Serialize(_backups.List()));

            case PrivilegedOperation.FirewallRestoreBackup:
            {
                var r = await _backups.RestoreAsync(a.GetValueOrDefault("name") ?? "", ct).ConfigureAwait(false);
                return r.Ok ? PipeResponse.Ok(id, r.Message) : PipeResponse.Fail(id, "restore-failed", r.Message);
            }

            case PrivilegedOperation.FirewallReadBlockedConnections:
            {
                if (!DateTime.TryParse(a.GetValueOrDefault("since"), null, System.Globalization.DateTimeStyles.RoundtripKind, out var since)) return Bad(id, "Date invalide.");
                var earliest = DateTime.UtcNow.AddDays(-1);
                if (since.ToUniversalTime() < earliest) since = earliest;
                var report = await BlockedConnectionReader.ReadAsync(since, ct).ConfigureAwait(false);
                return PipeResponse.Ok(id, "", JsonSerializer.Serialize(report));
            }

            case PrivilegedOperation.FirewallSetBlockAuditing:
            {
                if (!TryBool(a.GetValueOrDefault("enabled"), out var enabled)) return Bad(id, "Valeur « enabled » invalide.");
                var r = await BlockedConnectionReader.SetAuditingAsync(enabled, ct).ConfigureAwait(false);
                return r.Ok ? PipeResponse.Ok(id, r.Message) : PipeResponse.Fail(id, "failed", r.Message);
            }

            case PrivilegedOperation.EmergencyStatus:
                return PipeResponse.Ok(id, "", JsonSerializer.Serialize(_emergency.GetState()));

            case PrivilegedOperation.EmergencyCutoff:
            {
                int? minutes = null;
                if (a.TryGetValue("minutes", out var mText))
                {
                    if (!int.TryParse(mText, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var m)) return Bad(id, "Durée invalide.");
                    minutes = m;
                }
                var r = await _emergency.CutoffAsync(ct, minutes).ConfigureAwait(false);
                return r.Ok ? PipeResponse.Ok(id, r.Message) : PipeResponse.Fail(id, "failed", r.Message);
            }

            case PrivilegedOperation.EmergencyRestore:
            {
                var r = _emergency.Restore();
                return PipeResponse.Ok(id, r.Message);
            }
        }
        return Bad(id, "Opération non prise en charge.");
    }

    static PipeResponse Bad(string id, string msg) => PipeResponse.Fail(id, "invalid", msg);

    static bool TryBool(string? v, out bool b)
    {
        b = v == "1";
        return v is "0" or "1";
    }

    static bool IsReserved(string name) => name.StartsWith("SecureWall Emergency", StringComparison.OrdinalIgnoreCase);

    static bool TryParseSpec(string? json, out FirewallRuleSpec spec, out string error)
    {
        spec = new(); error = "";
        if (string.IsNullOrWhiteSpace(json)) { error = "Description de règle absente."; return false; }
        try { spec = JsonSerializer.Deserialize<FirewallRuleSpec>(json, Json) ?? new(); }
        catch (JsonException) { error = "Description de règle illisible."; return false; }
        var errors = RuleValidator.Validate(spec);
        if (errors.Count > 0) { error = string.Join(" ", errors); return false; }
        return true;
    }

    static string? CheckProgram(FirewallRuleSpec spec)
    {
        if (string.IsNullOrEmpty(spec.Program)) return null;
        return File.Exists(spec.Program) ? null : "Le programme indiqué n'existe pas.";
    }

    /// <summary>La règle doit exister, porter un nom unique (l'API Windows adresse les règles par nom) et ne pas appartenir au mode urgence.</summary>
    string? GuardExisting(string name)
    {
        if (!RuleValidator.IsSafeName(name)) return "Nom de règle invalide.";
        var matches = _policy.GetRules().Where(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase)).ToList();
        if (matches.Count == 0) return "Règle introuvable.";
        if (matches.Count > 1) return "Plusieurs règles portent ce nom : modifiez-la depuis Windows Defender Firewall avec fonctions avancées de sécurité.";
        if (matches[0].Group == RuleGroups.Emergency) return "Cette règle est gérée par le mode urgence (utilisez « Restaurer Internet »).";
        return null;
    }
}
