using System.Collections.Concurrent;
using System.Text.Json;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.PrivilegedService.Antivirus;
using SecureWall.PrivilegedService.Firewall;
using SecureWall.PrivilegedService.SystemOperations;

namespace SecureWall.PrivilegedService;

/// <summary>
/// Liste blanche stricte : seule une valeur définie de <see cref="PrivilegedOperation"/> avec exactement les arguments attendus est exécutée.
/// Aucun chemin, aucune commande ni aucun script fournis par le client ne sont jamais exécutés tels quels.
/// </summary>
public sealed class RequestDispatcher
{
    const int MaxArgLength = 8192;

    // Opération → noms d'arguments autorisés (tous les autres sont rejetés).
    static readonly Dictionary<PrivilegedOperation, string[]> AllowedArgs = new()
    {
        [PrivilegedOperation.Ping] = Array.Empty<string>(),
        [PrivilegedOperation.GetServiceInfo] = Array.Empty<string>(),
        [PrivilegedOperation.FirewallSetProfileEnabled] = new[] { "profile", "enabled" },
        [PrivilegedOperation.FirewallCreateRule] = new[] { "spec" },
        [PrivilegedOperation.FirewallUpdateRule] = new[] { "name", "spec" },
        [PrivilegedOperation.FirewallDeleteRule] = new[] { "name" },
        [PrivilegedOperation.FirewallSetRuleEnabled] = new[] { "name", "enabled" },
        [PrivilegedOperation.FirewallBackup] = Array.Empty<string>(),
        [PrivilegedOperation.FirewallListBackups] = Array.Empty<string>(),
        [PrivilegedOperation.FirewallRestoreBackup] = new[] { "name" },
        [PrivilegedOperation.FirewallReadBlockedConnections] = new[] { "since" },
        [PrivilegedOperation.FirewallSetBlockAuditing] = new[] { "enabled" },
        [PrivilegedOperation.EmergencyCutoff] = new[] { "minutes" },
        [PrivilegedOperation.EmergencyRestore] = Array.Empty<string>(),
        [PrivilegedOperation.EmergencyStatus] = Array.Empty<string>(),
        [PrivilegedOperation.DefenderRestoreQuarantined] = new[] { "name" },
        [PrivilegedOperation.DefenderRemoveThreat] = Array.Empty<string>(),
        [PrivilegedOperation.NetworkGetTcpTraffic] = Array.Empty<string>(),
        [PrivilegedOperation.StartupSetEnabled] = new[] { "source", "name", "enabled" },
        [PrivilegedOperation.DnsSetServers] = new[] { "index", "servers" },
        [PrivilegedOperation.DnsResetServers] = new[] { "index" },
        [PrivilegedOperation.DnsFlushCache] = Array.Empty<string>(),
    };

    // Opérations qui modifient le système : sérialisées, journalisées, limitées en fréquence.
    static readonly HashSet<PrivilegedOperation> Mutating = new()
    {
        PrivilegedOperation.FirewallSetProfileEnabled, PrivilegedOperation.FirewallCreateRule, PrivilegedOperation.FirewallUpdateRule,
        PrivilegedOperation.FirewallDeleteRule, PrivilegedOperation.FirewallSetRuleEnabled, PrivilegedOperation.FirewallRestoreBackup,
        PrivilegedOperation.FirewallSetBlockAuditing, PrivilegedOperation.EmergencyCutoff, PrivilegedOperation.EmergencyRestore,
        PrivilegedOperation.DefenderRestoreQuarantined, PrivilegedOperation.DefenderRemoveThreat, PrivilegedOperation.StartupSetEnabled,
        PrivilegedOperation.FirewallBackup, PrivilegedOperation.DnsSetServers, PrivilegedOperation.DnsResetServers, PrivilegedOperation.DnsFlushCache,
    };

    readonly FirewallHandler _firewall;
    readonly DefenderHandler _defender;
    readonly SystemHandler _system;
    readonly DnsHandler _dnsHandler;
    readonly ILogger<RequestDispatcher> _log;
    readonly SemaphoreSlim _mutating = new(1, 1);
    readonly ConcurrentQueue<DateTime> _recentMutations = new();

    public RequestDispatcher(FirewallHandler firewall, DefenderHandler defender, SystemHandler system, DnsHandler dnsHandler, ILogger<RequestDispatcher> log)
    {
        _firewall = firewall; _defender = defender; _system = system; _dnsHandler = dnsHandler; _log = log;
    }

    /// <summary>Validation structurelle seule (testable) : opération connue, arguments exactement ceux attendus, tailles bornées.</summary>
    public static string? ValidateEnvelope(PipeRequest req)
    {
        if (req.Version != PipeRequest.CurrentVersion) return "Version de protocole non prise en charge.";
        if (string.IsNullOrEmpty(req.Id) || req.Id.Length > 64) return "Identifiant de requête invalide.";
        if (!Enum.IsDefined(req.Operation) || !AllowedArgs.TryGetValue(req.Operation, out var allowed)) return "Opération non autorisée.";
        if (req.Args == null) return "Arguments absents.";
        if (req.Args.Count > allowed.Length) return "Arguments inattendus.";
        foreach (var (k, v) in req.Args)
        {
            if (!allowed.Contains(k, StringComparer.Ordinal)) return $"Argument « {k} » non autorisé pour cette opération.";
            if (v == null || v.Length > MaxArgLength) return $"Argument « {k} » invalide.";
        }
        return null;
    }

    public static bool IsKnownOperation(PrivilegedOperation op) => AllowedArgs.ContainsKey(op);

    public async Task<PipeResponse> DispatchAsync(PipeRequest req, string user, CancellationToken ct)
    {
        var error = ValidateEnvelope(req);
        if (error != null)
        {
            _log.LogWarning("Requête rejetée de {User} : {Error}", user, error);
            return PipeResponse.Fail(req.Id ?? "", "rejected", error);
        }

        var mutating = Mutating.Contains(req.Operation);
        if (mutating)
        {
            // « Restaurer Internet » ne peut jamais être bloqué par la limite de fréquence : c'est la sortie de secours, et elle ne fait que
            // retirer les deux règles créées par SecureWall.
            if (req.Operation != PrivilegedOperation.EmergencyRestore)
            {
                var now = DateTime.UtcNow;
                while (_recentMutations.TryPeek(out var t) && (now - t).TotalSeconds > 60) _recentMutations.TryDequeue(out _);
                if (_recentMutations.Count >= 60) return PipeResponse.Fail(req.Id, "rate-limit", "Trop de modifications en peu de temps. Réessayez dans une minute.");
                _recentMutations.Enqueue(now);
            }
            await _mutating.WaitAsync(ct).ConfigureAwait(false);
        }
        try
        {
            if (mutating) _log.LogInformation("{User} → {Op} {Args}", user, req.Operation, Summarize(req));
            return req.Operation switch
            {
                PrivilegedOperation.Ping => PipeResponse.Ok(req.Id, "pong"),
                PrivilegedOperation.GetServiceInfo => PipeResponse.Ok(req.Id, "", JsonSerializer.Serialize(new
                {
                    Version = typeof(RequestDispatcher).Assembly.GetName().Version?.ToString(),
                    Identity = System.Security.Principal.WindowsIdentity.GetCurrent().Name,
                })),
                var op when op is >= PrivilegedOperation.FirewallSetProfileEnabled and <= PrivilegedOperation.FirewallSetBlockAuditing
                    or >= PrivilegedOperation.EmergencyCutoff and <= PrivilegedOperation.EmergencyStatus
                    => await _firewall.HandleAsync(req, ct).ConfigureAwait(false),
                PrivilegedOperation.DefenderRestoreQuarantined or PrivilegedOperation.DefenderRemoveThreat
                    => await _defender.HandleAsync(req, ct).ConfigureAwait(false),
                PrivilegedOperation.NetworkGetTcpTraffic or PrivilegedOperation.StartupSetEnabled
                    => await _system.HandleAsync(req, ct).ConfigureAwait(false),
                PrivilegedOperation.DnsSetServers or PrivilegedOperation.DnsResetServers or PrivilegedOperation.DnsFlushCache
                    => await _dnsHandler.HandleAsync(req, ct).ConfigureAwait(false),
                _ => PipeResponse.Fail(req.Id, "rejected", "Opération non autorisée."),
            };
        }
        catch (OperationCanceledException) { return PipeResponse.Fail(req.Id, "cancelled", "Opération annulée ou expirée."); }
        catch (Exception ex)
        {
            _log.LogError(ex, "Échec de {Op}", req.Operation);
            return PipeResponse.Fail(req.Id, "failed", "L'opération a échoué : " + ex.Message);
        }
        finally { if (mutating) _mutating.Release(); }
    }

    static string Summarize(PipeRequest r) =>
        string.Join(", ", r.Args.Select(a => $"{a.Key}={(a.Value.Length > 80 ? a.Value[..80] + "…" : a.Value)}"));
}
