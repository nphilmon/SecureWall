using System.Collections.Concurrent;
using System.Net;

namespace SecureWall.Security.Network;

public enum ReverseDnsStatus { Resolved, NoName, Skipped, Failed }

public sealed record ReverseDnsResult(ReverseDnsStatus Status, string HostName, string Message)
{
    public bool HasName => Status == ReverseDnsStatus.Resolved;
}

/// <summary>
/// Résolution DNS inverse d'une adresse distante, uniquement à la demande de l'utilisateur (la requête part vers le résolveur DNS
/// configuré sur ce PC et révèle l'adresse recherchée). Résultats mis en cache pour la session ; délai d'attente borné.
/// </summary>
public sealed class ReverseDnsService
{
    public const int MaxCacheEntries = 2000;
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(4);

    readonly Func<IPAddress, CancellationToken, Task<string?>> _lookup;
    readonly ConcurrentDictionary<string, ReverseDnsResult> _cache = new();

    public ReverseDnsService(Func<IPAddress, CancellationToken, Task<string?>>? lookup = null) => _lookup = lookup ?? DefaultLookupAsync;

    /// <summary>Adresse qu'il est utile de résoudre : ni vide, ni non spécifiée, ni multicast/diffusion.</summary>
    public static bool IsResolvable(string address, out IPAddress? ip)
    {
        ip = null;
        if (!IPAddress.TryParse(address?.Trim(), out var parsed)) return false;
        if (parsed.IsIPv4MappedToIPv6) parsed = parsed.MapToIPv4();
        if (parsed.Equals(IPAddress.Any) || parsed.Equals(IPAddress.IPv6Any) || parsed.Equals(IPAddress.Broadcast) || parsed.Equals(IPAddress.IPv6None)) return false;
        if (parsed.IsIPv6Multicast || (parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && parsed.GetAddressBytes()[0] is >= 224)) return false;
        ip = parsed;
        return true;
    }

    /// <summary>Résultat déjà connu (sans aucune requête réseau), ou null.</summary>
    public ReverseDnsResult? TryGetCached(string address) =>
        IsResolvable(address, out var ip) && _cache.TryGetValue(ip!.ToString(), out var r) ? r : null;

    public async Task<ReverseDnsResult> ResolveAsync(string address, CancellationToken ct = default)
    {
        if (!IsResolvable(address, out var ip))
            return new(ReverseDnsStatus.Skipped, "", "Cette adresse (vide, non spécifiée ou de diffusion) ne peut pas être résolue.");
        var key = ip!.ToString();
        if (_cache.TryGetValue(key, out var cached)) return cached;

        ReverseDnsResult result;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(Timeout);
            var name = await _lookup(ip, cts.Token).ConfigureAwait(false);
            result = string.IsNullOrWhiteSpace(name) || name.Equals(key, StringComparison.OrdinalIgnoreCase)
                ? new(ReverseDnsStatus.NoName, "", "Aucun nom d'hôte n'est associé à cette adresse.")
                : new(ReverseDnsStatus.Resolved, name.TrimEnd('.'), "");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new(ReverseDnsStatus.Failed, "", "Le serveur DNS n'a pas répondu à temps.");   // non mis en cache : peut réussir plus tard
        }
        catch (System.Net.Sockets.SocketException se) when (se.SocketErrorCode is System.Net.Sockets.SocketError.HostNotFound or System.Net.Sockets.SocketError.NoData)
        {
            result = new(ReverseDnsStatus.NoName, "", "Aucun nom d'hôte n'est associé à cette adresse.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new(ReverseDnsStatus.Failed, "", "Résolution impossible : " + ex.Message);
        }

        if (_cache.Count >= MaxCacheEntries) _cache.Clear();
        _cache[key] = result;
        return result;
    }

    static async Task<string?> DefaultLookupAsync(IPAddress ip, CancellationToken ct) =>
        (await Dns.GetHostEntryAsync(ip.ToString(), ct).ConfigureAwait(false)).HostName;
}
