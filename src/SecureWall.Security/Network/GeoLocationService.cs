using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Logic;
using SecureWall.Core.Models;

namespace SecureWall.Security.Network;

public sealed record GeoResult(IReadOnlyDictionary<string, string> Countries, int QueriedOnline, int Remaining, string Warning)
{
    public bool Complete => Remaining == 0 && Warning.Length == 0;
}

/// <summary>
/// Pays des adresses IP publiques contactées. Utilise le service en ligne api.country.is (HTTPS, réponse limitée au pays) uniquement si
/// l'utilisateur l'a autorisé. Seules des adresses PUBLIQUES et jamais vues sont envoyées (ni nom d'application, ni identifiant, ni
/// adresse locale) ; le résultat est mis en cache localement (30 jours, 3 jours si le pays est inconnu) et le nombre de nouvelles
/// adresses interrogées par recherche est plafonné. Hôte fixe : il ne peut pas être redirigé vers un autre serveur.
/// </summary>
public sealed class GeoLocationService
{
    public const string Host = "api.country.is";
    public const int BatchSize = 100;
    public const int MaxNewPerRun = 600;
    public static readonly TimeSpan KnownTtl = TimeSpan.FromDays(30);
    public static readonly TimeSpan UnknownTtl = TimeSpan.FromDays(3);
    const int MaxResponseBytes = 128 * 1024;

    static readonly Regex Code = new("^[A-Za-z]{2}$", RegexOptions.Compiled);

    readonly ISecurityStore _store;
    readonly ISettingsStore _settings;
    readonly Func<string, CancellationToken, Task<string>> _post;
    readonly Func<DateTime> _now;

    public GeoLocationService(ISecurityStore store, ISettingsStore settings, Func<string, CancellationToken, Task<string>>? post = null, Func<DateTime>? now = null)
    {
        _store = store; _settings = settings; _post = post ?? DefaultPostAsync; _now = now ?? (() => DateTime.Now);
    }

    public bool Enabled => _settings.Current.GeoLookupEnabled;

    /// <summary>Adresse publique pouvant être localisée (ni privée, ni locale, ni réservée).</summary>
    public static bool IsLocatable(string address) => BlockedConnectionInsights.AddressKind(address) == "Internet";

    /// <summary>
    /// Retourne le pays des adresses publiques données (ordre = priorité). Les résultats en cache sont toujours utilisés ; le réseau n'est
    /// interrogé que si la localisation en ligne est autorisée.
    /// </summary>
    public async Task<GeoResult> LocateAsync(IEnumerable<string> addresses, CancellationToken ct = default)
    {
        var ordered = addresses.Select(CountryTraffic.NormalizeAddress).Where(IsLocatable).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (ordered.Count == 0) return new(result, 0, 0, "");

        var now = _now();
        var cache = _store.GetGeoCache(ordered);
        var missing = new List<string>();
        foreach (var a in ordered)
        {
            if (cache.TryGetValue(a, out var e))
            {
                result[a] = e.Country;   // même périmé, une valeur connue reste utile tant qu'on ne peut pas la rafraîchir
                var ttl = e.Country.Length == 0 ? UnknownTtl : KnownTtl;
                if (now - e.Checked > ttl) missing.Add(a);
            }
            else missing.Add(a);
        }
        if (missing.Count == 0) return new(result, 0, 0, "");
        if (!Enabled) return new(result, 0, 0, "");

        var toQuery = missing.Take(MaxNewPerRun).ToList();
        var done = 0; var warning = "";
        foreach (var batch in toQuery.Chunk(BatchSize))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var body = await _post(JsonSerializer.Serialize(batch), ct).ConfigureAwait(false);
                var found = Parse(body);
                var entries = new List<GeoCacheEntry>();
                foreach (var a in batch)
                {
                    var c = found.TryGetValue(a, out var cc) ? cc : "";   // absent de la réponse : pays inconnu (adresse anycast…)
                    result[a] = c;
                    entries.Add(new GeoCacheEntry(a, c, now));
                }
                _store.SetGeoCache(entries);
                done += batch.Length;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                warning = "Le service de localisation n'a pas répondu (" + ex.Message + "). Les adresses non localisées seront réessayées plus tard.";
                break;   // un échec n'est jamais mis en cache
            }
            if (done < toQuery.Count) await Task.Delay(150, ct).ConfigureAwait(false);
        }
        return new(result, done, missing.Count - done, warning);
    }

    /// <summary>Lit la réponse du service : tableau d'objets { ip, country }. Toute entrée mal formée est ignorée.</summary>
    public static Dictionary<string, string> Parse(string json)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var doc = JsonDocument.Parse(json);
        var items = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray().ToArray()
                  : doc.RootElement.ValueKind == JsonValueKind.Object ? new[] { doc.RootElement } : Array.Empty<JsonElement>();
        foreach (var it in items)
        {
            if (it.ValueKind != JsonValueKind.Object) continue;
            if (!it.TryGetProperty("ip", out var ipEl) || ipEl.ValueKind != JsonValueKind.String) continue;
            if (!it.TryGetProperty("country", out var cEl) || cEl.ValueKind != JsonValueKind.String) continue;
            var c = cEl.GetString() ?? "";
            if (!Code.IsMatch(c)) continue;
            d[CountryTraffic.NormalizeAddress(ipEl.GetString() ?? "")] = c.ToUpperInvariant();
        }
        return d;
    }

    public int ClearCache() => _store.ClearGeoCache();

    // ---------- Réseau ----------
    static readonly HttpClient Http = CreateClient();

    static HttpClient CreateClient()
    {
        var c = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(12) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("SecureWall-Security/2.0");
        c.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return c;
    }

    static async Task<string> DefaultPostAsync(string jsonBody, CancellationToken ct)
    {
        using var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
        using var resp = await Http.PostAsync("https://" + Host + "/", content, ct).ConfigureAwait(false);
        if ((int)resp.StatusCode == 429) throw new HttpRequestException("trop de requêtes, réessayez dans quelques minutes");
        resp.EnsureSuccessStatusCode();
        if (resp.Content.Headers.ContentLength > MaxResponseBytes) throw new InvalidDataException("réponse trop volumineuse");
        await using var s = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buf = new byte[MaxResponseBytes + 1]; var total = 0; int n;
        while (total < buf.Length && (n = await s.ReadAsync(buf.AsMemory(total, buf.Length - total), ct).ConfigureAwait(false)) > 0) total += n;
        if (total > MaxResponseBytes) throw new InvalidDataException("réponse trop volumineuse");
        return Encoding.UTF8.GetString(buf, 0, total);
    }
}
