using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Models;
using SecureWall.Core.Validation;

namespace SecureWall.Security.Firewall;

public sealed class BaselineRuleSet
{
    public string Format { get; set; } = "";
    public int Version { get; set; }
    public string Name { get; set; } = "";
    public string Published { get; set; } = "";
    public string Source { get; set; } = "";
    public List<FirewallRuleSpec> Rules { get; set; } = new();
}

public enum BaselineStatus { New, AlreadyPresent }

public sealed class BaselineRuleItem
{
    public FirewallRuleSpec Spec { get; init; } = new();
    public BaselineStatus Status { get; init; }
    public bool IsSelected { get; set; }
    public string StatusText => Status == BaselineStatus.New ? "À ajouter" : "Déjà présente";
    public string DirectionText => Spec.Direction == FirewallDirection.Inbound ? "Entrante" : "Sortante";
    public string Summary => $"{DirectionText} · {Spec.Protocol} · ports {(string.IsNullOrEmpty(Spec.LocalPorts) ? Spec.RemotePorts : Spec.LocalPorts)}"
        + (string.IsNullOrEmpty(Spec.RemoteAddresses) ? "" : $" · {Spec.RemoteAddresses}");
}

/// <summary>
/// Jeu de règles de base du pare-feu. Le fichier (intégré à l'application, ou téléchargé à la demande depuis un hôte autorisé)
/// est une enveloppe signée en ECDSA P-256 : rien n'est affiché ni appliqué si la signature ne correspond pas à la clé publique intégrée.
/// Les règles ne sont créées qu'après aperçu et confirmation, via le service privilégié (avec sauvegarde préalable).
/// </summary>
public sealed class BaselineRulesService
{
    /// <summary>Clé publique (SubjectPublicKeyInfo, base64) correspondant à la clé privée du mainteneur (outil swtool).</summary>
    public const string PublicKeyBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFyXMdd/gcC44W2S3th09wyIoAwKRr9+U0436ebBqh8Gx27IVQr6HOO/WyW8psS+2qDgwS16MW+AMntApRQNN/Q==";
    public const string CacheKey = "baseline.cached";
    public const string AppliedKey = "baseline.applied";
    const int MaxBytes = 256 * 1024;
    const int MaxRules = 100;

    static readonly string[] AllowedHosts = { "raw.githubusercontent.com" };
    static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, Converters = { new JsonStringEnumConverter() } };

    readonly ISecurityStore _store;
    readonly IFirewallRuleService _rules;
    readonly IAuditLog _audit;
    readonly Func<Uri, CancellationToken, Task<string>> _fetch;
    readonly string _publicKey;

    public BaselineRulesService(ISecurityStore store, IFirewallRuleService rules, IAuditLog audit,
        Func<Uri, CancellationToken, Task<string>>? fetch = null, string? publicKey = null)
    {
        _store = store; _rules = rules; _audit = audit;
        _fetch = fetch ?? DefaultFetchAsync;
        _publicKey = publicKey ?? PublicKeyBase64;
    }

    // ---------- Vérification ----------
    public static bool IsAllowedUrl(string url, out Uri? uri)
    {
        uri = null;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return false;
        if (u.Scheme != Uri.UriSchemeHttps || !u.IsDefaultPort) return false;
        if (!AllowedHosts.Contains(u.Host, StringComparer.OrdinalIgnoreCase)) return false;
        uri = u;
        return true;
    }

    /// <summary>Vérifie la signature puis valide chaque règle. Retourne null et un message en cas d'échec.</summary>
    public static BaselineRuleSet? Verify(string envelopeJson, string publicKeyBase64, out string error)
    {
        error = "";
        try
        {
            if (envelopeJson.Length > MaxBytes) { error = "Fichier trop volumineux."; return null; }
            using var doc = JsonDocument.Parse(envelopeJson);
            var payload = doc.RootElement.GetProperty("Payload").GetString() ?? "";
            var sig = Convert.FromBase64String(doc.RootElement.GetProperty("Signature").GetString() ?? "");

            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);
            if (!key.VerifyData(Encoding.UTF8.GetBytes(payload), sig, HashAlgorithmName.SHA256))
            { error = "Signature invalide : le fichier n'a pas été produit par l'éditeur de SecureWall ou a été modifié."; return null; }

            var set = JsonSerializer.Deserialize<BaselineRuleSet>(payload, Json);
            if (set is null || set.Format != "SecureWall.Baseline") { error = "Format de jeu de règles inconnu."; return null; }
            if (set.Rules.Count == 0 || set.Rules.Count > MaxRules) { error = "Nombre de règles invalide."; return null; }
            foreach (var r in set.Rules)
            {
                var errs = RuleValidator.Validate(r);
                if (errs.Count > 0) { error = $"Règle invalide « {r.Name} » : {errs[0]}"; return null; }
                if (!r.Name.StartsWith("SecureWall Base - ", StringComparison.Ordinal)) { error = $"Nom de règle non conforme : {r.Name}"; return null; }
                if (r.Action == FirewallAction.Allow && r.Direction == FirewallDirection.Inbound) { error = $"La règle « {r.Name} » ouvrirait un accès entrant : refusée."; return null; }
                r.Program = "";   // un jeu de règles de base ne cible jamais un programme précis
            }
            return set;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or CryptographicException or KeyNotFoundException or InvalidOperationException)
        {
            error = "Fichier illisible ou corrompu.";
            return null;
        }
    }

    // ---------- Sources ----------
    public BaselineRuleSet LoadBundled()
    {
        var asm = typeof(BaselineRulesService).Assembly;
        var name = asm.GetManifestResourceNames().Single(n => n.EndsWith("baseline-rules.signed.json", StringComparison.Ordinal));
        using var s = asm.GetManifestResourceStream(name)!;
        using var r = new StreamReader(s, Encoding.UTF8);
        return Verify(r.ReadToEnd(), PublicKeyBase64, out var err) ?? throw new InvalidDataException("Jeu de règles intégré invalide : " + err);
    }

    /// <summary>Jeu le plus récent entre celui intégré et celui téléchargé précédemment (re-vérifié à chaque lecture).</summary>
    public BaselineRuleSet LoadCurrent()
    {
        var bundled = LoadBundled();
        var cached = _store.GetSetting(CacheKey);
        if (cached != null && Verify(cached, _publicKey, out _) is { } set && set.Version > bundled.Version) return set;
        return bundled;
    }

    public int? AppliedVersion => int.TryParse(_store.GetSetting(AppliedKey), out var v) ? v : null;

    /// <summary>Téléchargement sur demande de l'utilisateur uniquement, depuis un hôte autorisé ; rien n'est appliqué.</summary>
    public async Task<(BaselineRuleSet? Set, string Message)> CheckForUpdateAsync(string url, CancellationToken ct = default)
    {
        if (!IsAllowedUrl(url, out var uri))
            return (null, "Adresse refusée : seules les adresses HTTPS de raw.githubusercontent.com sont autorisées.");
        string body;
        try { body = await _fetch(uri!, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { return (null, "Téléchargement impossible : " + ex.Message); }

        var set = Verify(body, _publicKey, out var error);
        if (set == null) return (null, error);
        var current = LoadCurrent();
        if (set.Version <= current.Version) return (null, $"Vous disposez déjà de la dernière version (v{current.Version}).");
        _store.SetSetting(CacheKey, body);
        _audit.Write("Mise à jour des règles de base", $"Version {set.Version} téléchargée et vérifiée (signature valide) depuis {uri!.Host}");
        return (set, $"Nouvelle version disponible : v{set.Version} ({set.Rules.Count} règles).");
    }

    static async Task<string> DefaultFetchAsync(Uri uri, CancellationToken ct)
    {
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(15) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("SecureWall-Security/1.0");
        using var resp = await http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
        if (resp.Content.Headers.ContentLength > MaxBytes) throw new InvalidDataException("Fichier trop volumineux.");
        await using var s = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buf = new byte[MaxBytes + 1];
        var total = 0; int n;
        while ((n = await s.ReadAsync(buf.AsMemory(total, buf.Length - total), ct).ConfigureAwait(false)) > 0) total += n;
        if (total > MaxBytes) throw new InvalidDataException("Fichier trop volumineux.");
        return Encoding.UTF8.GetString(buf, 0, total);
    }

    // ---------- Aperçu et application ----------
    public static IReadOnlyList<BaselineRuleItem> Preview(BaselineRuleSet set, IEnumerable<FirewallRule> existing)
    {
        var names = existing.Select(r => r.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return set.Rules.Select(r => new BaselineRuleItem
        {
            Spec = r, Status = names.Contains(r.Name) ? BaselineStatus.AlreadyPresent : BaselineStatus.New, IsSelected = !names.Contains(r.Name),
        }).ToList();
    }

    public async Task<OperationResult> ApplyAsync(BaselineRuleSet set, IEnumerable<BaselineRuleItem> chosen, CancellationToken ct = default)
    {
        var todo = chosen.Where(i => i.IsSelected && i.Status == BaselineStatus.New).ToList();
        if (todo.Count == 0) return OperationResult.Fail("Aucune règle à ajouter.");
        int ok = 0; var errors = new List<string>();
        foreach (var item in todo)
        {
            var r = await _rules.CreateRuleAsync(item.Spec, ct).ConfigureAwait(false);
            if (r.Success) ok++; else { errors.Add($"{item.Spec.Name} : {r.Message}"); if (r.Message.Contains("service", StringComparison.OrdinalIgnoreCase)) break; }
        }
        if (ok > 0) _store.SetSetting(AppliedKey, set.Version.ToString());
        _audit.Write("Application des règles de base", $"v{set.Version} : {ok}/{todo.Count} règle(s) créée(s)");
        return errors.Count == 0
            ? OperationResult.Ok($"{ok} règle(s) ajoutée(s) (jeu v{set.Version}). Une sauvegarde du pare-feu précède chaque ajout.")
            : OperationResult.Fail($"{ok} règle(s) ajoutée(s), {errors.Count} en échec.\n" + string.Join("\n", errors.Take(4)));
    }
}
