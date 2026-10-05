using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SecureWall.Core.Interfaces;
using SecureWall.Security.Firewall;

namespace SecureWall.Security.Updates;

public sealed class UpdateManifest
{
    public string Format { get; set; } = "";
    public string Version { get; set; } = "";
    public string Published { get; set; } = "";
    public string Notes { get; set; } = "";
    public string InstallerUrl { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public long Size { get; set; }

    public Version ParsedVersion => System.Version.Parse(Version);
}

public sealed record UpdateCheckResult(UpdateManifest? Manifest, bool UpToDate, string Message)
{
    public bool Available => Manifest != null;
}

/// <summary>
/// Mise à jour de l'application, à la demande de l'utilisateur uniquement. Le manifeste est une enveloppe signée en ECDSA P-256
/// (même clé que le jeu de règles de base) ; l'installateur n'est téléchargé que depuis GitHub, sa taille et son empreinte SHA-256
/// sont imposées par le manifeste signé, et il n'est jamais lancé sans confirmation de l'utilisateur.
/// </summary>
public sealed class AppUpdateService
{
    public const string ManifestFormat = "SecureWall.Update";
    public const int MaxManifestBytes = 64 * 1024;
    public const long MaxInstallerBytes = 300L * 1024 * 1024;
    const int MaxRedirects = 5;

    static readonly Regex Sha256Hex = new("^[0-9a-fA-F]{64}$", RegexOptions.Compiled);
    static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };

    readonly Func<Uri, CancellationToken, Task<HttpResponseMessage>> _get;
    readonly IAuditLog _audit;
    readonly string _publicKey;

    /// <summary>Version en cours d'exécution.</summary>
    public Version Current { get; }

    public AppUpdateService(IAuditLog audit, Version? current = null, Func<Uri, CancellationToken, Task<HttpResponseMessage>>? get = null, string? publicKey = null)
    {
        _audit = audit;
        Current = current ?? typeof(AppUpdateService).Assembly.GetName().Version ?? new Version(1, 0, 0);
        _get = get ?? DefaultGetAsync;
        _publicKey = publicKey ?? BaselineRulesService.PublicKeyBase64;
    }

    // ---------- Adresses autorisées ----------
    static bool IsHttps(Uri u) => u.Scheme == Uri.UriSchemeHttps && u.IsDefaultPort && string.IsNullOrEmpty(u.UserInfo);

    /// <summary>Le manifeste ne peut venir que de raw.githubusercontent.com.</summary>
    public static bool IsAllowedManifestUrl(string url, out Uri? uri)
    {
        uri = null;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || !IsHttps(u)) return false;
        if (!u.Host.Equals("raw.githubusercontent.com", StringComparison.OrdinalIgnoreCase)) return false;
        uri = u;
        return true;
    }

    /// <summary>L'installateur ne peut venir que de GitHub (pages de publication et leurs redirections vers *.githubusercontent.com).</summary>
    public static bool IsAllowedInstallerUrl(Uri u)
    {
        if (!IsHttps(u)) return false;
        var h = u.Host.ToLowerInvariant();
        return h == "github.com" || h == "githubusercontent.com" || h.EndsWith(".githubusercontent.com", StringComparison.Ordinal);
    }

    // ---------- Vérification du manifeste ----------
    public static UpdateManifest? Verify(string envelopeJson, string publicKeyBase64, out string error)
    {
        error = "";
        try
        {
            if (envelopeJson.Length > MaxManifestBytes) { error = "Manifeste trop volumineux."; return null; }
            using var doc = JsonDocument.Parse(envelopeJson);
            var payload = doc.RootElement.GetProperty("Payload").GetString() ?? "";
            var sig = Convert.FromBase64String(doc.RootElement.GetProperty("Signature").GetString() ?? "");

            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);
            if (!key.VerifyData(Encoding.UTF8.GetBytes(payload), sig, HashAlgorithmName.SHA256))
            { error = "Signature invalide : le manifeste n'a pas été produit par l'éditeur de SecureWall ou a été modifié."; return null; }

            var m = JsonSerializer.Deserialize<UpdateManifest>(payload, Json);
            if (m is null || m.Format != ManifestFormat) { error = "Format de manifeste inconnu."; return null; }
            if (!System.Version.TryParse(m.Version, out var v) || v.Major < 0 || v.Minor < 0 || v.Build < 0) { error = "Numéro de version invalide."; return null; }
            m.Version = $"{v.Major}.{v.Minor}.{v.Build}";
            if (!Sha256Hex.IsMatch(m.Sha256)) { error = "Empreinte SHA-256 invalide."; return null; }
            if (m.Size is < 1 or > MaxInstallerBytes) { error = "Taille de l'installateur invalide."; return null; }
            if (!Uri.TryCreate(m.InstallerUrl, UriKind.Absolute, out var iu) || !IsAllowedInstallerUrl(iu))
            { error = "Adresse de l'installateur refusée : seules les adresses HTTPS de GitHub sont autorisées."; return null; }
            if (m.Notes.Length > 4000) { error = "Notes de version trop longues."; return null; }
            return m;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or CryptographicException or KeyNotFoundException or InvalidOperationException)
        {
            error = "Manifeste illisible ou corrompu.";
            return null;
        }
    }

    // ---------- Recherche ----------
    public async Task<UpdateCheckResult> CheckAsync(string url, CancellationToken ct = default)
    {
        if (!IsAllowedManifestUrl(url, out var uri))
            return new(null, false, "Adresse refusée : seules les adresses HTTPS de raw.githubusercontent.com sont autorisées.");
        string body;
        try
        {
            using var resp = await _get(uri!, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
            body = await ReadTextLimitedAsync(resp, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { return new(null, false, "Recherche impossible : " + ex.Message); }

        var m = Verify(body, _publicKey, out var error);
        if (m == null) return new(null, false, error);
        if (m.ParsedVersion <= Current)
            return new(null, true, $"SecureWall est à jour (version {Current.ToString(3)}).");
        _audit.Write("Mise à jour de l'application", $"Version {m.Version} disponible (manifeste signé vérifié)");
        return new(m, false, $"Nouvelle version disponible : {m.Version}.");
    }

    // ---------- Téléchargement ----------
    /// <summary>Télécharge l'installateur, vérifie taille et SHA-256 puis retourne son chemin. Le fichier est supprimé en cas d'échec.</summary>
    public async Task<(string? Path, string Message)> DownloadAsync(UpdateManifest m, string destinationDir, IProgress<double>? progress = null, CancellationToken ct = default)
    {
        Directory.CreateDirectory(destinationDir);
        var final = Path.Combine(destinationDir, $"SecureWall-Setup-{m.Version}.exe");
        var part = final + ".part";
        try
        {
            var uri = new Uri(m.InstallerUrl);
            HttpResponseMessage? resp = null;
            for (var hop = 0; ; hop++)
            {
                resp?.Dispose();
                resp = await _get(uri, ct).ConfigureAwait(false);
                if ((int)resp.StatusCode is >= 300 and < 400 && resp.Headers.Location is { } loc)
                {
                    if (hop >= MaxRedirects) return (null, "Trop de redirections.");
                    uri = loc.IsAbsoluteUri ? loc : new Uri(uri, loc);
                    if (!IsAllowedInstallerUrl(uri)) return (null, "Redirection refusée vers un hôte non autorisé : " + uri.Host);
                    continue;
                }
                break;
            }
            using (resp)
            {
                resp.EnsureSuccessStatusCode();
                if (resp.Content.Headers.ContentLength is { } len && len != m.Size)
                    return (null, "La taille annoncée par le serveur ne correspond pas au manifeste signé : téléchargement refusé.");

                using var sha = SHA256.Create();
                long total = 0;
                await using (var src = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
                await using (var dst = new FileStream(part, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    var buf = new byte[81920]; int n;
                    while ((n = await src.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
                    {
                        total += n;
                        if (total > m.Size) return Fail(part, "Le fichier reçu dépasse la taille annoncée : téléchargement annulé.");
                        sha.TransformBlock(buf, 0, n, null, 0);
                        await dst.WriteAsync(buf.AsMemory(0, n), ct).ConfigureAwait(false);
                        progress?.Report((double)total / m.Size);
                    }
                }
                sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                if (total != m.Size) return Fail(part, "Téléchargement incomplet.");
                if (!Convert.ToHexString(sha.Hash!).Equals(m.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    _audit.Write("Mise à jour de l'application", $"Version {m.Version} : empreinte SHA-256 incorrecte, fichier supprimé");
                    return Fail(part, "Empreinte SHA-256 incorrecte : le fichier a été altéré ou est corrompu, il a été supprimé.");
                }
            }
            File.Move(part, final, overwrite: true);
            _audit.Write("Mise à jour de l'application", $"Version {m.Version} téléchargée et vérifiée (SHA-256)");
            return (final, "Installateur téléchargé et vérifié.");
        }
        catch (OperationCanceledException) { TryDelete(part); throw; }
        catch (Exception ex) { TryDelete(part); return (null, "Téléchargement impossible : " + ex.Message); }
    }

    /// <summary>
    /// Dernière vérification avant lancement. Ouvre l'installateur en lecture seule avec un verrou (tant que le flux retourné est ouvert, aucun autre
    /// processus ne peut l'écrire, le renommer ni le supprimer) puis contrôle taille et SHA-256 SUR CE MÊME FLUX. Le dossier de téléchargement
    /// appartient à l'utilisateur : sans ce verrou, un autre programme de la session pourrait remplacer le fichier entre la vérification et
    /// l'exécution avec élévation. L'appelant garde le flux ouvert jusqu'à la fin de l'installation.
    /// </summary>
    public (FileStream? Lock, string Message) OpenVerified(string path, UpdateManifest m)
    {
        FileStream? fs = null;
        try
        {
            fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (fs.Length != m.Size) { fs.Dispose(); return (null, "L'installateur a changé depuis son téléchargement (taille différente) : lancement refusé."); }
            var hash = Convert.ToHexString(SHA256.HashData(fs));
            if (!hash.Equals(m.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                fs.Dispose();
                _audit.Write("Mise à jour de l'application", $"Version {m.Version} : l'installateur a été modifié après vérification, lancement refusé");
                return (null, "L'installateur a été modifié après son téléchargement (empreinte différente) : lancement refusé.");
            }
            fs.Position = 0;
            return (fs, "");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            fs?.Dispose();
            return (null, "Installateur inaccessible ou déjà utilisé par un autre programme : " + ex.Message);
        }
    }

    static (string?, string) Fail(string part, string message) { TryDelete(part); return (null, message); }
    static void TryDelete(string path) { try { if (File.Exists(path)) File.Delete(path); } catch { /* ignoré */ } }

    static async Task<string> ReadTextLimitedAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        if (resp.Content.Headers.ContentLength > MaxManifestBytes) throw new InvalidDataException("Manifeste trop volumineux.");
        await using var s = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buf = new byte[MaxManifestBytes + 1];
        var total = 0; int n;
        while (total < buf.Length && (n = await s.ReadAsync(buf.AsMemory(total, buf.Length - total), ct).ConfigureAwait(false)) > 0) total += n;
        if (total > MaxManifestBytes) throw new InvalidDataException("Manifeste trop volumineux.");
        return Encoding.UTF8.GetString(buf, 0, total);
    }

    static readonly HttpClient Http = CreateClient();

    static HttpClient CreateClient()
    {
        // Pas de redirection automatique : chaque saut est vérifié contre la liste des hôtes autorisés.
        var c = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromMinutes(10) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("SecureWall-Updater/1.0");
        return c;
    }

    static Task<HttpResponseMessage> DefaultGetAsync(Uri uri, CancellationToken ct) => Http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct);
}
