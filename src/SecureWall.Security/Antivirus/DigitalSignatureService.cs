using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Models;
using SecureWall.Infrastructure.Windows;

namespace SecureWall.Security.Antivirus;

/// <summary>
/// Vérification Authenticode via Get-AuthenticodeSignature (cmdlet officielle, gère aussi les fichiers signés par catalogue Windows).
/// Les vérifications sont groupées et mises en cache. Une signature absente ou invalide n'est qu'une information, jamais un verdict.
/// </summary>
public sealed class DigitalSignatureService : ISignatureService, IDisposable
{
    readonly ConcurrentDictionary<string, SignatureInfo> _cache = new(StringComparer.OrdinalIgnoreCase);
    readonly ConcurrentDictionary<string, byte> _queued = new(StringComparer.OrdinalIgnoreCase);
    readonly Channel<string> _queue = Channel.CreateUnbounded<string>();
    readonly CancellationTokenSource _cts = new();
    readonly Task _worker;

    public event Action? Updated;

    public DigitalSignatureService() => _worker = Task.Run(WorkerAsync);

    static string KeyOf(string path)
    {
        try { return path + "|" + File.GetLastWriteTimeUtc(path).Ticks; } catch { return path; }
    }

    public SignatureInfo GetOrQueue(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return new SignatureInfo { Status = SignatureStatus.Unknown, Detail = "Chemin indisponible" };
        if (!File.Exists(path)) return new SignatureInfo { Status = SignatureStatus.Unknown, Detail = "Fichier introuvable" };
        var key = KeyOf(path);
        if (_cache.TryGetValue(key, out var info)) return info;
        if (_queued.TryAdd(key, 0)) _queue.Writer.TryWrite(path);
        return SignatureInfo.Pending;
    }

    public async Task<SignatureInfo> VerifyAsync(string path, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return new SignatureInfo { Status = SignatureStatus.Unknown, Detail = "Fichier introuvable" };
        var key = KeyOf(path);
        if (_cache.TryGetValue(key, out var info)) return info;
        var results = await VerifyBatchAsync(new[] { path }, ct).ConfigureAwait(false);
        var r = results.TryGetValue(path, out var v) ? v : new SignatureInfo { Status = SignatureStatus.Unknown, Detail = "Vérification impossible" };
        _cache[key] = r;
        return r;
    }

    async Task WorkerAsync()
    {
        var reader = _queue.Reader;
        try
        {
            while (await reader.WaitToReadAsync(_cts.Token).ConfigureAwait(false))
            {
                await Task.Delay(200, _cts.Token).ConfigureAwait(false);   // laisse s'accumuler un lot
                var batch = new List<string>();
                while (batch.Count < 25 && reader.TryRead(out var p)) batch.Add(p);
                if (batch.Count == 0) continue;
                var results = await VerifyBatchAsync(batch, _cts.Token).ConfigureAwait(false);
                foreach (var p in batch)
                {
                    var key = KeyOf(p);
                    _cache[key] = results.TryGetValue(p, out var info) ? info : new SignatureInfo { Status = SignatureStatus.Unknown, Detail = "Vérification impossible" };
                    _queued.TryRemove(key, out _);
                }
                Updated?.Invoke();
            }
        }
        catch (OperationCanceledException) { /* arrêt */ }
    }

    static async Task<Dictionary<string, SignatureInfo>> VerifyBatchAsync(IReadOnlyList<string> paths, CancellationToken ct)
    {
        var list = string.Join(",", paths.Select(PowerShell.Quote));
        var script = $$"""
            $ErrorActionPreference='SilentlyContinue'
            $paths=@({{list}})
            $r = foreach($p in $paths){
              $s = Get-AuthenticodeSignature -LiteralPath $p
              $c = $s.SignerCertificate
              [pscustomobject]@{ P=$p; S=[string]$s.Status; M=[string]$s.StatusMessage; Sub=$(if($c){$c.Subject}else{''}); T=$(if($c){$c.Thumbprint}else{''}); E=$(if($c){$c.NotAfter.ToString('o')}else{''}) }
            }
            ConvertTo-Json -InputObject @($r) -Compress
            """;
        var result = new Dictionary<string, SignatureInfo>(StringComparer.OrdinalIgnoreCase);
        var run = await PowerShell.RunAsync(script, ct, TimeSpan.FromSeconds(90)).ConfigureAwait(false);
        if (!run.Ok) return result;
        try
        {
            using var doc = JsonDocument.Parse(run.Output.Trim());
            foreach (var e in doc.RootElement.EnumerateArray())
            {
                var path = e.GetProperty("P").GetString() ?? "";
                var status = e.GetProperty("S").GetString() ?? "";
                var subject = e.GetProperty("Sub").GetString() ?? "";
                DateTime? expiry = DateTime.TryParse(e.GetProperty("E").GetString(), out var d) ? d : null;
                result[path] = new SignatureInfo
                {
                    Status = status switch
                    {
                        "Valid" => SignatureStatus.SignedValid,
                        "NotSigned" => SignatureStatus.Unsigned,
                        "HashMismatch" or "NotTrusted" or "Incompatible" => SignatureStatus.Invalid,
                        _ => SignatureStatus.Unknown,
                    },
                    Publisher = ExtractCommonName(subject),
                    Thumbprint = e.GetProperty("T").GetString() ?? "",
                    CertificateExpiry = expiry,
                    Detail = e.GetProperty("M").GetString() ?? "",
                };
            }
        }
        catch { /* sortie inattendue : résultat partiel */ }
        return result;
    }

    internal static string ExtractCommonName(string subject)
    {
        var m = Regex.Match(subject, "CN=(\"(?:[^\"]|\"\")+\"|[^,]+)");
        return m.Success ? m.Groups[1].Value.Trim().Trim('"') : "";
    }

    public void Dispose()
    {
        _cts.Cancel();
        _queue.Writer.TryComplete();
    }
}
