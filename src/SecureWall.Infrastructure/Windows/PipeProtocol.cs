using System.IO.Pipes;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Infrastructure.Configuration;

namespace SecureWall.Infrastructure.Windows;

/// <summary>Trame : 4 octets (longueur, little-endian) + JSON UTF-8. Taille maximale stricte.</summary>
public static class PipeFraming
{
    public const int MaxFrameBytes = 1024 * 1024;
    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = false,
        Converters = { new JsonStringEnumConverter() },
    };

    public static async Task WriteAsync<T>(Stream s, T value, CancellationToken ct)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(value, Json);
        if (payload.Length > MaxFrameBytes) throw new InvalidDataException("Message trop volumineux.");
        var header = BitConverter.GetBytes(payload.Length);
        await s.WriteAsync(header, ct).ConfigureAwait(false);
        await s.WriteAsync(payload, ct).ConfigureAwait(false);
        await s.FlushAsync(ct).ConfigureAwait(false);
    }

    public static async Task<T?> ReadAsync<T>(Stream s, CancellationToken ct)
    {
        var header = new byte[4];
        await ReadExactAsync(s, header, ct).ConfigureAwait(false);
        var len = BitConverter.ToInt32(header);
        if (len <= 0 || len > MaxFrameBytes) throw new InvalidDataException("Taille de message invalide.");
        var buf = new byte[len];
        await ReadExactAsync(s, buf, ct).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(buf, Json);
    }

    static async Task ReadExactAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        var read = 0;
        while (read < buf.Length)
        {
            var n = await s.ReadAsync(buf.AsMemory(read), ct).ConfigureAwait(false);
            if (n == 0) throw new EndOfStreamException();
            read += n;
        }
    }
}

/// <summary>
/// Client du service privilégié (tube nommé local). Il vérifie que le serveur est bien le service installé
/// à côté de l'application avant de lui envoyer quoi que ce soit.
/// </summary>
public sealed class PrivilegedPipeClient : IPrivilegedClient
{
    readonly string _expectedServicePath = Path.Combine(AppContext.BaseDirectory, AppPaths.ServiceExeName);
    readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<bool> IsAvailableAsync(CancellationToken ct = default)
    {
        try
        {
            var r = await SendAsync(PrivilegedOperation.Ping, null, ct).ConfigureAwait(false);
            return r.Success;
        }
        catch { return false; }
    }

    public async Task<PipeResponse> SendAsync(PrivilegedOperation op, Dictionary<string, string>? args = null, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var pipe = new NamedPipeClientStream(".", AppPaths.PipeName, PipeDirection.InOut,
                PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Identification);
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(TimeSpan.FromSeconds(2));
            try { await pipe.ConnectAsync(connectCts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return PipeResponse.Fail("", "unavailable", "Le service privilégié SecureWall ne répond pas. Vérifiez qu'il est installé et démarré.");
            }
            catch (IOException)
            {
                return PipeResponse.Fail("", "unavailable", "Le service privilégié SecureWall est inaccessible.");
            }

            if (!IsExpectedServer(pipe))
                return PipeResponse.Fail("", "untrusted-server", "Le serveur du tube nommé n'est pas le service SecureWall installé : opération annulée.");

            var req = new PipeRequest { Operation = op, Args = args ?? new() };
            using var ioCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            ioCts.CancelAfter(TimeSpan.FromSeconds(60));
            await PipeFraming.WriteAsync(pipe, req, ioCts.Token).ConfigureAwait(false);
            var resp = await PipeFraming.ReadAsync<PipeResponse>(pipe, ioCts.Token).ConfigureAwait(false);
            if (resp == null || resp.Id != req.Id)
                return PipeResponse.Fail(req.Id, "bad-response", "Réponse invalide du service privilégié.");
            return resp;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return PipeResponse.Fail("", "io-error", "Erreur de communication avec le service privilégié : " + ex.Message);
        }
        finally { _gate.Release(); }
    }

    bool IsExpectedServer(NamedPipeClientStream pipe)
    {
#if DEBUG
        // En développement, le service peut tourner depuis son dossier de build (--console).
        if (Environment.GetEnvironmentVariable("SECUREWALL_DEV") == "1") return true;
#endif
        var pid = NativeProcess.GetPipeServerPid(pipe.SafePipeHandle);
        if (pid <= 0) return false;
        // Le processus d'un service SYSTEM n'est pas ouvrable sans élévation : on s'appuie sur le SCM
        // (écriture réservée aux administrateurs) pour l'identité du service installé.
        var (svcPid, svcPath) = NativeProcess.GetServiceInfo(AppPaths.ServiceName);
        return svcPid == pid && string.Equals(svcPath, _expectedServicePath, StringComparison.OrdinalIgnoreCase);
    }
}
