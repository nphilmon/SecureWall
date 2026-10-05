using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Security.DnsConfig;

namespace SecureWall.PrivilegedService.SystemOperations;

/// <summary>Gestion DNS : changer ou réinitialiser les serveurs d'une carte active, vider le cache. Tout est revalidé côté service.</summary>
public sealed class DnsHandler
{
    readonly DnsConfigurator _dns;
    public DnsHandler(DnsConfigurator dns) => _dns = dns;

    public async Task<PipeResponse> HandleAsync(PipeRequest req, CancellationToken ct)
    {
        var a = req.Args;
        (bool Ok, string Message) r;
        switch (req.Operation)
        {
            case PrivilegedOperation.DnsSetServers: r = _dns.Set(a.GetValueOrDefault("index"), a.GetValueOrDefault("servers")); break;
            case PrivilegedOperation.DnsResetServers: r = _dns.Reset(a.GetValueOrDefault("index")); break;
            case PrivilegedOperation.DnsFlushCache: r = await _dns.FlushAsync(ct).ConfigureAwait(false); break;
            default: return PipeResponse.Fail(req.Id, "invalid", "Opération non prise en charge.");
        }
        return r.Ok ? PipeResponse.Ok(req.Id, r.Message) : PipeResponse.Fail(req.Id, "failed", r.Message);
    }
}
