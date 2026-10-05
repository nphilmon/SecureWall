using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Management;
using Microsoft.Win32;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Logic;
using SecureWall.Core.Models;
using SecureWall.Infrastructure.Windows;

namespace SecureWall.Security.DnsConfig;

public sealed class DnsAdapterInfo
{
    public int Index { get; set; }
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string Kind { get; set; } = "";
    /// <summary>Vrai si les serveurs DNS sont saisis manuellement ; faux s'ils viennent du DHCP (box, routeur, entreprise).</summary>
    public bool IsManual { get; set; }
    public List<string> Servers { get; set; } = new();
    public string ModeText => IsManual ? "Manuel" : "Automatique (DHCP)";
}

/// <summary>Accès au système pour la gestion DNS (remplaçable dans les tests).</summary>
public interface IDnsSystem
{
    IReadOnlyList<DnsAdapterInfo> GetAdapters();
    /// <summary>Code de retour WMI (0 ou 1 = succès). servers = null : retour à la configuration automatique (DHCP).</summary>
    int SetServers(int interfaceIndex, string[]? servers);
    Task<bool> FlushCacheAsync(CancellationToken ct);
}

[SupportedOSPlatform("windows")]
public sealed class WindowsDnsSystem : IDnsSystem
{
    const string InterfacesKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\";

    public IReadOnlyList<DnsAdapterInfo> GetAdapters()
    {
        var list = new List<DnsAdapterInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
            try
            {
                var props = nic.GetIPProperties();
                var index = props.GetIPv4Properties()?.Index ?? props.GetIPv6Properties()?.Index ?? -1;
                if (index < 0) continue;
                var servers = props.DnsAddresses
                    .Where(a => !(a.AddressFamily == AddressFamily.InterNetworkV6 && a.IsIPv6SiteLocal))   // fec0:0:0:ffff::1 : entrées héritées sans intérêt
                    .Select(a => a.ToString()).Distinct().ToList();
                list.Add(new DnsAdapterInfo
                {
                    Index = index, Name = nic.Name, Description = nic.Description,
                    Kind = nic.NetworkInterfaceType switch
                    {
                        NetworkInterfaceType.Wireless80211 => "Wi-Fi",
                        NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet => "Ethernet",
                        var t => t.ToString(),
                    },
                    IsManual = HasStaticDns(nic.Id), Servers = servers,
                });
            }
            catch (NetworkInformationException) { /* carte en cours de changement : ignorée */ }
        }
        return list;
    }

    static bool HasStaticDns(string guid)
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(InterfacesKey + guid);
            return !string.IsNullOrWhiteSpace(k?.GetValue("NameServer") as string);
        }
        catch { return false; }
    }

    public int SetServers(int interfaceIndex, string[]? servers)
    {
        using var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE InterfaceIndex = {interfaceIndex} AND IPEnabled = TRUE");
        foreach (ManagementObject cfg in searcher.Get())
        {
            using (cfg)
            {
                using var args = cfg.GetMethodParameters("SetDNSServerSearchOrder");
                args["DNSServerSearchOrder"] = servers;       // null = DHCP
                using var r = cfg.InvokeMethod("SetDNSServerSearchOrder", args, null);
                return Convert.ToInt32(r?["ReturnValue"] ?? -1);
            }
        }
        return -2;   // carte introuvable ou sans IP
    }

    public async Task<bool> FlushCacheAsync(CancellationToken ct)
    {
        var r = await ProcessRunner.RunAsync(Path.Combine(Environment.SystemDirectory, "ipconfig.exe"), new[] { "/flushdns" }, ct, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
        return r.Ok;
    }
}

/// <summary>Écritures DNS, exécutées par le service privilégié : l'adresse de la carte et chaque serveur sont revalidés ici.</summary>
public sealed class DnsConfigurator
{
    readonly IDnsSystem _sys;
    public DnsConfigurator(IDnsSystem sys) => _sys = sys;

    static string Fmt(DnsAdapterInfo a) => a.Servers.Count == 0 ? "aucun" : string.Join(", ", a.Servers);

    public (bool Ok, string Message) Set(string? indexText, string? serversText)
    {
        if (!TryAdapter(indexText, out var adapter, out var err)) return (false, err);
        if (!DnsLogic.TryParseServers(serversText, out var servers, out var perr)) return (false, perr);
        var code = _sys.SetServers(adapter!.Index, servers.ToArray());
        return code is 0 or 1
            ? (true, $"Serveurs DNS de « {adapter.Name} » : {string.Join(", ", servers)} (précédemment : {Fmt(adapter)}).")
            : (false, WmiMessage(code));
    }

    public (bool Ok, string Message) Reset(string? indexText)
    {
        if (!TryAdapter(indexText, out var adapter, out var err)) return (false, err);
        var code = _sys.SetServers(adapter!.Index, null);
        return code is 0 or 1
            ? (true, $"« {adapter.Name} » utilise de nouveau les serveurs DNS automatiques (précédemment : {Fmt(adapter)}).")
            : (false, WmiMessage(code));
    }

    public async Task<(bool Ok, string Message)> FlushAsync(CancellationToken ct) =>
        await _sys.FlushCacheAsync(ct).ConfigureAwait(false) ? (true, "Cache DNS vidé.") : (false, "Impossible de vider le cache DNS.");

    bool TryAdapter(string? indexText, out DnsAdapterInfo? adapter, out string error)
    {
        adapter = null; error = "";
        if (!int.TryParse(indexText, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var index))
        { error = "Carte réseau invalide."; return false; }
        adapter = _sys.GetAdapters().FirstOrDefault(a => a.Index == index);
        if (adapter == null) { error = "Cette carte réseau n'est plus active ou n'existe pas."; return false; }
        return true;
    }

    static string WmiMessage(int code) => code switch
    {
        -2 => "Carte réseau introuvable ou sans adresse IP.",
        64 => "Méthode non prise en charge par cette carte.",
        65 => "Échec de la modification.",
        66 => "Serveurs DNS refusés par Windows.",
        70 => "Adresse de serveur DNS refusée par Windows.",
        91 => "Accès refusé : droits administrateur requis.",
        _ => $"Windows a refusé la modification (code {code}).",
    };
}

/// <summary>Côté application : lecture directe, écritures via le service privilégié.</summary>
public sealed class DnsService
{
    readonly IDnsSystem _sys;
    readonly IPrivilegedClient _client;
    readonly IAuditLog _audit;

    public DnsService(IDnsSystem sys, IPrivilegedClient client, IAuditLog audit) { _sys = sys; _client = client; _audit = audit; }

    public Task<IReadOnlyList<DnsAdapterInfo>> GetAdaptersAsync(CancellationToken ct = default) => Task.Run(() => _sys.GetAdapters(), ct);

    public async Task<OperationResult> SetServersAsync(DnsAdapterInfo adapter, string serversText, CancellationToken ct = default)
    {
        if (!DnsLogic.TryParseServers(serversText, out var servers, out var error)) return OperationResult.Fail(error);
        var r = await _client.SendAsync(PrivilegedOperation.DnsSetServers,
            new() { ["index"] = adapter.Index.ToString(System.Globalization.CultureInfo.InvariantCulture), ["servers"] = string.Join(",", servers) }, ct).ConfigureAwait(false);
        _audit.Write("Serveurs DNS", r.Success ? r.Message : $"Échec sur « {adapter.Name} » : {r.Message}");
        return r.Success ? OperationResult.Ok(r.Message) : OperationResult.Fail(r.Message);
    }

    public async Task<OperationResult> ResetAsync(DnsAdapterInfo adapter, CancellationToken ct = default)
    {
        var r = await _client.SendAsync(PrivilegedOperation.DnsResetServers,
            new() { ["index"] = adapter.Index.ToString(System.Globalization.CultureInfo.InvariantCulture) }, ct).ConfigureAwait(false);
        _audit.Write("Serveurs DNS", r.Success ? r.Message : $"Échec sur « {adapter.Name} » : {r.Message}");
        return r.Success ? OperationResult.Ok(r.Message) : OperationResult.Fail(r.Message);
    }

    public async Task<OperationResult> FlushCacheAsync(CancellationToken ct = default)
    {
        var r = await _client.SendAsync(PrivilegedOperation.DnsFlushCache, null, ct).ConfigureAwait(false);
        _audit.Write("Cache DNS", r.Success ? "Cache DNS vidé" : "Échec : " + r.Message);
        return r.Success ? OperationResult.Ok(r.Message) : OperationResult.Fail(r.Message);
    }
}

