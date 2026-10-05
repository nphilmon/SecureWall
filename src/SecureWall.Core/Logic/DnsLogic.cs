using System.Net;
using System.Net.Sockets;

namespace SecureWall.Core.Logic;

public sealed record DnsPreset(string Name, string Description, string[] Servers)
{
    public string ServersText => string.Join(", ", Servers);
}

/// <summary>Logique pure de la gestion DNS : serveurs prédéfinis, validation et reconnaissance des fournisseurs (testée).</summary>
public static class DnsLogic
{
    public const int MaxServers = 4;

    public static readonly DnsPreset[] Presets =
    {
        new("Cloudflare", "Rapide, ne conserve pas les adresses IP des requêtes.", new[] { "1.1.1.1", "1.0.0.1" }),
        new("Google Public DNS", "Très disponible, journalisation limitée par Google.", new[] { "8.8.8.8", "8.8.4.4" }),
        new("Quad9", "Bloque les domaines malveillants connus.", new[] { "9.9.9.9", "149.112.112.112" }),
        new("Cloudflare (filtre malwares)", "Bloque les domaines malveillants.", new[] { "1.1.1.2", "1.0.0.2" }),
        new("Cloudflare (malwares + contenus adultes)", "Contrôle parental, bloque aussi les contenus pour adultes.", new[] { "1.1.1.3", "1.0.0.3" }),
        new("OpenDNS", "Cisco OpenDNS, filtrage de base.", new[] { "208.67.222.222", "208.67.220.220" }),
    };

    static readonly Dictionary<string, string> KnownProviders = BuildKnown();

    static Dictionary<string, string> BuildKnown()
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Presets) foreach (var s in p.Servers) d[s] = p.Name.Split(" (")[0];
        d["2606:4700:4700::1111"] = "Cloudflare"; d["2606:4700:4700::1001"] = "Cloudflare";
        d["2001:4860:4860::8888"] = "Google Public DNS"; d["2001:4860:4860::8844"] = "Google Public DNS";
        d["2620:fe::fe"] = "Quad9"; d["2620:fe::9"] = "Quad9";
        d["94.140.14.14"] = "AdGuard DNS"; d["94.140.15.15"] = "AdGuard DNS";
        return d;
    }

    /// <summary>Nom du fournisseur public connu, ou chaîne vide.</summary>
    public static string Provider(string address) => KnownProviders.TryGetValue(address.Trim(), out var n) ? n : "";

    public static bool IsPrivateOrLocal(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] is >= 64 and <= 127);
        }
        return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || (ip.GetAddressBytes()[0] & 0xFE) == 0xFC;
    }

    /// <summary>Texte d'état d'un serveur DNS : fournisseur reconnu, routeur/réseau local, ou inconnu.</summary>
    public static string Describe(string address)
    {
        var p = Provider(address);
        if (p.Length > 0) return p;
        if (!IPAddress.TryParse(address.Trim(), out var ip)) return "Adresse invalide";
        if (IPAddress.IsLoopback(ip)) return "Cet ordinateur (résolveur local)";
        return IsPrivateOrLocal(ip) ? "Réseau local (routeur ou box)" : "Serveur non reconnu";
    }

    /// <summary>Les serveurs imposés par un réseau d'entreprise ou la box de l'opérateur sont normaux ; un serveur public inconnu mérite d'être vérifié.</summary>
    public static bool IsUnusual(string address) => Describe(address) == "Serveur non reconnu";

    /// <summary>
    /// Valide la liste saisie (IPv4 uniquement, 1 à 4 adresses distinctes, séparées par virgule, point-virgule ou espace).
    /// Refuse adresse non spécifiée, multicast, diffusion et plages réservées.
    /// </summary>
    public static bool TryParseServers(string? text, out List<string> servers, out string error)
    {
        servers = new(); error = "";
        var tokens = (text ?? "").Split(new[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0) { error = "Saisissez au moins une adresse de serveur DNS."; return false; }
        if (tokens.Length > MaxServers) { error = $"{MaxServers} serveurs au maximum."; return false; }
        foreach (var t in tokens)
        {
            if (t.Count(c => c == '.') != 3 || !IPAddress.TryParse(t, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            { error = $"« {t} » n'est pas une adresse IPv4 valide (exemple : 1.1.1.1)."; return false; }
            var b = ip.GetAddressBytes();
            if (b[0] == 0 || b[0] >= 224 || ip.Equals(IPAddress.Broadcast))
            { error = $"« {t} » ne peut pas être un serveur DNS (adresse réservée, de diffusion ou multicast)."; return false; }
            var canonical = ip.ToString();
            if (servers.Contains(canonical)) { error = $"« {canonical} » est saisie deux fois."; return false; }
            servers.Add(canonical);
        }
        return true;
    }
}
