using System.Net;
using System.Net.Sockets;

namespace SecureWall.Core.Models;

/// <summary>Aide à comprendre une connexion bloquée : service associé au port, nature de l'adresse distante (logique pure, testée).</summary>
public static class BlockedConnectionInsights
{
    static readonly Dictionary<int, string> WellKnownPorts = new()
    {
        [20] = "FTP (données)", [21] = "FTP", [22] = "SSH", [23] = "Telnet", [25] = "SMTP", [53] = "DNS", [67] = "DHCP", [68] = "DHCP",
        [80] = "HTTP", [110] = "POP3", [123] = "NTP (heure)", [135] = "RPC", [137] = "NetBIOS", [138] = "NetBIOS", [139] = "NetBIOS",
        [143] = "IMAP", [161] = "SNMP", [389] = "LDAP", [443] = "HTTPS", [445] = "SMB (partages Windows)", [465] = "SMTPS", [514] = "Syslog",
        [587] = "SMTP (envoi)", [636] = "LDAPS", [993] = "IMAPS", [995] = "POP3S", [1433] = "SQL Server", [1900] = "UPnP/SSDP",
        [3306] = "MySQL", [3389] = "Bureau à distance (RDP)", [5353] = "mDNS", [5355] = "LLMNR", [5432] = "PostgreSQL",
        [5900] = "VNC", [5985] = "WinRM", [5986] = "WinRM (TLS)", [8080] = "HTTP (alternatif)", [8443] = "HTTPS (alternatif)",
    };

    /// <summary>Nom du service habituellement associé au port, ou chaîne vide.</summary>
    public static string ServiceName(int port) => WellKnownPorts.TryGetValue(port, out var n) ? n : "";

    public static string PortText(int port)
    {
        if (port <= 0) return "—";
        var s = ServiceName(port);
        return s.Length == 0 ? port.ToString() : $"{port} · {s}";
    }

    public static string AddressKind(string address)
    {
        if (string.IsNullOrWhiteSpace(address)) return "Inconnue";
        if (!IPAddress.TryParse(address.Trim(), out var ip)) return "Inconnue";
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return "Cet ordinateur (boucle locale)";

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            if (b[0] == 0) return "Non spécifiée";
            if (b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168)) return "Réseau local (privée)";
            if (b[0] == 100 && b[1] is >= 64 and <= 127) return "Réseau d'opérateur (CGNAT)";
            if (b[0] == 169 && b[1] == 254) return "Liaison locale (sans DHCP)";
            if (b[0] >= 224 && b[0] <= 239) return "Multicast (diffusion groupée)";
            if (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) return "Diffusion locale";
            if (b[0] >= 240) return "Réservée";
            return "Internet";
        }

        if (ip.IsIPv6LinkLocal) return "Liaison locale";
        if (ip.IsIPv6Multicast) return "Multicast (diffusion groupée)";
        if (ip.IsIPv6SiteLocal || (ip.GetAddressBytes()[0] & 0xFE) == 0xFC) return "Réseau local (privée)";
        if (ip.Equals(IPAddress.IPv6None) || ip.Equals(IPAddress.IPv6Any)) return "Non spécifiée";
        return "Internet";
    }

    /// <summary>Phrase qui explique ce qui a été bloqué, en langage courant.</summary>
    public static string Explain(string application, string direction, string protocol, string address, int port)
    {
        var app = string.IsNullOrWhiteSpace(application) ? "Un programme ou service système" : application;
        var service = ServiceName(port);
        var target = port > 0 ? $"{address} (port {port}{(service.Length > 0 ? ", " + service : "")})" : address;
        return direction == "Entrante"
            ? $"Le pare-feu a refusé une connexion {protocol} entrante : {target} tentait de joindre {app} sur cet ordinateur."
            : $"Le pare-feu a refusé une connexion {protocol} sortante : {app} tentait de joindre {target}.";
    }
}
