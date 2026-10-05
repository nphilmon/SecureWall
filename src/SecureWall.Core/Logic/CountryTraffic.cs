using System.Globalization;
using SecureWall.Core.Models;

namespace SecureWall.Core.Logic;

public sealed record CountryApp(string Application, int Connections);
public sealed record CountryAddress(string Address, string Ports, int Connections, string Applications);

public sealed record CountryStat(string Code, string Name, int Connections, int Addresses, IReadOnlyList<CountryApp> Apps, IReadOnlyList<CountryAddress> TopAddresses)
{
    public bool IsReal => Code is not (CountryTraffic.LocalCode or CountryTraffic.UnknownCode);
}

/// <summary>Regroupement du trafic par pays (logique pure, testée).</summary>
public static class CountryTraffic
{
    public const string LocalCode = "LOCAL";
    public const string UnknownCode = "??";

    public static string NameOf(string code)
    {
        if (code == LocalCode) return "Réseau local";
        if (code == UnknownCode || string.IsNullOrWhiteSpace(code)) return "Pays inconnu";
        if (code.Equals("XK", StringComparison.OrdinalIgnoreCase)) return "Kosovo";
        try { return new RegionInfo(code.ToUpperInvariant()).DisplayName; }
        catch (ArgumentException) { return code.ToUpperInvariant(); }
    }

    /// <summary>
    /// Regroupe le trafic par pays. Les adresses non publiques (réseau local, boucle, multicast…) vont dans « Réseau local » ;
    /// les adresses publiques sans pays connu vont dans « Pays inconnu ».
    /// </summary>
    /// <param name="countryByAddress">Pays (code ISO sur 2 lettres, éventuellement vide) des adresses publiques déjà localisées.</param>
    public static List<CountryStat> Build(IEnumerable<RemoteTraffic> rows, IReadOnlyDictionary<string, string> countryByAddress, Func<string, string>? nameOf = null)
    {
        nameOf ??= NameOf;
        var groups = rows.GroupBy(r => CodeFor(r.Address, countryByAddress));
        var list = new List<CountryStat>();
        foreach (var g in groups)
        {
            var apps = g.GroupBy(r => string.IsNullOrWhiteSpace(r.Application) ? "(inconnu)" : r.Application)
                .Select(a => new CountryApp(a.Key, a.Sum(x => x.Connections))).OrderByDescending(a => a.Connections).ThenBy(a => a.Application).ToList();
            var addrs = g.GroupBy(r => r.Address)
                .Select(a => new CountryAddress(a.Key,
                    string.Join(", ", a.Where(x => x.Port > 0).GroupBy(x => x.Port).OrderByDescending(p => p.Sum(x => x.Connections)).Take(3).Select(p => p.Key)),
                    a.Sum(x => x.Connections),
                    string.Join(", ", a.Select(x => string.IsNullOrWhiteSpace(x.Application) ? "(inconnu)" : x.Application).Distinct().Take(3))))
                .OrderByDescending(a => a.Connections).ThenBy(a => a.Address).ToList();
            list.Add(new CountryStat(g.Key, nameOf(g.Key), g.Sum(r => r.Connections), addrs.Count, apps, addrs));
        }
        return list.OrderByDescending(c => c.Connections).ThenBy(c => c.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
    }

    static string CodeFor(string address, IReadOnlyDictionary<string, string> countryByAddress)
    {
        if (BlockedConnectionInsights.AddressKind(address) != "Internet")
            return BlockedConnectionInsights.AddressKind(address) == "Inconnue" ? UnknownCode : LocalCode;
        return countryByAddress.TryGetValue(NormalizeAddress(address), out var c) && c.Length == 2 ? c.ToUpperInvariant() : UnknownCode;
    }

    /// <summary>Forme canonique d'une adresse (IPv4 mappée en IPv6 ramenée en IPv4, IPv6 en minuscules compressées).</summary>
    public static string NormalizeAddress(string address)
    {
        if (!System.Net.IPAddress.TryParse(address?.Trim(), out var ip)) return address?.Trim() ?? "";
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return ip.ToString();
    }

    /// <summary>Niveau d'intensité 0..1 (échelle logarithmique) pour colorer la carte.</summary>
    public static double Intensity(int connections, int max) =>
        connections <= 0 || max <= 0 ? 0 : max == 1 ? 1 : Math.Clamp(Math.Log(connections + 1) / Math.Log(max + 1), 0.08, 1);
}
