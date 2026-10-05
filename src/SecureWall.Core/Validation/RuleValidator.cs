using System.Net;
using System.Text.RegularExpressions;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;

namespace SecureWall.Core.Validation;

/// <summary>
/// Validation stricte, partagée par l'interface (retour utilisateur) ET par le service privilégié
/// (défense en profondeur : le service ne fait jamais confiance au client).
/// </summary>
public static class RuleValidator
{
    public const int MaxNameLength = 200;
    public const int MaxListItems = 100;

    static readonly HashSet<string> AddressKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        // « Internet » est un mot-clé SecureWall : Windows le refuse (E_INVALIDARG), ComFirewallPolicy le convertit en plages d'adresses.
        // Any, Intranet, IntranetRemoteAccess et PlayToDevice sont refusés par Windows et donc exclus.
        "*", "LocalSubnet", "DefaultGateway", "DNS", "DHCP", "WINS", "Internet",
    };

    static readonly Regex PortToken = new(@"^(\d{1,5})(-(\d{1,5}))?$", RegexOptions.Compiled);

    public static IReadOnlyList<string> Validate(FirewallRuleSpec s)
    {
        var errors = new List<string>();

        if (!IsSafeName(s.Name)) errors.Add($"Le nom est obligatoire (max. {MaxNameLength} caractères, sans caractères de contrôle ni '|').");
        if (s.Description is { Length: > 500 }) errors.Add("La description dépasse 500 caractères.");
        if (!Enum.IsDefined(s.Direction)) errors.Add("Direction invalide.");
        if (!Enum.IsDefined(s.Action)) errors.Add("Action invalide.");
        if (!Enum.IsDefined(s.Protocol)) errors.Add("Protocole invalide.");
        if (s.Profiles == FirewallProfiles.None || ((int)s.Profiles & ~7) != 0) errors.Add("Sélectionnez au moins un profil réseau valide.");

        if (!string.IsNullOrEmpty(s.Program) && !IsValidProgramPath(s.Program))
            errors.Add("Le programme doit être un chemin absolu valide (sans caractères génériques).");

        var portsAllowed = s.Protocol is FirewallProtocol.Tcp or FirewallProtocol.Udp;
        if (!portsAllowed && (HasValue(s.LocalPorts) || HasValue(s.RemotePorts)))
            errors.Add("Les ports ne sont possibles qu'avec les protocoles TCP ou UDP.");
        if (portsAllowed)
        {
            if (!IsValidPortList(s.LocalPorts)) errors.Add("Port local invalide (exemples : 80, 443, 8000-8100).");
            if (!IsValidPortList(s.RemotePorts)) errors.Add("Port distant invalide (exemples : 80, 443, 8000-8100).");
        }

        if (!IsValidAddressList(s.LocalAddresses)) errors.Add("Adresse IP locale invalide.");
        if (!IsValidAddressList(s.RemoteAddresses)) errors.Add("Adresse IP distante invalide.");

        return errors;
    }

    static bool HasValue(string? v) => !string.IsNullOrWhiteSpace(v) && v.Trim() != "*";

    public static bool IsSafeName(string? name) =>
        !string.IsNullOrWhiteSpace(name) && name.Length <= MaxNameLength && !name.Any(c => char.IsControl(c) || c == '|');

    public static bool IsValidProgramPath(string path)
    {
        if (path.Length > 259 || path.IndexOfAny(new[] { '*', '?', '<', '>', '|', '"' }) >= 0 || path.Any(char.IsControl)) return false;
        if (!Path.IsPathFullyQualified(path)) return false;
        return path.StartsWith(@"\\") is false; // pas de chemins UNC
    }

    public static bool IsValidPortList(string? list)
    {
        if (string.IsNullOrWhiteSpace(list) || list.Trim() == "*") return true;
        var tokens = list.Split(',', StringSplitOptions.TrimEntries);
        if (tokens.Length > MaxListItems) return false;
        foreach (var t in tokens)
        {
            var m = PortToken.Match(t);
            if (!m.Success) return false;
            var a = int.Parse(m.Groups[1].Value);
            if (a is < 1 or > 65535) return false;
            if (m.Groups[3].Success)
            {
                var b = int.Parse(m.Groups[3].Value);
                if (b is < 1 or > 65535 || b < a) return false;
            }
        }
        return true;
    }

    public static bool IsValidAddressList(string? list)
    {
        if (string.IsNullOrWhiteSpace(list)) return true;
        var tokens = list.Split(',', StringSplitOptions.TrimEntries);
        if (tokens.Length > MaxListItems) return false;
        return tokens.All(IsValidAddressToken);
    }

    static bool IsValidAddressToken(string t)
    {
        if (t.Length == 0) return false;
        if (AddressKeywords.Contains(t)) return true;

        var slash = t.IndexOf('/');
        if (slash > 0)
        {
            var addr = t[..slash];
            var suffix = t[(slash + 1)..];
            if (!IsStrictIp(addr, out var ip)) return false;
            if (int.TryParse(suffix, out var prefix))
                return prefix >= 0 && prefix <= (ip!.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);
            return ip!.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && IsStrictIp(suffix, out _); // masque 255.255.255.0
        }

        var dash = t.IndexOf('-');
        if (dash > 0)
            return IsStrictIp(t[..dash], out var a) && IsStrictIp(t[(dash + 1)..], out var b) && a!.AddressFamily == b!.AddressFamily;

        return IsStrictIp(t, out _);
    }

    static bool IsStrictIp(string s, out IPAddress? ip)
    {
        ip = null;
        if (!IPAddress.TryParse(s, out var parsed)) return false;
        // IPAddress.TryParse accepte "1" ou "1.2" : on exige la forme complète.
        if (parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && s.Count(c => c == '.') != 3) return false;
        if (parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && !s.Contains(':')) return false;
        ip = parsed;
        return true;
    }
}
