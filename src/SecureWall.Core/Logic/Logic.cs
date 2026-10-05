using System.Net;
using System.Net.Sockets;
using SecureWall.Core.Enums;
using SecureWall.Core.Models;

namespace SecureWall.Core.Logic;

public static class NetworkAddressClassifier
{
    /// <summary>true si l'adresse n'est ni locale, ni privée, ni de liaison locale, ni non spécifiée.</summary>
    public static bool IsExternal(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return false;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return !(b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168)
                     || (b[0] == 169 && b[1] == 254) || b[0] >= 224);
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            return !(ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || (b[0] & 0xFE) == 0xFC || b[0] == 0xFF);
        }
        return false;
    }

    public static bool IsExternal(string address) => IPAddress.TryParse(address, out var ip) && IsExternal(ip);
}

public static class ConnectionAnalyzer
{
    public static IReadOnlyList<(string App, int Count)> TopApplications(IEnumerable<NetConnection> connections, int take = 10) =>
        connections.Where(c => c.IsEstablished || !c.IsListening)
            .GroupBy(c => string.IsNullOrEmpty(c.ProcessName) ? $"PID {c.Pid}" : c.ProcessName)
            .Select(g => (g.Key, g.Count()))
            .OrderByDescending(x => x.Item2).Take(take).ToList();

    public static IReadOnlyList<(int Port, int Count)> TopRemotePorts(IEnumerable<NetConnection> connections, int take = 10) =>
        connections.Where(c => c.IsEstablished && c.RemotePort > 0)
            .GroupBy(c => c.RemotePort).Select(g => (g.Key, g.Count()))
            .OrderByDescending(x => x.Item2).Take(take).ToList();

    public static Dictionary<string, int> CountByState(IEnumerable<NetConnection> connections) =>
        connections.GroupBy(c => c.State).ToDictionary(g => g.Key, g => g.Count());
}

/// <summary>Programmes Windows critiques : jamais bloqués ni signalés automatiquement comme "nouveaux".</summary>
public static class CriticalProcessPolicy
{
    public static bool IsCriticalWindowsComponent(string path)
    {
        if (string.IsNullOrEmpty(path)) return true;   // PID système sans chemin (System, Idle…)
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return path.StartsWith(win, StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsUnusualLocation(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        string[] unusual = { @"\Temp\", @"\Downloads\", @"\Users\Public\", @"\$Recycle.Bin\", @"\AppData\Local\Temp\" };
        if (unusual.Any(u => path.Contains(u, StringComparison.OrdinalIgnoreCase))) return true;
        var root = Path.GetPathRoot(path) ?? "";
        return string.Equals(Path.GetDirectoryName(path)?.TrimEnd('\\') + "\\", root, StringComparison.OrdinalIgnoreCase);
    }
}

// ---------- Surveillance des modifications sensibles (logique pure, testable) ----------

public sealed class SecuritySnapshot
{
    public bool DefenderEnabled { get; set; }
    public bool RealTimeEnabled { get; set; }
    public bool FirewallDomain { get; set; }
    public bool FirewallPrivate { get; set; }
    public bool FirewallPublic { get; set; }
    public HashSet<string> Exclusions { get; set; } = new();
    public bool ExclusionsKnown { get; set; }
    public Dictionary<string, string> Rules { get; set; } = new();   // nom → empreinte des propriétés
    public HashSet<string> StartupKeys { get; set; } = new();
    public string DefenderPrefsSignature { get; set; } = "";
}

public sealed record SecurityChange(string EventType, string Description, string Severity, NotificationKind? Notify);

public static class SecurityChangeDetector
{
    /// <summary>Compare deux instantanés. <paramref name="previous"/> null = première exécution : aucune alerte (base de référence).</summary>
    public static List<SecurityChange> Compare(SecuritySnapshot? previous, SecuritySnapshot current)
    {
        var l = new List<SecurityChange>();
        if (previous == null) return l;

        if (previous.DefenderEnabled && !current.DefenderEnabled)
            l.Add(new("Antivirus", "Microsoft Defender Antivirus n'est plus actif.", "Attention", NotificationKind.DefenderDisabled));
        else if (!previous.DefenderEnabled && current.DefenderEnabled)
            l.Add(new("Antivirus", "Microsoft Defender Antivirus est de nouveau actif.", "Succès", null));

        if (previous.RealTimeEnabled && !current.RealTimeEnabled)
            l.Add(new("Antivirus", "La protection en temps réel a été désactivée.", "Attention", NotificationKind.DefenderDisabled));
        else if (!previous.RealTimeEnabled && current.RealTimeEnabled)
            l.Add(new("Antivirus", "La protection en temps réel est de nouveau activée.", "Succès", null));

        Profile("Domaine", previous.FirewallDomain, current.FirewallDomain, l);
        Profile("Privé", previous.FirewallPrivate, current.FirewallPrivate, l);
        Profile("Public", previous.FirewallPublic, current.FirewallPublic, l);

        if (previous.ExclusionsKnown && current.ExclusionsKnown)
            foreach (var e in current.Exclusions.Except(previous.Exclusions))
                l.Add(new("Antivirus", $"Nouvelle exclusion Microsoft Defender : {e}. Une exclusion réduit la protection pour l'élément concerné.", "Attention", NotificationKind.SecurityChange));

        if (previous.DefenderPrefsSignature != "" && current.DefenderPrefsSignature != previous.DefenderPrefsSignature)
            l.Add(new("Paramètres", "Des paramètres de protection Microsoft Defender ont été modifiés (cloud, comportement, téléchargements ou applications indésirables).", "Information", NotificationKind.SecurityChange));

        var added = current.Rules.Keys.Except(previous.Rules.Keys).ToList();
        foreach (var n in added.Take(5))
            l.Add(new("Pare-feu", $"Nouvelle règle de pare-feu : {n}", "Information", null));
        if (added.Count > 5)
            l.Add(new("Pare-feu", $"{added.Count} nouvelles règles de pare-feu ont été ajoutées.", "Information", null));
        foreach (var kv in current.Rules.Where(r => previous.Rules.TryGetValue(r.Key, out var h) && h != r.Value).Take(5))
            l.Add(new("Pare-feu", $"Règle de pare-feu modifiée : {kv.Key}", "Information", null));

        foreach (var k in current.StartupKeys.Except(previous.StartupKeys))
            l.Add(new("Démarrage", $"Nouvelle application au démarrage de Windows : {k.Split('|').ElementAtOrDefault(1) ?? k}", "Information", NotificationKind.SecurityChange));

        return l;
    }

    static void Profile(string name, bool before, bool after, List<SecurityChange> l)
    {
        if (before && !after)
            l.Add(new("Pare-feu", $"Le pare-feu Windows est désactivé pour le profil {name}.", "Attention", NotificationKind.FirewallDisabled));
        else if (!before && after)
            l.Add(new("Pare-feu", $"Le pare-feu Windows est de nouveau activé pour le profil {name}.", "Succès", null));
    }
}

/// <summary>Calcule l'état global à partir de faits réels uniquement.</summary>
public static class GlobalStateEvaluator
{
    public static GlobalState Evaluate(DefenderStatus d, IReadOnlyCollection<DefenderThreat> threats, bool firewallEnabled, int signatureMaxAgeDays,
        out List<string> reasons)
    {
        reasons = new();
        if (threats.Any(t => t.IsActive || t.StatusId == 1))
        {
            reasons.Add("Au moins une menace détectée par Microsoft Defender n'est pas résolue.");
            return GlobalState.ThreatDetected;
        }
        var disabled = false;
        if (!d.Available) { reasons.Add("Microsoft Defender n'est pas accessible."); disabled = true; }
        else if (d.PassiveMode) reasons.Add("Defender est en mode passif : un autre antivirus gère probablement la protection.");
        else if (!d.AntivirusEnabled) { reasons.Add("L'antivirus Microsoft Defender est désactivé."); disabled = true; }
        else if (!d.RealTime) { reasons.Add("La protection en temps réel est désactivée."); disabled = true; }
        if (!firewallEnabled) { reasons.Add("Le pare-feu Windows est désactivé sur le profil actif."); disabled = true; }
        if (disabled) return GlobalState.ProtectionDisabled;

        var attention = d.PassiveMode;
        if (d.SignatureAgeDays is { } age && age > signatureMaxAgeDays) { reasons.Add($"Les signatures antivirus datent de {age} jours."); attention = true; }
        if (d.LastScan is null || (DateTime.Now - d.LastScan.Value).TotalDays > 30) { reasons.Add("Aucune analyse récente (plus de 30 jours)."); attention = true; }
        if (threats.Any(t => t.StatusId is 102 or 103 or 104 or 107)) { reasons.Add("Une action sur une menace a échoué."); attention = true; }
        return attention ? GlobalState.AttentionRequired : GlobalState.Protected;
    }

    public static string Text(GlobalState s) => s switch
    {
        GlobalState.Protected => "Système protégé",
        GlobalState.AttentionRequired => "Attention requise",
        GlobalState.ThreatDetected => "Menace détectée",
        _ => "Protection désactivée",
    };

    public static Level LevelOf(GlobalState s) => s switch
    {
        GlobalState.Protected => Level.Good,
        GlobalState.AttentionRequired => Level.Warning,
        _ => Level.Bad,
    };
}
