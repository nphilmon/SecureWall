using System.Runtime.InteropServices;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Models;

namespace SecureWall.Security.Firewall;

/// <summary>
/// Accès à Windows Defender Firewall via l'API COM officielle (INetFwPolicy2 / INetFwRule).
/// La lecture fonctionne sans élévation ; toute écriture exige les droits administrateur (donc réalisée par le service privilégié).
/// </summary>
public sealed class ComFirewallPolicy : IFirewallPolicy
{
    readonly object _lock = new();

    /// <summary>
    /// Équivalent de « Internet » : tout sauf réseau local, bouclage, liaison locale, multicast et adresses privées (IPv4 + IPv6 global).
    /// Le mot-clé natif est refusé par INetFwRule.RemoteAddresses sur cette version de Windows.
    /// </summary>
    public const string InternetAddresses =
        "0.0.0.0-9.255.255.255,11.0.0.0-100.63.255.255,100.128.0.0-126.255.255.255,128.0.0.0-169.253.255.255," +
        "169.255.0.0-172.15.255.255,172.32.0.0-192.167.255.255,192.169.0.0-223.255.255.255," +
        "2000::-3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";

    static string ExpandKeywords(string addresses) => string.Join(",", addresses.Split(',', StringSplitOptions.TrimEntries)
        .Select(t => t.Equals("Internet", StringComparison.OrdinalIgnoreCase) ? InternetAddresses : t));

    static dynamic NewPolicy() => Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)!)!;
    static dynamic NewRule() => Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true)!)!;

    public IReadOnlyList<FirewallProfileInfo> GetProfiles()
    {
        lock (_lock)
        {
            dynamic policy = NewPolicy();
            int current = policy.CurrentProfileTypes;
            var list = new List<FirewallProfileInfo>();
            foreach (var (type, name) in new[] { (FirewallProfiles.Domain, "Domaine"), (FirewallProfiles.Private, "Privé"), (FirewallProfiles.Public, "Public") })
            {
                int t = (int)type;
                list.Add(new FirewallProfileInfo
                {
                    Profile = type, Name = name,
                    Enabled = (bool)policy.FirewallEnabled[t],
                    IsCurrent = (current & t) != 0,
                    DefaultInbound = (int)policy.DefaultInboundAction[t] == 0 ? "Bloquer" : "Autoriser",
                    DefaultOutbound = (int)policy.DefaultOutboundAction[t] == 0 ? "Bloquer" : "Autoriser",
                });
            }
            return list;
        }
    }

    public void SetProfileEnabled(FirewallProfiles profile, bool enabled)
    {
        if (profile is not (FirewallProfiles.Domain or FirewallProfiles.Private or FirewallProfiles.Public))
            throw new ArgumentException("Profil invalide.");
        lock (_lock)
        {
            dynamic policy = NewPolicy();
            policy.FirewallEnabled[(int)profile] = enabled;
        }
    }

    public int GetRuleCount()
    {
        lock (_lock)
        {
            dynamic policy = NewPolicy();
            return (int)policy.Rules.Count;
        }
    }

    public IReadOnlyList<FirewallRule> GetRules()
    {
        lock (_lock)
        {
            dynamic policy = NewPolicy();
            var list = new List<FirewallRule>(512);
            foreach (dynamic r in policy.Rules)
            {
                try { list.Add(Map(r)); }
                catch (COMException) { /* règle illisible : ignorée */ }
            }
            return list;
        }
    }

    public FirewallRule? FindRule(string name)
    {
        lock (_lock)
        {
            dynamic policy = NewPolicy();
            try { return Map(policy.Rules.Item(name)); }
            catch (Exception ex) when (ex is COMException or FileNotFoundException) { return null; }
        }
    }

    static FirewallRule Map(dynamic r) => new()
    {
        Name = (string?)r.Name ?? "",
        Description = (string?)r.Description ?? "",
        Enabled = (bool)r.Enabled,
        Direction = (int)r.Direction == 1 ? FirewallDirection.Inbound : FirewallDirection.Outbound,
        Action = (int)r.Action == 1 ? FirewallAction.Allow : FirewallAction.Block,
        ProtocolNumber = (int)r.Protocol,
        LocalPorts = (string?)r.LocalPorts ?? "",
        RemotePorts = (string?)r.RemotePorts ?? "",
        LocalAddresses = (string?)r.LocalAddresses ?? "",
        RemoteAddresses = (string?)r.RemoteAddresses ?? "",
        Program = (string?)r.ApplicationName ?? "",
        ServiceName = (string?)r.ServiceName ?? "",
        ProfilesMask = (int)r.Profiles,
        Group = (string?)r.Grouping ?? "",
    };

    public void AddRule(FirewallRuleSpec spec, string group)
    {
        lock (_lock)
        {
            dynamic policy = NewPolicy();
            dynamic rule = NewRule();
            Apply(rule, spec, newRule: true);
            rule.Grouping = group;
            policy.Rules.Add(rule);
        }
    }

    public void UpdateRule(string originalName, FirewallRuleSpec spec)
    {
        lock (_lock)
        {
            dynamic policy = NewPolicy();
            dynamic rule = policy.Rules.Item(originalName);
            var group = (string?)rule.Grouping ?? "";
            var oldProtocol = (int)rule.Protocol;
            if (oldProtocol != (int)spec.Protocol)
            {
                // Changer de protocole avec des ports définis est refusé par l'API : on recrée la règle.
                dynamic fresh = NewRule();
                Apply(fresh, spec, newRule: true);
                fresh.Grouping = group;
                policy.Rules.Remove(originalName);
                policy.Rules.Add(fresh);
                return;
            }
            Apply(rule, spec, newRule: false);
        }
    }

    static void Apply(dynamic rule, FirewallRuleSpec s, bool newRule)
    {
        rule.Name = s.Name;
        rule.Description = s.Description ?? "";
        rule.Direction = (int)s.Direction;
        rule.Action = (int)s.Action;
        rule.Protocol = (int)s.Protocol;
        // Une valeur nulle ou vide est refusée (E_INVALIDARG) : pour une nouvelle règle sans programme, on ne touche pas au champ.
        if (!string.IsNullOrWhiteSpace(s.Program) || !newRule)
            rule.ApplicationName = string.IsNullOrWhiteSpace(s.Program) ? null : s.Program;
        var portsOk = s.Protocol is FirewallProtocol.Tcp or FirewallProtocol.Udp;
        if (portsOk)
        {
            rule.LocalPorts = Blank(s.LocalPorts) ? "*" : s.LocalPorts;
            rule.RemotePorts = Blank(s.RemotePorts) ? "*" : s.RemotePorts;
        }
        rule.LocalAddresses = Blank(s.LocalAddresses) ? "*" : ExpandKeywords(s.LocalAddresses!);
        rule.RemoteAddresses = Blank(s.RemoteAddresses) ? "*" : ExpandKeywords(s.RemoteAddresses!);
        rule.Profiles = (int)s.Profiles;
        rule.Enabled = s.Enabled;
    }

    static bool Blank(string? v) => string.IsNullOrWhiteSpace(v);

    public void RemoveRule(string name)
    {
        lock (_lock)
        {
            dynamic policy = NewPolicy();
            policy.Rules.Remove(name);
        }
    }

    public void SetRuleEnabled(string name, bool enabled)
    {
        lock (_lock)
        {
            dynamic policy = NewPolicy();
            dynamic rule = policy.Rules.Item(name);
            rule.Enabled = enabled;
        }
    }
}
