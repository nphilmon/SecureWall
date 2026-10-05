using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;

namespace SecureWall.Core.Models;

public sealed class FirewallProfileInfo
{
    public FirewallProfiles Profile { get; init; }
    public string Name { get; init; } = "";
    public bool Enabled { get; init; }
    public bool IsCurrent { get; init; }
    public string DefaultInbound { get; init; } = "";
    public string DefaultOutbound { get; init; } = "";
}

/// <summary>Règle telle que lue dans Windows Defender Firewall.</summary>
public sealed class FirewallRule
{
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public bool Enabled { get; init; }
    public FirewallDirection Direction { get; init; }
    public FirewallAction Action { get; init; }
    public int ProtocolNumber { get; init; } = 256;
    public string LocalPorts { get; init; } = "";
    public string RemotePorts { get; init; } = "";
    public string LocalAddresses { get; init; } = "";
    public string RemoteAddresses { get; init; } = "";
    public string Program { get; init; } = "";
    public string ServiceName { get; init; } = "";
    public int ProfilesMask { get; init; }
    public string Group { get; init; } = "";

    public bool CreatedBySecureWall => Group == RuleGroups.SecureWall || Group == RuleGroups.Emergency;
    public string DirectionText => Direction == FirewallDirection.Inbound ? "Entrante" : "Sortante";
    public string ActionText => Action == FirewallAction.Allow ? "Autoriser" : "Bloquer";
    public string StatusText => Enabled ? "Activée" : "Désactivée";
    public string ProtocolText => ProtocolNumber switch { 256 => "Tous", 6 => "TCP", 17 => "UDP", 1 => "ICMPv4", 58 => "ICMPv6", var n => n.ToString() };
    public string ProfilesText => ProfilesMask is 0x7FFFFFFF or 7 or -1 ? "Tous"
        : string.Join(", ", new[] { (ProfilesMask & 1) != 0 ? "Domaine" : null, (ProfilesMask & 2) != 0 ? "Privé" : null, (ProfilesMask & 4) != 0 ? "Public" : null }.Where(s => s != null));
    public string ProgramText => string.IsNullOrEmpty(Program) ? (string.IsNullOrEmpty(ServiceName) ? "Tous les programmes" : $"Service : {ServiceName}") : Program;

    public FirewallRuleSpec ToSpec() => new()
    {
        Name = Name, Description = Description, Enabled = Enabled, Direction = Direction, Action = Action,
        Protocol = Enum.IsDefined(typeof(FirewallProtocol), ProtocolNumber) ? (FirewallProtocol)ProtocolNumber : FirewallProtocol.Any,
        Program = Program, LocalPorts = LocalPorts, RemotePorts = RemotePorts,
        LocalAddresses = LocalAddresses, RemoteAddresses = RemoteAddresses,
        Profiles = ProfilesMask is 0x7FFFFFFF or -1 or 0 ? FirewallProfiles.All : (FirewallProfiles)(ProfilesMask & 7),
    };
}

public static class RuleGroups
{
    public const string SecureWall = "SecureWall";
    public const string Emergency = "SecureWall Emergency";
}
