using SecureWall.Core.Enums;

namespace SecureWall.Core.DTOs;

public sealed record OperationResult(bool Success, string Message = "")
{
    public static OperationResult Ok(string message = "") => new(true, message);
    public static OperationResult Fail(string message) => new(false, message);
}

/// <summary>Description complète d'une règle de pare-feu à créer ou à remplacer.</summary>
public sealed class FirewallRuleSpec
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public FirewallDirection Direction { get; set; } = FirewallDirection.Outbound;
    public FirewallAction Action { get; set; } = FirewallAction.Block;
    public FirewallProtocol Protocol { get; set; } = FirewallProtocol.Any;
    public string Program { get; set; } = "";
    public string LocalPorts { get; set; } = "";
    public string RemotePorts { get; set; } = "";
    public string LocalAddresses { get; set; } = "";
    public string RemoteAddresses { get; set; } = "";
    public FirewallProfiles Profiles { get; set; } = FirewallProfiles.All;

    public FirewallRuleSpec Clone() => (FirewallRuleSpec)MemberwiseClone();
}

/// <summary>Requête envoyée au service privilégié. Tous les arguments sont des chaînes validées côté service.</summary>
public sealed class PipeRequest
{
    public const int CurrentVersion = 1;
    public int Version { get; set; } = CurrentVersion;
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public PrivilegedOperation Operation { get; set; }
    public Dictionary<string, string> Args { get; set; } = new();
}

public sealed class PipeResponse
{
    public string Id { get; set; } = "";
    public bool Success { get; set; }
    public string ErrorCode { get; set; } = "";
    public string Message { get; set; } = "";
    /// <summary>Charge utile JSON optionnelle (liste de sauvegardes, trafic TCP, etc.).</summary>
    public string? Data { get; set; }

    public static PipeResponse Ok(string id, string message = "", string? data = null) =>
        new() { Id = id, Success = true, Message = message, Data = data };

    public static PipeResponse Fail(string id, string code, string message) =>
        new() { Id = id, Success = false, ErrorCode = code, Message = message };
}

public sealed class TcpTrafficEntry
{
    public string LocalAddress { get; set; } = "";
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }
}

public sealed class BlockedConnectionEntry
{
    public DateTime Time { get; set; }
    public string Application { get; set; } = "";
    public string Direction { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
}

public sealed class BlockedConnectionsReport
{
    public bool AuditingEnabled { get; set; }
    public bool Readable { get; set; }
    public List<BlockedConnectionEntry> Entries { get; set; } = new();
}

public sealed class EmergencyState
{
    public bool Active { get; set; }
    public DateTime? Since { get; set; }
    public string BackupName { get; set; } = "";
    /// <summary>Heure à laquelle Internet sera rétabli automatiquement (null = jamais).</summary>
    public DateTime? AutoRestoreAt { get; set; }
}
