namespace SecureWall.Core.Enums;

/// <summary>Niveau d'information (couleur). Ne représente jamais un "score de risque".</summary>
public enum Level { Neutral, Good, Info, Warning, Bad }

public enum AppPage
{
    Dashboard, Antivirus, Scans, Threats, Quarantine, Processes, Connections, Applications,
    Firewall, Rules, Usb, Startup, History, Statistics, SecurityCenter, Settings, Dns, Map, WhatsNew
}

public enum ScanKind { Quick, Full, Custom, File }

public enum GlobalState { Protected, AttentionRequired, ProtectionDisabled, ThreatDetected }

public enum SignatureStatus { SignedValid, Invalid, Unsigned, Unknown, Pending }

public enum FirewallDirection { Inbound = 1, Outbound = 2 }

public enum FirewallAction { Block = 0, Allow = 1 }

/// <summary>Valeurs numériques = numéros de protocole IANA utilisés par INetFwRule (256 = tous).</summary>
public enum FirewallProtocol { Any = 256, Tcp = 6, Udp = 17, Icmpv4 = 1, Icmpv6 = 58 }

[Flags]
public enum FirewallProfiles { None = 0, Domain = 1, Private = 2, Public = 4, All = 7 }

public enum ThemeMode { System, Light, Dark }

public enum NotificationKind
{
    ThreatDetected, ScanCompleted, FirewallDisabled, DefenderDisabled, SignaturesOutdated,
    UsbConnected, NewNetworkApp, SecurityChange, ThreatRemoved, Quarantined, EmergencyMode
}

/// <summary>
/// Liste blanche des seules opérations que le service privilégié accepte.
/// Toute valeur inconnue est rejetée avant tout traitement.
/// </summary>
public enum PrivilegedOperation
{
    Ping = 1,
    GetServiceInfo = 2,

    FirewallSetProfileEnabled = 10,
    FirewallCreateRule = 11,
    FirewallUpdateRule = 12,
    FirewallDeleteRule = 13,
    FirewallSetRuleEnabled = 14,
    FirewallBackup = 15,
    FirewallListBackups = 16,
    FirewallRestoreBackup = 17,
    FirewallReadBlockedConnections = 18,
    FirewallSetBlockAuditing = 19,

    EmergencyCutoff = 30,
    EmergencyRestore = 31,
    EmergencyStatus = 32,

    DefenderRestoreQuarantined = 40,
    DefenderRemoveThreat = 41,

    NetworkGetTcpTraffic = 50,

    StartupSetEnabled = 60,

    DnsSetServers = 70,
    DnsResetServers = 71,
    DnsFlushCache = 72,
}

