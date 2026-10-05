using SecureWall.Core.Enums;

namespace SecureWall.Core.Models;

// Enregistrements de la base SQLite locale. Aucun contenu de fichier utilisateur n'y est stocké.

public sealed class ApplicationRecord
{
    public long Id { get; set; }
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public string Publisher { get; set; } = "";
    public string SignatureStatus { get; set; } = "";
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public string FirstSeenText => FirstSeen.ToString("g");
    public string LastSeenText => LastSeen.ToString("g");
}

/// <summary>Trafic vers une destination, regroupé par adresse, port et application (lecture seule, issue de l'historique des connexions).</summary>
public sealed record RemoteTraffic(string Address, int Port, string Application, int Connections, DateTime LastSeen);

/// <summary>Pays d'une adresse IP publique, mis en cache localement. Country vide = pays inconnu (adresse anycast, réservée…).</summary>
public sealed record GeoCacheEntry(string Address, string Country, DateTime Checked);

public sealed class ConnectionRecord
{
    public long Id { get; set; }
    public long ApplicationId { get; set; }
    public string Protocol { get; set; } = "";
    public string LocalAddress { get; set; } = "";
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public string State { get; set; } = "";
    public DateTime Timestamp { get; set; }
}

public sealed class FirewallEventRecord
{
    public long Id { get; set; }
    public long? ApplicationId { get; set; }
    public string Application { get; set; } = "";
    public string Action { get; set; } = "";
    public string Direction { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public string RuleName { get; set; } = "";
    public DateTime Timestamp { get; set; }
    public string TimeText => Timestamp.ToString("G");
    public string PortText => BlockedConnectionInsights.PortText(RemotePort);
    public string AddressKind => BlockedConnectionInsights.AddressKind(RemoteAddress);
    public string Explanation => BlockedConnectionInsights.Explain(Application, Direction, Protocol, RemoteAddress, RemotePort);
}

public sealed class ScanRecord
{
    public long Id { get; set; }
    public string ScanType { get; set; } = "";
    public DateTime StartDate { get; set; }
    public DateTime? EndDate { get; set; }
    public int? FilesScanned { get; set; }
    public int ThreatsFound { get; set; }
    public string Status { get; set; } = "";
    public string? Target { get; set; }
    public string StartText => StartDate.ToString("g");
    public string EndText => EndDate?.ToString("g") ?? "—";
    public string DurationText => EndDate is { } e ? (e - StartDate).ToString(@"hh\:mm\:ss") : "—";
}

public sealed class ThreatRecord
{
    public long Id { get; set; }
    public string ThreatName { get; set; } = "";
    public string Category { get; set; } = "";
    public string FilePath { get; set; } = "";
    public string Severity { get; set; } = "";
    public DateTime DetectionDate { get; set; }
    public string Action { get; set; } = "";
    public string Status { get; set; } = "";
    public string DetectionId { get; set; } = "";
    public string Application { get; set; } = "";
    public string DateText => DetectionDate.ToString("g");
}

public sealed class SecurityEventRecord
{
    public long Id { get; set; }
    public string EventType { get; set; } = "";
    public string Description { get; set; } = "";
    public string Severity { get; set; } = "Information";
    public DateTime Timestamp { get; set; }
    public string TimeText => Timestamp.ToString("g");
    public Level Level => Severity switch { "Alerte" => Level.Bad, "Attention" => Level.Warning, "Succès" => Level.Good, _ => Level.Info };
}

public sealed class DeviceRecord
{
    public long Id { get; set; }
    public string DeviceIdentifier { get; set; } = "";
    public string DeviceName { get; set; } = "";
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public DateTime? LastScanDate { get; set; }
}

public sealed class AuditLogRecord
{
    public long Id { get; set; }
    public string User { get; set; } = "";
    public string Action { get; set; } = "";
    public string Details { get; set; } = "";
    public DateTime Timestamp { get; set; }
    public string TimeText => Timestamp.ToString("g");
}

/// <summary>Application ayant utilisé le réseau (vue agrégée).</summary>
public sealed class NetworkAppInfo
{
    public long ApplicationId { get; set; }
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public string Publisher { get; set; } = "";
    public SignatureInfo Signature { get; set; } = SignatureInfo.Pending;
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public int ActiveConnections { get; set; }
    public string CurrentRule { get; set; } = "—";
    public string FirstSeenText => FirstSeen.ToString("g");
    public string LastSeenText => LastSeen.ToString("g");
}

public sealed class AppSettings
{
    public bool FirstRunCompleted { get; set; }
    public ThemeMode Theme { get; set; } = ThemeMode.System;
    public bool MinimizeToTray { get; set; } = true;
    public int RefreshSeconds { get; set; } = 3;

    public bool NotificationsEnabled { get; set; } = true;
    public bool NotifyThreats { get; set; } = true;
    public bool NotifyScans { get; set; } = true;
    public bool NotifyFirewall { get; set; } = true;
    public bool NotifyUsb { get; set; } = true;
    public bool NotifySignatures { get; set; } = true;

    public bool UsbPromptScan { get; set; } = true;
    public bool UsbOnlyNewDevices { get; set; } = false;

    public bool AlertNewNetworkApps { get; set; } = false;
    public bool ConfirmRuleChanges { get; set; } = true;
    public bool MonitorSecurityChanges { get; set; } = true;
    public bool RecordConnections { get; set; } = true;
    public int RetentionDays { get; set; } = 90;
    public int SignatureMaxAgeDays { get; set; } = 3;
    /// <summary>Adresse (HTTPS, raw.githubusercontent.com) d'un jeu de règles de base signé. Vide = jeu intégré uniquement.</summary>
    public string BaselineUpdateUrl { get; set; } = "";
    /// <summary>Adresse (HTTPS, raw.githubusercontent.com) du manifeste signé des versions de l'application. Vide = pas de recherche de mise à jour.</summary>
    public string AppUpdateUrl { get; set; } = DefaultAppUpdateUrl;
    /// <summary>Manifeste officiel proposé par défaut (dépôt GitHub du projet, branche main).</summary>
    public const string DefaultAppUpdateUrl = "https://raw.githubusercontent.com/nphilmon/SecureWall/main/update.signed.json";
    /// <summary>Autorisation explicite d'interroger un service en ligne pour connaître le pays des adresses contactées. Désactivée par défaut.</summary>
    public bool GeoLookupEnabled { get; set; } = false;
    /// <summary>Dernière version dont la page Nouveautés a été ouverte (elle s'ouvre seule à chaque nouvelle version).</summary>
    public string LastSeenVersion { get; set; } = "";

    public List<ScheduleConfig> Schedules { get; set; } = new();
}

public enum ScheduleFrequency { Daily, Weekly, Monthly }

public sealed class ScheduleConfig
{
    public string Id { get; set; } = "";
    public string Label { get; set; } = "";
    public bool Enabled { get; set; }
    public ScheduleFrequency Frequency { get; set; } = ScheduleFrequency.Daily;
    public DayOfWeek DayOfWeek { get; set; } = DayOfWeek.Monday;
    public int DayOfMonth { get; set; } = 1;
    public string Time { get; set; } = "12:00";
    public ScanKind ScanKind { get; set; } = ScanKind.Quick;
    public string CustomPath { get; set; } = "";
}
