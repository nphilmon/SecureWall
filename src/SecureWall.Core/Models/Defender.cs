using SecureWall.Core.Enums;

namespace SecureWall.Core.Models;

public sealed class DefenderStatus
{
    public bool Available { get; init; }
    public string? Error { get; init; }
    public bool ServiceEnabled { get; init; }
    public bool AntivirusEnabled { get; init; }
    public bool PassiveMode { get; init; }
    public string RunningMode { get; init; } = "";
    public bool RealTime { get; init; }
    public bool OnAccess { get; init; }
    public bool Downloads { get; init; }
    public bool Behavior { get; init; }
    public bool NetworkInspection { get; init; }
    public bool TamperProtected { get; init; }
    public string ProductVersion { get; init; } = "";
    public string EngineVersion { get; init; } = "";
    public string SignatureVersion { get; init; } = "";
    public DateTime? SignatureUpdated { get; init; }
    public int? SignatureAgeDays { get; init; }
    public DateTime? LastQuickScan { get; init; }
    public DateTime? LastFullScan { get; init; }

    public DateTime? LastScan =>
        (LastQuickScan, LastFullScan) switch
        {
            (null, null) => null,
            (var q, null) => q,
            (null, var f) => f,
            (var q, var f) => q > f ? q : f,
        };

    public static DefenderStatus Unavailable(string error) => new() { Available = false, Error = error };
}

public sealed class DefenderPreferences
{
    public bool Available { get; init; }
    public int CloudReporting { get; init; }      // MAPSReporting : 0 désactivé, 1 de base, 2 avancé
    public int SampleConsent { get; init; }
    public int PuaProtection { get; init; }       // 0 désactivé, 1 activé, 2 audit
    public bool BehaviorDisabled { get; init; }
    public bool DownloadsDisabled { get; init; }
    public bool RealTimeDisabled { get; init; }
    /// <summary>Windows ne renvoie les exclusions qu'aux administrateurs.</summary>
    public bool ExclusionsVisible { get; init; }
    public List<string> Exclusions { get; init; } = new();
}

public sealed class SignatureVersionInfo
{
    public string Version { get; init; } = "";
    public string EngineVersion { get; init; } = "";
    public DateTime? LastUpdated { get; init; }
    public int? AgeDays { get; init; }
}

public enum FeatureState { On, Off, Unavailable }

public sealed class ProtectionFeature
{
    public string Name { get; init; } = "";
    public FeatureState State { get; init; }
    public string ManagedBy { get; init; } = "Microsoft Defender";
    public string Description { get; init; } = "";
    public string StateText => State switch { FeatureState.On => "Activé", FeatureState.Off => "Désactivé", _ => "Indisponible" };
    public Level Level => State switch { FeatureState.On => Level.Good, FeatureState.Off => Level.Warning, _ => Level.Neutral };
}

public sealed class RealtimeProtectionStatus
{
    public bool RealTimeEnabled { get; init; }
    public List<ProtectionFeature> Features { get; init; } = new();
}

public sealed class DefenderThreat
{
    public string DetectionId { get; init; } = "";
    public long ThreatId { get; init; }
    public string Name { get; init; } = "";
    public int CategoryId { get; init; }
    public string FilePath { get; init; } = "";
    public int SeverityId { get; init; }
    public DateTime DetectionTime { get; init; }
    public string Process { get; init; } = "";
    public int StatusId { get; init; }
    public int ActionId { get; init; }
    public bool IsActive { get; init; }
    public string User { get; init; } = "";

    public string Severity => SeverityId switch { 1 => "Faible", 2 => "Moyenne", 4 => "Élevée", 5 => "Grave", _ => "Inconnue" };

    public string Category => CategoryId switch
    {
        1 => "Logiciel publicitaire", 2 => "Logiciel espion", 3 => "Voleur de mots de passe", 4 => "Téléchargeur de chevaux de Troie",
        5 => "Ver", 6 => "Porte dérobée", 8 => "Cheval de Troie", 10 => "Enregistreur de frappe", 27 => "Logiciel potentiellement indésirable",
        30 => "Exploit", 37 => "Dropper", 42 => "Virus", 46 => "Comportement suspect", 47 => "Vulnérabilité", _ => "Menace",
    };

    public string Status => StatusId switch
    {
        1 => "Actif", 2 => "Nettoyé", 3 => "Mis en quarantaine", 4 => "Supprimé", 5 => "Autorisé", 6 => "Bloqué",
        102 => "Échec de mise en quarantaine", 103 => "Échec de suppression", 104 => "Échec de l'autorisation",
        105 => "Abandonné", 107 => "Échec du blocage", _ => "Inconnu",
    };

    public string Action => ActionId switch
    {
        1 => "Nettoyé", 2 => "Mis en quarantaine", 3 => "Supprimé", 6 => "Autorisé",
        8 => "Action de l'utilisateur", 9 => "Aucune action", 10 => "Bloqué", _ => "—",
    };

    public Level SeverityLevel => SeverityId switch { 1 => Level.Info, 2 => Level.Warning, 4 or 5 => Level.Bad, _ => Level.Neutral };
    public bool IsQuarantined => StatusId == 3;
    public string Engine => "Microsoft Defender";
    public string FileName => string.IsNullOrEmpty(FilePath) ? "—" : Path.GetFileName(FilePath);
    public string DetectionDateText => DetectionTime.ToString("g");
}

public sealed class ScanProgress
{
    public string State { get; init; } = "";
    public string? CurrentItem { get; init; }
    public int? FilesTotal { get; init; }
    public int? FilesScanned { get; init; }
    public TimeSpan Elapsed { get; init; }
    public int ThreatsFound { get; init; }
    /// <summary>null = progression non communiquée par Defender (barre indéterminée).</summary>
    public double? Percent { get; init; }
}

public sealed class ScanResult
{
    public long ScanId { get; init; }
    public ScanKind Kind { get; init; }
    public DateTime Start { get; init; }
    public DateTime End { get; init; }
    public int? FilesScanned { get; init; }
    public string Status { get; init; } = "";   // Terminée, Annulée, Impossible, Échec
    public string? Message { get; init; }
    public string Target { get; init; } = "";
    public List<DefenderThreat> Threats { get; init; } = new();
    public int ThreatsFound => Threats.Count;
    public bool Completed => Status == "Terminée";
}
