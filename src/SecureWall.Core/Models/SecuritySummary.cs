using SecureWall.Core.Enums;
using SecureWall.Core.Logic;

namespace SecureWall.Core.Models;

    /// <summary>Photographie de l'état de sécurité, construite uniquement à partir de données réelles du système.</summary>
    public sealed class SecuritySummary
    {
        public DefenderStatus Defender { get; init; } = DefenderStatus.Unavailable("Non chargé");
        public GlobalState State { get; init; } = GlobalState.AttentionRequired;
        public List<string> Reasons { get; init; } = new();
        public int TotalDetections { get; init; }
        public int ActiveThreats { get; init; }
        public int QuarantineCount { get; init; }
        public IReadOnlyList<FirewallProfileInfo> Profiles { get; init; } = Array.Empty<FirewallProfileInfo>();
        public bool FirewallProtected { get; init; }
        public int ActiveRules { get; init; }
        public int TotalRules { get; init; }
        public int BlockedLast24h { get; init; }
        public bool ServiceAvailable { get; init; }
        public bool EmergencyActive { get; init; }
        public DateTime? EmergencyAutoRestoreAt { get; init; }
        public IReadOnlyList<NetworkProfileInfo> Networks { get; init; } = Array.Empty<NetworkProfileInfo>();
        public DateTime Updated { get; init; } = DateTime.MinValue;

        public string StateText => GlobalStateEvaluator.Text(State);
        public Level StateLevel => GlobalStateEvaluator.LevelOf(State);
        public string ActiveProfileName => Profiles.FirstOrDefault(p => p.IsCurrent)?.Name ?? Networks.FirstOrDefault()?.Category ?? "—";
    }

