using SecureWall.Core.Enums;

namespace SecureWall.Core.Models;

public sealed class SignatureInfo
{
    public SignatureStatus Status { get; init; } = SignatureStatus.Unknown;
    public string Publisher { get; init; } = "";
    public string Thumbprint { get; init; } = "";
    public DateTime? CertificateExpiry { get; init; }
    public string Detail { get; init; } = "";

    public static readonly SignatureInfo Pending = new() { Status = SignatureStatus.Pending };

    public string Text => Status switch
    {
        SignatureStatus.SignedValid => "Signé et valide",
        SignatureStatus.Invalid => "Signature invalide",
        SignatureStatus.Unsigned => "Non signé",
        SignatureStatus.Pending => "Vérification…",
        _ => "Inconnu",
    };

    public Level Level => Status switch
    {
        SignatureStatus.SignedValid => Level.Good,
        SignatureStatus.Invalid => Level.Warning,
        _ => Level.Neutral,
    };
}

public sealed class NetConnection
{
    public string Protocol { get; init; } = "TCP";
    public string LocalAddress { get; init; } = "";
    public int LocalPort { get; init; }
    public string RemoteAddress { get; init; } = "";
    public int RemotePort { get; init; }
    public string State { get; init; } = "";
    public int Pid { get; init; }
    public string ProcessName { get; set; } = "";
    public string ProcessPath { get; set; } = "";
    public bool IsExternal { get; init; }
    public bool IsListening { get; init; }
    public bool IsEstablished { get; init; }
    public long? BytesSent { get; set; }
    public long? BytesReceived { get; set; }

    public string Local => $"{LocalAddress}:{LocalPort}";
    public string Remote => string.IsNullOrEmpty(RemoteAddress) ? "—" : $"{RemoteAddress}:{RemotePort}";
    public string SentText => BytesSent is { } b ? FormatBytes(b) : "—";
    public string ReceivedText => BytesReceived is { } b ? FormatBytes(b) : "—";

    public static string FormatBytes(long b) =>
        b < 1024 ? $"{b} o" : b < 1024 * 1024 ? $"{b / 1024.0:0.#} Ko" : b < 1024L * 1024 * 1024 ? $"{b / 1048576.0:0.#} Mo" : $"{b / 1073741824.0:0.##} Go";
}

public sealed class NetworkSample
{
    public DateTime Time { get; init; }
    public double DownBytesPerSec { get; init; }
    public double UpBytesPerSec { get; init; }
    public static string Rate(double bps) => NetConnection.FormatBytes((long)bps) + "/s";
}

public sealed class NetworkProfileInfo
{
    public string Name { get; init; } = "";
    public string Interface { get; init; } = "";
    public string Category { get; init; } = "";   // Public, Privé, Domaine
    public string Connectivity { get; init; } = "";
}

public sealed class ProcessEntry
{
    public string Name { get; init; } = "";
    public int Pid { get; init; }
    public string User { get; init; } = "";
    public string Path { get; init; } = "";
    public double Cpu { get; init; }
    public double MemoryMb { get; init; }
    public int Connections { get; set; }
    public DateTime? StartTime { get; init; }
    public bool UnusualLocation { get; init; }
    public SignatureInfo Signature { get; set; } = SignatureInfo.Pending;

    public string Publisher => string.IsNullOrEmpty(Signature.Publisher) ? "—" : Signature.Publisher;
    public string CpuText => $"{Cpu:0.0} %";
    public string MemoryText => $"{MemoryMb:N0} Mo";
    public string StartText => StartTime?.ToString("g") ?? "—";

    /// <summary>Faits purement informatifs : aucun ne signifie à lui seul qu'un processus est malveillant.</summary>
    public string Indicators
    {
        get
        {
            var l = new List<string>();
            switch (Signature.Status)
            {
                case SignatureStatus.SignedValid: l.Add("Signé"); break;
                case SignatureStatus.Unsigned: l.Add("Non signé"); break;
                case SignatureStatus.Invalid: l.Add("Signature invalide"); break;
            }
            if (Signature.Status != SignatureStatus.Pending && Signature.Status != SignatureStatus.SignedValid
                && string.IsNullOrEmpty(Signature.Publisher) && Path.Length > 0)
                l.Add("Éditeur inconnu");
            if (UnusualLocation) l.Add("Chemin inhabituel");
            return l.Count == 0 ? "—" : string.Join(" · ", l);
        }
    }
}

public sealed class StartupEntry
{
    public string Name { get; init; } = "";
    public string Command { get; init; } = "";
    public string Path { get; init; } = "";
    public string Location { get; init; } = "";   // chemin lisible de la clé / du dossier
    public string Source { get; init; } = "";     // HKCU-Run, HKLM-Run, HKLM-Run32, Startup-User, Startup-Common
    public bool Enabled { get; init; } = true;
    public SignatureInfo Signature { get; set; } = SignatureInfo.Pending;
    public string Key => $"{Source}|{Name}|{Command}".ToLowerInvariant();
    public string Status => Enabled ? "Activé" : "Désactivé";
    public string Publisher => string.IsNullOrEmpty(Signature.Publisher) ? "—" : Signature.Publisher;
    /// <summary>Windows ne fournit pas d'API publique pour l'impact au démarrage : on l'indique honnêtement.</summary>
    public string Impact => "Non communiqué par Windows";
}

public sealed class UsbDevice
{
    public string DriveLetter { get; init; } = "";
    public string Label { get; init; } = "";
    public string Model { get; init; } = "";
    public string Identifier { get; init; } = "";
    public long SizeBytes { get; init; }
    public string Type { get; init; } = "Stockage amovible";
    public DateTime InsertedAt { get; init; } = DateTime.Now;
    public DateTime? LastScan { get; set; }
    public bool IsNew { get; set; }
    public string DisplayName => string.IsNullOrWhiteSpace(Label) ? (string.IsNullOrWhiteSpace(Model) ? DriveLetter : Model) : Label;
    public string SizeText => SizeBytes <= 0 ? "—" : $"{SizeBytes / 1_000_000_000.0:0.0} Go";
    public string InsertedText => InsertedAt.ToString("g");
    public string LastScanText => LastScan?.ToString("g") ?? "Jamais analysé";
}

public sealed class ProgramReportItem
{
    public string Label { get; init; } = "";
    public string Value { get; init; } = "";
    public Level Level { get; init; } = Level.Neutral;
    /// <summary>true = détection réelle d'un moteur antivirus ; false = simple information.</summary>
    public bool IsDetection { get; init; }
}
