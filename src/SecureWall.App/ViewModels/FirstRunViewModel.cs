using System.Runtime.InteropServices;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SecureWall.App.ViewModels;

public sealed record CheckLine(string Text, Level Level);

public sealed partial class FirstRunViewModel : ObservableObject
{
    public static readonly string[] StepTitles =
    {
        "Bienvenue", "Vérification de Windows", "Vérification de Microsoft Defender", "Vérification du pare-feu",
        "Détection du réseau", "Notifications", "Analyse rapide", "Configuration terminée",
    };

    readonly IDefenderService _defender;
    readonly IFirewallService _firewall;
    readonly INetworkProfileService _networks;
    readonly IPrivilegedClient _client;
    readonly ISettingsStore _settings;

    [ObservableProperty] private int _step;
    [ObservableProperty] private bool _loading;
    [ObservableProperty] private bool _runQuickScan;
    public bool RequestQuickScan { get; private set; }
    public ObservableCollection<CheckLine> Lines { get; } = new();

    public string StepTitle => StepTitles[Step];
    public string Progress => $"Étape {Step + 1} sur {StepTitles.Length}";
    public bool CanBack => Step > 0 && Step < StepTitles.Length - 1;
    public bool IsLast => Step == StepTitles.Length - 1;
    public bool IsWelcome => Step == 0;
    public bool IsChecks => Step is >= 1 and <= 4;
    public bool IsNotifications => Step == 5;
    public bool IsScan => Step == 6;
    public bool IsDone => Step == 7;

    public bool NotificationsEnabled { get => _settings.Current.NotificationsEnabled; set { _settings.Current.NotificationsEnabled = value; OnPropertyChanged(); } }
    public bool NotifyThreats { get => _settings.Current.NotifyThreats; set { _settings.Current.NotifyThreats = value; OnPropertyChanged(); } }
    public bool NotifyFirewall { get => _settings.Current.NotifyFirewall; set { _settings.Current.NotifyFirewall = value; OnPropertyChanged(); } }
    public bool NotifyUsb { get => _settings.Current.NotifyUsb; set { _settings.Current.NotifyUsb = value; OnPropertyChanged(); } }
    public bool NotifyScans { get => _settings.Current.NotifyScans; set { _settings.Current.NotifyScans = value; OnPropertyChanged(); } }
    public bool UsbPrompt { get => _settings.Current.UsbPromptScan; set { _settings.Current.UsbPromptScan = value; OnPropertyChanged(); } }

    public event Action? Finished;

    public FirstRunViewModel(IDefenderService defender, IFirewallService firewall, INetworkProfileService networks, IPrivilegedClient client, ISettingsStore settings)
    {
        _defender = defender; _firewall = firewall; _networks = networks; _client = client; _settings = settings;
    }

    partial void OnStepChanged(int value)
    {
        foreach (var n in new[] { nameof(StepTitle), nameof(Progress), nameof(CanBack), nameof(IsLast), nameof(IsWelcome), nameof(IsChecks), nameof(IsNotifications), nameof(IsScan), nameof(IsDone) })
            OnPropertyChanged(n);
        _ = LoadStepAsync();
    }

    async Task LoadStepAsync()
    {
        Lines.Clear();
        if (!IsChecks) return;
        Loading = true;
        try
        {
            switch (Step)
            {
                case 1:
                {
                    var build = Environment.OSVersion.Version.Build;
                    var is64 = RuntimeInformation.OSArchitecture == Architecture.X64;
                    Lines.Add(new($"{RuntimeInformation.OSDescription} (build {build})", build >= 19041 ? Level.Good : Level.Warning));
                    Lines.Add(new(is64 ? "Architecture x64 : compatible" : $"Architecture {RuntimeInformation.OSArchitecture} : SecureWall est conçu pour Windows 64 bits", is64 ? Level.Good : Level.Warning));
                    Lines.Add(new(build >= 22000 ? "Windows 11 détecté" : build >= 19041 ? "Windows 10 (version 2004 ou ultérieure) détecté" : "Version de Windows ancienne : certaines fonctions peuvent être indisponibles", build >= 19041 ? Level.Good : Level.Warning));
                    var svc = await _client.IsAvailableAsync();
                    Lines.Add(new(svc ? "Service privilégié SecureWall : actif" : "Service privilégié SecureWall : non démarré. Les modifications du pare-feu et la restauration de quarantaine seront indisponibles jusqu'à son installation (voir le README).", svc ? Level.Good : Level.Warning));
                    break;
                }
                case 2:
                {
                    var d = await _defender.GetStatusAsync();
                    if (!d.Available) { Lines.Add(new("Microsoft Defender n'est pas accessible : " + d.Error, Level.Bad)); break; }
                    Lines.Add(new($"Microsoft Defender Antivirus : {(d.AntivirusEnabled ? "actif" : "désactivé")}", d.AntivirusEnabled ? Level.Good : Level.Bad));
                    if (d.PassiveMode) Lines.Add(new("Mode passif : un autre antivirus semble gérer la protection.", Level.Warning));
                    Lines.Add(new($"Protection en temps réel : {(d.RealTime ? "activée" : "désactivée")}", d.RealTime ? Level.Good : Level.Warning));
                    Lines.Add(new($"Signatures : {d.SignatureVersion} ({d.SignatureUpdated?.ToString("g") ?? "date inconnue"})", (d.SignatureAgeDays ?? 0) <= 3 ? Level.Good : Level.Warning));
                    Lines.Add(new("SecureWall ne modifie aucun paramètre de Defender : il affiche son état et déclenche ses analyses.", Level.Info));
                    break;
                }
                case 3:
                {
                    var profiles = await _firewall.GetProfilesAsync();
                    foreach (var p in profiles)
                        Lines.Add(new($"Profil {p.Name} : {(p.Enabled ? "activé" : "désactivé")}{(p.IsCurrent ? " — profil actif" : "")}", p.Enabled ? Level.Good : Level.Warning));
                    Lines.Add(new("SecureWall ne change rien pendant cet assistant.", Level.Info));
                    break;
                }
                case 4:
                {
                    var nets = await _networks.GetNetworkProfilesAsync();
                    if (nets.Count == 0) Lines.Add(new("Aucun réseau actif détecté.", Level.Info));
                    foreach (var n in nets) Lines.Add(new($"Réseau « {n.Name} » ({n.Interface}) — profil {n.Category} — {n.Connectivity}", Level.Good));
                    break;
                }
            }
        }
        catch (Exception ex) { Lines.Add(new("Vérification impossible : " + ex.Message, Level.Warning)); }
        finally { Loading = false; }
    }

    [RelayCommand] void Next() { if (Step < StepTitles.Length - 1) Step++; }
    [RelayCommand] void Back() { if (Step > 0) Step--; }

    [RelayCommand]
    void Finish()
    {
        RequestQuickScan = RunQuickScan;
        _settings.Current.FirstRunCompleted = true;
        _settings.Save();
        Finished?.Invoke();
    }
}
