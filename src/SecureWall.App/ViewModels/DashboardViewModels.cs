using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureWall.App.Services;
using SecureWall.Security.Monitoring;

namespace SecureWall.App.ViewModels;

public sealed partial class DashboardViewModel : PageViewModel
{
    readonly SecurityStateService _state;
    readonly INetworkMonitor _network;
    readonly ISecurityStore _store;
    readonly IDefenderService _defender;
    readonly INavigator _nav;
    readonly IDialogService _dialogs;

    public override string Title => "Tableau de bord";
    public override string Subtitle => "Vue d'ensemble de la sécurité de votre PC, basée sur les données réelles de Windows.";

    [ObservableProperty] private SecuritySummary _summary = new();
    [ObservableProperty] private string _downText = "—";
    [ObservableProperty] private string _upText = "—";
    [ObservableProperty] private int _activeConnections;
    [ObservableProperty] private int _connectedApps;
    [ObservableProperty] private bool _updating;

    public ObservableCollection<double> DownHistory { get; } = new();
    public ObservableCollection<double> UpHistory { get; } = new();
    public ObservableCollection<SecurityEventRecord> RecentEvents { get; } = new();

    public string AntivirusStatusText => !Summary.Defender.Available ? "Indisponible"
        : Summary.Defender.PassiveMode ? "Mode passif (autre antivirus)"
        : Summary.Defender.AntivirusEnabled ? "Microsoft Defender actif" : "Désactivé";
    public Level AntivirusLevel => !Summary.Defender.Available || !Summary.Defender.AntivirusEnabled ? Level.Bad : Summary.Defender.PassiveMode ? Level.Warning : Level.Good;
    public string RealtimeText => Summary.Defender.Available ? (Summary.Defender.RealTime ? "Activée" : "Désactivée") : "Indisponible";
    public Level RealtimeLevel => !Summary.Defender.Available ? Level.Neutral : Summary.Defender.RealTime ? Level.Good : Level.Bad;
    public string LastScanText => Summary.Defender.LastScan?.ToString("g") ?? "Aucune analyse";
    public string SignatureText => string.IsNullOrEmpty(Summary.Defender.SignatureVersion) ? "—" : Summary.Defender.SignatureVersion;
    public string SignatureDateText => Summary.Defender.SignatureUpdated?.ToString("g") ?? "—";
    public string FirewallText => Summary.Profiles.Count == 0 ? "Indisponible" : Summary.FirewallProtected ? "Activé" : "Désactivé";
    public Level FirewallLevel => Summary.Profiles.Count == 0 ? Level.Neutral : Summary.FirewallProtected ? Level.Good : Level.Bad;
    public string BlockedText => Summary.BlockedLast24h > 0 ? Summary.BlockedLast24h.ToString("N0") : "Non journalisées";
    public string BlockedHint => Summary.BlockedLast24h > 0 ? "sur 24 h" : "Activez l'audit dans Pare-feu pour les compter";

    public DashboardViewModel(SecurityStateService state, INetworkMonitor network, ISecurityStore store, IDefenderService defender, INavigator nav, IDialogService dialogs)
    {
        _state = state; _network = network; _store = store; _defender = defender; _nav = nav; _dialogs = dialogs;
    }

    partial void OnSummaryChanged(SecuritySummary value)
    {
        foreach (var n in new[] { nameof(AntivirusStatusText), nameof(AntivirusLevel), nameof(RealtimeText), nameof(RealtimeLevel), nameof(LastScanText),
                     nameof(SignatureText), nameof(SignatureDateText), nameof(FirewallText), nameof(FirewallLevel), nameof(BlockedText), nameof(BlockedHint) })
            OnPropertyChanged(n);
    }

    public override async Task OnNavigatedToAsync()
    {
        Summary = _state.Current;
        await RefreshAsync();
        StartTimer(TimeSpan.FromSeconds(2), RefreshAsync);
        _ = _state.RefreshAsync().ContinueWith(t => OnUi(() => Summary = t.Result), TaskContinuationOptions.OnlyOnRanToCompletion);
    }

    int _tick;

    async Task RefreshAsync()
    {
        if (_network.LastSample is { } s)
        {
            DownText = NetworkSample.Rate(s.DownBytesPerSec);
            UpText = NetworkSample.Rate(s.UpBytesPerSec);
        }
        var hist = _network.History;
        Fill(DownHistory, hist.Select(h => h.DownBytesPerSec));
        Fill(UpHistory, hist.Select(h => h.UpBytesPerSec));

        var conns = await _network.GetConnectionsAsync();
        ActiveConnections = conns.Count(c => c.IsEstablished);
        ConnectedApps = conns.Where(c => c.IsEstablished && !string.IsNullOrEmpty(c.ProcessPath)).Select(c => c.ProcessPath.ToLowerInvariant()).Distinct().Count();

        if (_tick++ % 3 == 0)
        {
            var events = await Task.Run(() => _store.GetEvents(8));
            RecentEvents.Clear();
            foreach (var e in events) RecentEvents.Add(e);
        }
    }

    static void Fill(ObservableCollection<double> target, IEnumerable<double> values)
    {
        target.Clear();
        foreach (var v in values) target.Add(v);
    }

    [RelayCommand] void Go(AppPage page) => _nav.Navigate(page);
    [RelayCommand] void GoBlocked() => _nav.Navigate(AppPage.History, HistoryViewModel.BlockedTab);

    [RelayCommand]
    void QuickScan() => _nav.Navigate(AppPage.Scans, "quick");

    [RelayCommand]
    async Task UpdateSignaturesAsync()
    {
        Updating = true;
        Info("Recherche de mises à jour des signatures par Microsoft Defender…");
        var r = await _defender.UpdateSignaturesAsync();
        if (r.Success) Success(r.Message); else Fail(r.Message);
        Updating = false;
        Summary = await _state.RefreshAsync();
    }
}

public sealed partial class AntivirusDashboardViewModel : PageViewModel
{
    readonly SecurityStateService _state;
    readonly IDefenderService _defender;
    readonly INavigator _nav;

    public override string Title => "Antivirus";
    public override string Subtitle => "Protection assurée par Microsoft Defender Antivirus. SecureWall affiche son état réel et ne le remplace pas.";

    [ObservableProperty] private SecuritySummary _summary = new();
    [ObservableProperty] private SignatureVersionInfo _signature = new();
    [ObservableProperty] private bool _updating;
    [ObservableProperty] private bool _exclusionsVisible;

    public ObservableCollection<ProtectionFeature> Features { get; } = new();
    public ObservableCollection<string> Exclusions { get; } = new();

    public string DefenderStatusText => !Summary.Defender.Available ? "Microsoft Defender indisponible"
        : Summary.Defender.PassiveMode ? "Defender en mode passif" : Summary.Defender.AntivirusEnabled ? "Protégé par Microsoft Defender" : "Antivirus désactivé";
    public string SignatureAgeText => Signature.AgeDays is { } d ? (d == 0 ? "Signatures à jour (aujourd'hui)" : $"Dernière mise à jour il y a {d} jour(s)") : "Date inconnue";
    public Level SignatureLevel => Signature.AgeDays is { } d && d > 3 ? Level.Warning : Signature.AgeDays == null ? Level.Neutral : Level.Good;

    public AntivirusDashboardViewModel(SecurityStateService state, IDefenderService defender, INavigator nav)
    {
        _state = state; _defender = defender; _nav = nav;
    }

    partial void OnSummaryChanged(SecuritySummary value) => OnPropertyChanged(nameof(DefenderStatusText));
    partial void OnSignatureChanged(SignatureVersionInfo value) { OnPropertyChanged(nameof(SignatureAgeText)); OnPropertyChanged(nameof(SignatureLevel)); }

    public override Task OnNavigatedToAsync() => GuardAsync(LoadAsync, "Chargement de l'antivirus");

    async Task LoadAsync()
    {
        Summary = _state.Current;
        var rt = await _defender.GetRealtimeProtectionStatusAsync(PageToken);
        Features.Clear();
        foreach (var f in rt.Features) Features.Add(f);
        Signature = await _defender.GetSignatureVersionAsync(PageToken);
        var prefs = await _defender.GetPreferencesAsync(PageToken);
        ExclusionsVisible = prefs.ExclusionsVisible;
        Exclusions.Clear();
        foreach (var e in prefs.Exclusions) Exclusions.Add(e);
        Summary = await _state.RefreshAsync(PageToken);
    }

    [RelayCommand]
    async Task UpdateAsync()
    {
        Updating = true;
        Info("Recherche de mises à jour des signatures par Microsoft Defender…");
        var r = await _defender.UpdateSignaturesAsync();
        if (r.Success) Success(r.Message); else Fail(r.Message);
        Updating = false;
        await LoadAsync();
    }

    [RelayCommand] void OpenWindowsSecurity() => Process.Start(new ProcessStartInfo("windowsdefender://threat") { UseShellExecute = true });
    [RelayCommand] void OpenProtectionSettings() => Process.Start(new ProcessStartInfo("windowsdefender://threatsettings") { UseShellExecute = true });
    [RelayCommand] void GoToScans() => _nav.Navigate(AppPage.Scans);
    [RelayCommand] Task Refresh() => GuardAsync(LoadAsync, "Actualisation");
}
