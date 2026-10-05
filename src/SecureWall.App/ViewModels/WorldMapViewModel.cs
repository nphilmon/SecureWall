using System.Collections.ObjectModel;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureWall.App.Services;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Logic;
using SecureWall.Core.Models;
using SecureWall.Security.Network;

namespace SecureWall.App.ViewModels;

/// <summary>Un pays dessiné sur la carte.</summary>
public sealed partial class MapCountry : ObservableObject
{
    public string Code { get; }
    public string Name { get; }
    public Geometry Geometry { get; }

    [ObservableProperty] private int _connections;
    [ObservableProperty] private double _intensity;
    [ObservableProperty] private bool _isSelected;

    public bool HasTraffic => Connections > 0;
    public string Tooltip => Connections > 0 ? $"{Name}\n{Connections:N0} connexion(s)" : Name;
    partial void OnConnectionsChanged(int value) { OnPropertyChanged(nameof(HasTraffic)); OnPropertyChanged(nameof(Tooltip)); }

    public MapCountry(MapShape shape, string displayName)
    {
        Code = shape.Code; Name = displayName;
        Geometry = Geometry.Parse(shape.PathData);
        Geometry.Freeze();
    }
}

public sealed partial class WorldMapViewModel : PageViewModel
{
    static readonly Lazy<WorldMapData> MapData = new(LoadMap);
    static readonly TimeSpan[] PeriodSpans = { TimeSpan.Zero, TimeSpan.FromHours(24), TimeSpan.FromDays(7), TimeSpan.FromDays(30) };
    public static string[] Periods { get; } = { "En ce moment", "24 heures", "7 jours", "30 jours" };

    readonly ISecurityStore _store;
    readonly INetworkMonitor _network;
    readonly GeoLocationService _geo;
    readonly ISettingsStore _settings;
    readonly IDialogService _dialogs;
    readonly IAuditLog _audit;

    public override string Title => "Carte des connexions";
    public override string Subtitle => "Pays des serveurs contactés par les applications de ce PC.";

    public double MapWidth => MapData.Value.Width;
    public double MapHeight => MapData.Value.Height;
    public ObservableCollection<MapCountry> Countries { get; } = new();
    public ObservableCollection<CountryStat> Stats { get; } = new();

    [ObservableProperty] private int _period = 1;
    [ObservableProperty] private CountryStat? _selectedStat;
    [ObservableProperty] private string _summaryText = "";
    [ObservableProperty] private string _geoStatus = "";
    [ObservableProperty] private bool _geoEnabled;

    public bool HasSelection => SelectedStat != null;
    public string SelectedTitle => SelectedStat == null ? "" : $"{SelectedStat.Name} — {SelectedStat.Connections:N0} connexion(s), {SelectedStat.Addresses:N0} adresse(s)";

    public WorldMapViewModel(ISecurityStore store, INetworkMonitor network, GeoLocationService geo, ISettingsStore settings, IDialogService dialogs, IAuditLog audit)
    {
        _store = store; _network = network; _geo = geo; _settings = settings; _dialogs = dialogs; _audit = audit;
        _geoEnabled = geo.Enabled;
    }

    static WorldMapData LoadMap()
    {
        var asm = typeof(WorldMapViewModel).Assembly;
        var name = asm.GetManifestResourceNames().Single(n => n.EndsWith("world-map.txt", StringComparison.Ordinal));
        using var s = asm.GetManifestResourceStream(name)!;
        using var r = new StreamReader(s);
        return WorldMapData.Parse(r.ReadToEnd());
    }

    void EnsureShapes()
    {
        if (Countries.Count > 0) return;
        foreach (var shape in MapData.Value.Shapes) Countries.Add(new MapCountry(shape, CountryTraffic.NameOf(shape.Code)));
    }

    public override async Task OnNavigatedToAsync()
    {
        EnsureShapes();
        GeoEnabled = _geo.Enabled;
        await GuardAsync(LoadAsync, "Chargement de la carte");
        StartTimer(TimeSpan.FromSeconds(20), () => Period == 0 ? LoadAsync() : Task.CompletedTask);
    }

    partial void OnPeriodChanged(int value) => _ = GuardAsync(LoadAsync, "Chargement de la carte");

    async Task LoadAsync()
    {
        var ct = PageToken;
        List<RemoteTraffic> rows;
        if (Period == 0)
        {
            var now = DateTime.Now;
            var conns = await _network.GetConnectionsAsync(ct);
            rows = conns.Where(c => c.IsExternal && !c.IsListening && !string.IsNullOrEmpty(c.RemoteAddress))
                .GroupBy(c => (c.RemoteAddress, c.RemotePort, App: string.IsNullOrEmpty(c.ProcessName) ? "(inconnu)" : c.ProcessName))
                .Select(g => new RemoteTraffic(g.Key.RemoteAddress, g.Key.RemotePort, g.Key.App, g.Count(), now)).ToList();
        }
        else
        {
            var since = DateTime.Now - PeriodSpans[Math.Clamp(Period, 0, PeriodSpans.Length - 1)];
            rows = await Task.Run(() => _store.GetRemoteTraffic(since), ct);
        }

        GeoStatus = _geo.Enabled ? "Localisation en ligne active." : "";
        var ordered = rows.GroupBy(r => r.Address).OrderByDescending(g => g.Sum(x => x.Connections)).Select(g => g.Key).ToList();
        if (_geo.Enabled && ordered.Any(GeoLocationService.IsLocatable)) GeoStatus = "Localisation des nouvelles adresses…";
        var geo = await _geo.LocateAsync(ordered, ct);
        ct.ThrowIfCancellationRequested();

        var stats = CountryTraffic.Build(rows, geo.Countries);
        ApplyStats(stats);
        GeoEnabled = _geo.Enabled;
        GeoStatus = geo.Warning.Length > 0 ? geo.Warning
            : geo.Remaining > 0 ? $"{geo.Remaining} adresse(s) seront localisées à la prochaine actualisation (limite de {GeoLocationService.MaxNewPerRun} nouvelles adresses par recherche)."
            : !_geo.Enabled && stats.Any(s => s.Code == CountryTraffic.UnknownCode) ? "Pays inconnus : activez la localisation en ligne pour les identifier."
            : geo.QueriedOnline > 0 ? $"{geo.QueriedOnline} nouvelle(s) adresse(s) localisée(s) en ligne." : "";
    }

    void ApplyStats(List<CountryStat> stats)
    {
        var keep = SelectedStat?.Code;
        var max = stats.Where(s => s.IsReal).Select(s => s.Connections).DefaultIfEmpty(0).Max();
        var byCode = stats.ToDictionary(s => s.Code);
        foreach (var c in Countries)
        {
            var n = byCode.TryGetValue(c.Code, out var s) ? s.Connections : 0;
            c.Connections = n; c.Intensity = CountryTraffic.Intensity(n, max);
        }
        Stats.Clear(); foreach (var s in stats) Stats.Add(s);
        SelectedStat = keep == null ? null : Stats.FirstOrDefault(s => s.Code == keep);

        var real = stats.Where(s => s.IsReal).ToList();
        var total = stats.Sum(s => s.Connections);
        SummaryText = total == 0 ? "Aucune connexion enregistrée sur cette période."
            : $"{total:N0} connexion(s) · {real.Count} pays" + (stats.FirstOrDefault(s => s.Code == CountryTraffic.LocalCode) is { } l ? $" · {l.Connections:N0} sur le réseau local" : "");
    }

    partial void OnSelectedStatChanged(CountryStat? value)
    {
        foreach (var c in Countries) c.IsSelected = value != null && c.Code == value.Code;
        OnPropertyChanged(nameof(HasSelection)); OnPropertyChanged(nameof(SelectedTitle));
    }

    [RelayCommand]
    void SelectCountry(MapCountry? country)
    {
        if (country == null) return;
        SelectedStat = Stats.FirstOrDefault(s => s.Code == country.Code);
        if (SelectedStat == null) Info($"{country.Name} : aucune connexion sur cette période.");
    }

    [RelayCommand] Task RefreshAsync() => GuardAsync(LoadAsync, "Actualisation de la carte");

    [RelayCommand]
    async Task EnableGeoAsync()
    {
        if (!_dialogs.Confirm("Localiser les adresses en ligne",
                "Pour connaître le pays d'un serveur, SecureWall interroge le service en ligne api.country.is (connexion HTTPS).\n\n" +
                "• Il reçoit l'adresse IP PUBLIQUE des serveurs que votre PC contacte, par lots, uniquement celles jamais localisées. Il peut ainsi déduire quels serveurs vous contactez, et connaît votre adresse IP publique comme tout site visité.\n" +
                "• Il ne reçoit ni nom d'application, ni nom d'utilisateur, ni adresse du réseau local.\n" +
                "• Les pays trouvés sont conservés sur ce PC (30 jours) pour ne pas redemander.\n\n" +
                "Vous pouvez désactiver cette option et effacer ces données à tout moment.", "Activer la localisation en ligne")) return;
        _settings.Current.GeoLookupEnabled = true; _settings.Save();
        _audit.Write("Localisation des adresses", "Activée (service en ligne api.country.is)");
        GeoEnabled = true;
        await GuardAsync(LoadAsync, "Chargement de la carte");
    }

    [RelayCommand]
    async Task DisableGeoAsync()
    {
        _settings.Current.GeoLookupEnabled = false; _settings.Save();
        _audit.Write("Localisation des adresses", "Désactivée");
        GeoEnabled = false;
        await GuardAsync(LoadAsync, "Chargement de la carte");
        Info("Localisation en ligne désactivée. Les pays déjà connus restent affichés ; aucune nouvelle adresse n'est envoyée.");
    }

    [RelayCommand]
    async Task ClearGeoCacheAsync()
    {
        if (!_dialogs.Confirm("Effacer les pays enregistrés", "Les pays déjà trouvés seront supprimés de ce PC. Ils seront redemandés au service en ligne si la localisation est activée.", "Effacer", warning: true)) return;
        var n = _geo.ClearCache();
        _audit.Write("Localisation des adresses", $"Cache effacé ({n} adresse(s))");
        await GuardAsync(LoadAsync, "Chargement de la carte");
        Success($"{n} adresse(s) effacée(s) du cache de localisation.");
    }
}
