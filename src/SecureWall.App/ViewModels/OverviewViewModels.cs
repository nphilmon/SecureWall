using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using SecureWall.App.Services;
using SecureWall.Security.Devices;
using SecureWall.Security.Monitoring;

namespace SecureWall.App.ViewModels;

public sealed partial class UsbViewModel : PageViewModel
{
    readonly IUsbMonitor _usb;
    readonly ISecurityStore _store;
    readonly IDefenderService _defender;
    readonly ISettingsStore _settings;
    readonly IDialogService _dialogs;

    public override string Title => "USB";
    public override string Subtitle => "Supports amovibles détectés. SecureWall n'en bloque aucun : il propose une analyse Microsoft Defender.";

    public ObservableCollection<UsbDevice> Connected { get; } = new();
    public ObservableCollection<DeviceRecord> Known { get; } = new();
    [ObservableProperty] private UsbDevice? _selected;

    public bool PromptScan
    {
        get => _settings.Current.UsbPromptScan;
        set { _settings.Current.UsbPromptScan = value; _settings.Save(); OnPropertyChanged(); }
    }

    public bool OnlyNew
    {
        get => _settings.Current.UsbOnlyNewDevices;
        set { _settings.Current.UsbOnlyNewDevices = value; _settings.Save(); OnPropertyChanged(); }
    }

    public UsbViewModel(IUsbMonitor usb, ISecurityStore store, IDefenderService defender, ISettingsStore settings, IDialogService dialogs)
    {
        _usb = usb; _store = store; _defender = defender; _settings = settings; _dialogs = dialogs;
    }

    public override async Task OnNavigatedToAsync()
    {
        await GuardAsync(LoadAsync, "Chargement des périphériques");
        StartTimer(TimeSpan.FromSeconds(3), LoadAsync);
    }

    async Task LoadAsync()
    {
        var connected = _usb.Connected.OrderBy(d => d.DriveLetter).ToList();
        var key = Selected?.Identifier;
        Reconciler.Sync(Connected, connected, d => d.DriveLetter, d => d.DriveLetter, d => d, (_, _) => { });
        var known = await Task.Run(_store.GetDevices, PageToken);
        Known.Clear(); foreach (var k in known) Known.Add(k);
        Selected ??= Connected.FirstOrDefault(d => d.Identifier == key) ?? Connected.FirstOrDefault();
    }

    [RelayCommand]
    async Task ScanAsync(UsbDevice? d)
    {
        if (d == null) return;
        await GuardAsync(async () =>
        {
            Info($"Analyse de {d.DisplayName} ({d.DriveLetter}) par Microsoft Defender…");
            var r = await _defender.StartCustomScanAsync(new[] { d.DriveLetter + "\\" });
            if (r.Completed)
            {
                _store.MarkDeviceScanned(d.Identifier);
                d.LastScan = DateTime.Now;
                if (r.ThreatsFound == 0) Success($"{d.DisplayName} : aucune menace détectée par Microsoft Defender.");
                else Fail($"{d.DisplayName} : {r.ThreatsFound} menace(s) détectée(s). Consultez la page Menaces.");
            }
            else Warn($"Analyse {r.Status.ToLowerInvariant()} : {r.Message}");
            await LoadAsync();
            Selected = Connected.FirstOrDefault(x => x.DriveLetter == d.DriveLetter);
        }, "Analyse du périphérique");
    }

    [RelayCommand] void OpenDrive(UsbDevice? d) { if (d != null) Process.Start(new ProcessStartInfo("explorer.exe", d.DriveLetter + "\\") { UseShellExecute = false }); }
}

public sealed partial class HistoryViewModel : PageViewModel, IParameterReceiver
{
    const int PageSize = 200;
    const int BlockedMax = 5000;
    public const string BlockedTab = "blocked";
    readonly ISecurityStore _store;
    readonly IDialogService _dialogs;
    List<FirewallEventRecord> _blockedAll = new();

    public static string[] BlockedPeriods { get; } = { "Dernière heure", "24 heures", "7 jours", "30 jours" };
    public static string[] BlockedDirections { get; } = { "Toutes", "Sortantes", "Entrantes" };
    static readonly TimeSpan[] PeriodSpans = { TimeSpan.FromHours(1), TimeSpan.FromHours(24), TimeSpan.FromDays(7), TimeSpan.FromDays(30) };

    public override string Title => "Historique";
    public override string Subtitle => "Événements de sécurité, journal d'audit des actions SecureWall, analyses et connexions bloquées.";

    public ObservableCollection<SecurityEventRecord> Events { get; } = new();
    public ObservableCollection<AuditLogRecord> Audit { get; } = new();
    public ObservableCollection<ScanRecord> Scans { get; } = new();
    public ObservableCollection<FirewallEventRecord> Blocked { get; } = new();

    [ObservableProperty] private string _search = "";
    [ObservableProperty] private bool _hasMoreEvents;
    [ObservableProperty] private bool _hasMoreAudit;
    [ObservableProperty] private bool _hasMoreScans;

    // Connexions bloquées : filtres, résumé et détail de la ligne sélectionnée
    [ObservableProperty] private int _selectedTab;
    [ObservableProperty] private int _blockedPeriod = 1;
    [ObservableProperty] private int _blockedDirection;
    [ObservableProperty] private string _blockedSearch = "";
    [ObservableProperty] private FirewallEventRecord? _selectedBlocked;
    [ObservableProperty] private string _blockedSummary = "";
    public ObservableCollection<string> TopBlockedApps { get; } = new();
    public ObservableCollection<string> TopBlockedRemotes { get; } = new();
    public ObservableCollection<string> TopBlockedPorts { get; } = new();

    readonly SecureWall.Security.Network.ReverseDnsService _dns;
    [ObservableProperty] private string _blockedHostText = "";
    [ObservableProperty] private bool _blockedHostBusy;
    public bool CanResolveBlockedHost => SelectedBlocked != null && SecureWall.Security.Network.ReverseDnsService.IsResolvable(SelectedBlocked.RemoteAddress, out _);

    public HistoryViewModel(ISecurityStore store, IDialogService dialogs, SecureWall.Security.Network.ReverseDnsService dns) { _store = store; _dialogs = dialogs; _dns = dns; }

    partial void OnSelectedBlockedChanged(FirewallEventRecord? value)
    {
        OnPropertyChanged(nameof(CanResolveBlockedHost));
        // Un nom déjà résolu pendant la session s'affiche sans nouvelle requête ; sinon rien ne part tant que vous ne cliquez pas.
        var cached = value == null ? null : _dns.TryGetCached(value.RemoteAddress);
        BlockedHostText = cached == null ? "" : cached.HasName ? cached.HostName : cached.Message;
    }

    [RelayCommand]
    async Task ResolveBlockedHostAsync()
    {
        var e = SelectedBlocked;
        if (e == null) return;
        try
        {
            BlockedHostBusy = true; BlockedHostText = "Résolution en cours…";
            var r = await _dns.ResolveAsync(e.RemoteAddress, PageToken);
            if (ReferenceEquals(e, SelectedBlocked)) BlockedHostText = r.HasName ? r.HostName : r.Message;
        }
        catch (OperationCanceledException) { BlockedHostText = ""; }
        finally { BlockedHostBusy = false; }
    }

    /// <summary>Navigation depuis le tableau de bord : ouvre directement l'onglet des connexions bloquées.</summary>
    public void Receive(object parameter)
    {
        if (parameter is string s && s == BlockedTab) SelectedTab = 3;
    }

    partial void OnSearchChanged(string value) => _ = GuardAsync(ReloadEventsAsync, "Recherche");
    partial void OnBlockedPeriodChanged(int value) => _ = GuardAsync(ReloadBlockedAsync, "Chargement des connexions bloquées");
    partial void OnBlockedDirectionChanged(int value) => ApplyBlockedFilter();
    partial void OnBlockedSearchChanged(string value) => ApplyBlockedFilter();

    public override async Task OnNavigatedToAsync()
    {
        await GuardAsync(async () =>
        {
            await ReloadEventsAsync();
            var audit = await Task.Run(() => _store.GetAudit(PageSize));
            Audit.Clear(); foreach (var a in audit) Audit.Add(a); HasMoreAudit = audit.Count == PageSize;
            var scans = await Task.Run(() => _store.GetScans(PageSize));
            Scans.Clear(); foreach (var s in scans) Scans.Add(s); HasMoreScans = scans.Count == PageSize;
            await ReloadBlockedAsync();
        }, "Chargement de l'historique");
    }

    async Task ReloadBlockedAsync()
    {
        var since = DateTime.Now - PeriodSpans[Math.Clamp(BlockedPeriod, 0, PeriodSpans.Length - 1)];
        _blockedAll = await Task.Run(() => _store.GetFirewallEvents(since, BlockedMax));
        ApplyBlockedFilter();
    }

    void ApplyBlockedFilter()
    {
        var q = BlockedSearch.Trim();
        var dir = BlockedDirection switch { 1 => "Sortante", 2 => "Entrante", _ => "" };
        var rows = _blockedAll.Where(b =>
            (dir.Length == 0 || b.Direction == dir) &&
            (q.Length == 0 || b.Application.Contains(q, StringComparison.OrdinalIgnoreCase) || b.RemoteAddress.Contains(q, StringComparison.OrdinalIgnoreCase)
                || b.PortText.Contains(q, StringComparison.OrdinalIgnoreCase) || b.Protocol.Contains(q, StringComparison.OrdinalIgnoreCase))).ToList();

        var keep = SelectedBlocked?.Id;
        Blocked.Clear(); foreach (var b in rows) Blocked.Add(b);
        SelectedBlocked = keep == null ? null : rows.FirstOrDefault(b => b.Id == keep);

        BlockedSummary = rows.Count == 0 ? "Aucune connexion bloquée pour ces critères."
            : $"{rows.Count:N0} connexion(s) bloquée(s) · {rows.Select(b => b.Application).Distinct().Count()} application(s) · {rows.Select(b => b.RemoteAddress).Distinct().Count()} adresse(s) distante(s)"
              + (_blockedAll.Count >= BlockedMax ? $" (limité aux {BlockedMax:N0} plus récentes)" : "");
        Fill(TopBlockedApps, rows.GroupBy(b => string.IsNullOrEmpty(b.Application) ? "(inconnu)" : b.Application));
        Fill(TopBlockedRemotes, rows.GroupBy(b => b.RemoteAddress));
        Fill(TopBlockedPorts, rows.Where(b => b.RemotePort > 0).GroupBy(b => b.PortText));
    }

    static void Fill(ObservableCollection<string> target, IEnumerable<IGrouping<string, FirewallEventRecord>> groups)
    {
        target.Clear();
        foreach (var g in groups.OrderByDescending(g => g.Count()).ThenBy(g => g.Key).Take(5)) target.Add($"{g.Key} — {g.Count():N0}");
    }

    [RelayCommand]
    void ExportBlocked()
    {
        if (Blocked.Count == 0) { Info("Aucune connexion à exporter."); return; }
        var path = _dialogs.SaveFile($"connexions-bloquees-{DateTime.Now:yyyyMMdd-HHmm}.csv", "Fichier CSV (*.csv)|*.csv");
        if (path == null) return;
        static string Csv(string v) => "\"" + v.Replace("\"", "\"\"") + "\"";
        var lines = new List<string> { "Date;Application;Direction;Protocole;Adresse distante;Type d'adresse;Port;Service" };
        lines.AddRange(Blocked.Select(b => string.Join(";", Csv(b.Timestamp.ToString("s")), Csv(b.Application), Csv(b.Direction), Csv(b.Protocol),
            Csv(b.RemoteAddress), Csv(b.AddressKind), b.RemotePort, Csv(BlockedConnectionInsights.ServiceName(b.RemotePort)))));
        File.WriteAllLines(path, lines, new System.Text.UTF8Encoding(true));
        Success($"{Blocked.Count:N0} connexion(s) exportée(s).");
    }

    [RelayCommand]
    void CopyBlocked(FirewallEventRecord? e)
    {
        if (e == null) return;
        try { System.Windows.Clipboard.SetText($"{e.TimeText} | {e.Application} | {e.Direction} {e.Protocol} | {e.RemoteAddress}:{e.RemotePort}"); Success("Détail copié."); }
        catch (Exception ex) { Fail("Copie impossible : " + ex.Message); }
    }

    async Task ReloadEventsAsync()
    {
        var q = Search;
        var list = await Task.Run(() => _store.GetEvents(PageSize, 0, q));
        Events.Clear(); foreach (var e in list) Events.Add(e);
        HasMoreEvents = list.Count == PageSize;
    }

    [RelayCommand]
    async Task MoreEventsAsync()
    {
        var q = Search; var off = Events.Count;
        var list = await Task.Run(() => _store.GetEvents(PageSize, off, q));
        foreach (var e in list) Events.Add(e);
        HasMoreEvents = list.Count == PageSize;
    }

    [RelayCommand]
    async Task MoreAuditAsync()
    {
        var off = Audit.Count;
        var list = await Task.Run(() => _store.GetAudit(PageSize, off));
        foreach (var e in list) Audit.Add(e);
        HasMoreAudit = list.Count == PageSize;
    }

    [RelayCommand]
    async Task MoreScansAsync()
    {
        var off = Scans.Count;
        var list = await Task.Run(() => _store.GetScans(PageSize, off));
        foreach (var e in list) Scans.Add(e);
        HasMoreScans = list.Count == PageSize;
    }
}

public sealed record BarItem(string Label, int Value, double Fraction)
{
    public string ValueText => Value.ToString("N0");
    public double Rest => 1 - Fraction;
}

public sealed partial class StatisticsViewModel : PageViewModel
{
    readonly ISecurityStore _store;

    public override string Title => "Statistiques";
    public override string Subtitle => "Calculées à partir des connexions externes et événements enregistrés localement par SecureWall.";

    [ObservableProperty] private string _period = "24h";
    [ObservableProperty] private int _scans;
    [ObservableProperty] private int _threats;
    [ObservableProperty] private int _blocked;
    [ObservableProperty] private int _connectionsTotal;
    [ObservableProperty] private bool _noData;

    public ObservableCollection<BarItem> TopApps { get; } = new();
    public ObservableCollection<BarItem> ByHour { get; } = new();
    public ObservableCollection<BarItem> Ports { get; } = new();
    public ObservableCollection<BarItem> Destinations { get; } = new();
    public ObservableCollection<BarItem> BlockedApps { get; } = new();

    public StatisticsViewModel(ISecurityStore store) => _store = store;

    partial void OnPeriodChanged(string value) => _ = GuardAsync(LoadAsync, "Calcul des statistiques");

    public override Task OnNavigatedToAsync() => GuardAsync(LoadAsync, "Calcul des statistiques");

    static void Fill(ObservableCollection<BarItem> target, Dictionary<string, int> data, Func<string, string>? label = null)
    {
        target.Clear();
        var max = data.Count == 0 ? 1 : data.Values.Max();
        foreach (var kv in data) target.Add(new BarItem(label?.Invoke(kv.Key) ?? kv.Key, kv.Value, (double)kv.Value / Math.Max(1, max)));
    }

    async Task LoadAsync()
    {
        var since = Period switch { "7d" => DateTime.Now.AddDays(-7), "30d" => DateTime.Now.AddDays(-30), _ => DateTime.Now.AddHours(-24) };
        var data = await Task.Run(() => new
        {
            Scans = _store.CountScans(since),
            Threats = _store.CountThreats(since),
            Blocked = _store.CountBlocked(since),
            Apps = _store.TopApplications(since, 10),
            Hours = _store.ConnectionsByHour(since),
            Ports = _store.TopPorts(since, 10),
            Dest = _store.TopDestinations(since, 10),
            BlockedApps = _store.BlockedByApplication(since, 10),
        });
        Scans = data.Scans; Threats = data.Threats; Blocked = data.Blocked;
        ConnectionsTotal = data.Hours.Values.Sum();
        NoData = data.Apps.Count == 0;
        Fill(TopApps, data.Apps);
        var hours = data.Hours;
        if (Period == "24h") hours = hours.TakeLast(24).ToDictionary(k => k.Key, v => v.Value);
        Fill(ByHour, hours, k => Period == "24h" ? k[^5..] : k[5..]);
        Fill(Ports, data.Ports, k => $"Port {k}" + PortName(k));
        Fill(Destinations, data.Dest);
        Fill(BlockedApps, data.BlockedApps);
    }

    static string PortName(string p) => p switch { "443" => " (HTTPS)", "80" => " (HTTP)", "53" => " (DNS)", "5228" => " (Google)", "993" => " (IMAPS)", "587" => " (SMTP)", "123" => " (NTP)", _ => "" };
}

public sealed class SecurityTile
{
    public string Title { get; init; } = "";
    public string Glyph { get; init; } = "";
    public string StatusText { get; init; } = "";
    public Level Level { get; init; }
    public List<string> Lines { get; init; } = new();
    public string ActionText { get; init; } = "";
    public AppPage Page { get; init; }
}

public sealed partial class SecurityCenterViewModel : PageViewModel
{
    readonly SecurityStateService _state;
    readonly INetworkMonitor _network;
    readonly IProcessService _processes;
    readonly IUsbMonitor _usb;
    readonly INavigator _nav;
    readonly SecurityMonitor _monitor;

    public override string Title => "Centre de sécurité";
    public override string Subtitle => "Chaque statut est calculé à partir de l'état réel du système, sans note arbitraire.";

    [ObservableProperty] private SecuritySummary _summary = new();
    public ObservableCollection<SecurityTile> Tiles { get; } = new();
    public ObservableCollection<string> Reasons { get; } = new();

    public SecurityCenterViewModel(SecurityStateService state, INetworkMonitor network, IProcessService processes, IUsbMonitor usb, INavigator nav, SecurityMonitor monitor)
    {
        _state = state; _network = network; _processes = processes; _usb = usb; _nav = nav; _monitor = monitor;
    }

    public override Task OnNavigatedToAsync() => GuardAsync(LoadAsync, "Chargement du centre de sécurité");

    async Task LoadAsync()
    {
        var s = await _state.RefreshAsync(PageToken);
        Summary = s;
        var conns = await _network.GetConnectionsAsync(PageToken);
        var procs = await _processes.GetProcessesAsync(PageToken);
        var products = await WindowsSecurityCenter.ReadAsync();
        var d = s.Defender;

        static string Protected(Level l) => l switch { Level.Good => "Protégé", Level.Warning => "Attention", _ => "Action requise" };
        var tiles = new List<SecurityTile>();

        // Antivirus
        var avLevel = s.ActiveThreats > 0 || !d.Available || !d.AntivirusEnabled || !d.RealTime ? Level.Bad
            : d.PassiveMode || (d.SignatureAgeDays ?? 0) > 3 || d.LastScan is null ? Level.Warning : Level.Good;
        tiles.Add(new SecurityTile
        {
            Title = "Antivirus", Glyph = "", Level = avLevel, StatusText = Protected(avLevel), Page = AppPage.Antivirus, ActionText = "Ouvrir l'antivirus",
            Lines = new()
            {
                !d.Available ? "Microsoft Defender n'est pas accessible." : $"Microsoft Defender : {(d.AntivirusEnabled ? "actif" : "désactivé")}, temps réel {(d.RealTime ? "activé" : "désactivé")}",
                $"Dernière analyse : {d.LastScan?.ToString("g") ?? "aucune"}",
                $"Signatures : {(string.IsNullOrEmpty(d.SignatureVersion) ? "—" : d.SignatureVersion)} ({d.SignatureUpdated?.ToString("g") ?? "date inconnue"})",
                s.ActiveThreats > 0 ? $"{s.ActiveThreats} menace(s) non résolue(s)" : "Aucune menace non résolue",
            },
        });

        // Pare-feu
        var fwLevel = !s.FirewallProtected ? Level.Bad : s.EmergencyActive ? Level.Warning : Level.Good;
        tiles.Add(new SecurityTile
        {
            Title = "Pare-feu", Glyph = "", Level = fwLevel, StatusText = Protected(fwLevel), Page = AppPage.Firewall, ActionText = "Ouvrir le pare-feu",
            Lines = s.Profiles.Select(p => $"Profil {p.Name} : {(p.Enabled ? "activé" : "désactivé")}{(p.IsCurrent ? " (actif)" : "")}")
                .Concat(new[] { $"{s.ActiveRules:N0} règle(s) activée(s) sur {s.TotalRules:N0}" })
                .Concat(s.EmergencyActive ? new[] { "Mode urgence actif : Internet est coupé." } : Array.Empty<string>()).ToList(),
        });

        // Réseau
        var external = conns.Count(c => c.IsEstablished && c.IsExternal);
        var netLevel = !s.ServiceAvailable ? Level.Warning : Level.Good;
        tiles.Add(new SecurityTile
        {
            Title = "Réseau", Glyph = "", Level = netLevel, StatusText = Protected(netLevel), Page = AppPage.Connections, ActionText = "Voir les connexions",
            Lines = new()
            {
                $"{conns.Count(c => c.IsEstablished):N0} connexion(s) établie(s), dont {external:N0} vers l'extérieur",
                s.Networks.FirstOrDefault() is { } n ? $"Réseau « {n.Name} » — profil {n.Category}" : "Aucun réseau détecté",
                s.BlockedLast24h > 0 ? $"{s.BlockedLast24h} connexion(s) bloquée(s) sur 24 h" : (_monitor.BlockedConnectionsAuditing ? "Aucune connexion bloquée sur 24 h" : "Connexions bloquées non journalisées par Windows (audit désactivé)"),
                s.ServiceAvailable ? "Service privilégié actif" : "Service privilégié indisponible : trafic par connexion et modifications du pare-feu impossibles",
            },
        });

        // Processus
        var invalid = procs.Where(p => p.Signature.Status == SignatureStatus.Invalid).ToList();
        var unsigned = procs.Count(p => p.Signature.Status == SignatureStatus.Unsigned);
        var unusual = procs.Count(p => p.UnusualLocation);
        var prLevel = invalid.Count > 0 ? Level.Warning : Level.Good;
        tiles.Add(new SecurityTile
        {
            Title = "Processus", Glyph = "", Level = prLevel, StatusText = Protected(prLevel), Page = AppPage.Processes, ActionText = "Voir les processus",
            Lines = new()
            {
                $"{procs.Count} processus en cours",
                invalid.Count > 0 ? $"{invalid.Count} avec une signature invalide : {string.Join(", ", invalid.Select(p => p.Name).Distinct().Take(3))}" : "Aucune signature invalide",
                $"À titre informatif : {unsigned} non signé(s), {unusual} à un chemin inhabituel (ce n'est pas une preuve de malveillance)",
            },
        });

        // USB
        var devices = _usb.Connected;
        var unscanned = devices.Where(x => x.LastScan is null).ToList();
        var usbLevel = unscanned.Count > 0 ? Level.Warning : Level.Good;
        tiles.Add(new SecurityTile
        {
            Title = "USB", Glyph = "", Level = usbLevel, StatusText = Protected(usbLevel), Page = AppPage.Usb, ActionText = "Voir les périphériques",
            Lines = devices.Count == 0 ? new() { "Aucun support amovible connecté" }
                : devices.Select(x => $"{x.DisplayName} ({x.DriveLetter}) — {(x.LastScan is { } t ? "analysé le " + t.ToString("g") : "jamais analysé")}").ToList(),
        });

        // Protection Windows
        var winLines = new List<string>
        {
            $"Protection contre les falsifications : {(d.Available ? (d.TamperProtected ? "activée" : "désactivée") : "inconnue")}",
            $"Protection du réseau (NIS) : {(d.Available ? (d.NetworkInspection ? "activée" : "désactivée") : "inconnue")}",
        };
        winLines.AddRange(products.Select(p => $"{p.Kind} : {p.Name} — {(p.Enabled ? "actif" : "inactif")}{(p.UpToDate ? "" : ", non à jour")}"));
        var winLevel = d.Available && d.TamperProtected && products.All(p => p.Enabled || p.Kind == "Anti-logiciels espions") ? Level.Good : Level.Warning;
        tiles.Add(new SecurityTile
        {
            Title = "Protection Windows", Glyph = "", Level = winLevel, StatusText = Protected(winLevel), Page = AppPage.Antivirus, ActionText = "Détails Defender", Lines = winLines,
        });

        Tiles.Clear(); foreach (var t in tiles) Tiles.Add(t);
        Reasons.Clear(); foreach (var r in s.Reasons) Reasons.Add(r);
    }

    [RelayCommand] void Open(SecurityTile? t) { if (t != null) _nav.Navigate(t.Page); }
    [RelayCommand] void OpenWindowsSecurity() => Process.Start(new ProcessStartInfo("windowsdefender://") { UseShellExecute = true });
    [RelayCommand] Task Refresh() => GuardAsync(LoadAsync, "Actualisation");
}

public sealed partial class SettingsViewModel : PageViewModel
{
    const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    readonly ISettingsStore _settings;
    readonly ThemeService _theme;
    readonly IDialogService _dialogs;
    readonly ISecurityStore _store;
    readonly IPrivilegedClient _client;
    readonly IAuditLog _audit;
    readonly SecurityStateService _state;
    readonly SecureWall.Security.Updates.AppUpdateService _updates;
    SecureWall.Security.Updates.UpdateManifest? _pendingUpdate;
    FileStream? _installerLock;   // verrou sur l'installateur vérifié, conservé jusqu'à la fermeture de l'application

    // Mise à jour de l'application
    [ObservableProperty] private string _updateUrl = "";
    [ObservableProperty] private string _updateStatus = "";
    [ObservableProperty] private Level _updateLevel = Level.Neutral;
    [ObservableProperty] private string _updateLastCheck = "";
    [ObservableProperty] private bool _updateIndeterminate;   // recherche (durée inconnue) ; faux pendant le téléchargement, qui a un pourcentage
    [ObservableProperty] private string _updateNotes = "";
    [ObservableProperty] private bool _updateAvailable;
    [ObservableProperty] private bool _updateBusy;
    [ObservableProperty] private double _updateProgress;
    public string UpdateInstallText => _pendingUpdate == null ? "" : $"Télécharger et installer la version {_pendingUpdate.Version}";

    public override string Title => "Paramètres";
    public override string Subtitle => "Toutes les données restent sur cet ordinateur.";

    [ObservableProperty] private bool _serviceAvailable;
    [ObservableProperty] private string _serviceText = "Vérification…";
    [ObservableProperty] private bool _startWithWindows;
    public string DataFolder => SecureWall.Infrastructure.Configuration.AppPaths.UserDataDir;
    public string Version => typeof(SettingsViewModel).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
    public bool IsAdmin => SecureWall.Infrastructure.Windows.Elevation.IsAdmin;

    AppSettings S => _settings.Current;
    void Set<T>(Action<AppSettings> a) { a(S); _settings.Save(); }

    public bool MinimizeToTray { get => S.MinimizeToTray; set { Set<bool>(s => s.MinimizeToTray = value); OnPropertyChanged(); } }
    public int RefreshSeconds { get => S.RefreshSeconds; set { Set<int>(s => s.RefreshSeconds = Math.Clamp(value, 1, 60)); OnPropertyChanged(); } }
    public bool NotificationsEnabled { get => S.NotificationsEnabled; set { Set<bool>(s => s.NotificationsEnabled = value); OnPropertyChanged(); } }
    public bool NotifyThreats { get => S.NotifyThreats; set { Set<bool>(s => s.NotifyThreats = value); OnPropertyChanged(); } }
    public bool NotifyScans { get => S.NotifyScans; set { Set<bool>(s => s.NotifyScans = value); OnPropertyChanged(); } }
    public bool NotifyFirewall { get => S.NotifyFirewall; set { Set<bool>(s => s.NotifyFirewall = value); OnPropertyChanged(); } }
    public bool NotifyUsb { get => S.NotifyUsb; set { Set<bool>(s => s.NotifyUsb = value); OnPropertyChanged(); } }
    public bool NotifySignatures { get => S.NotifySignatures; set { Set<bool>(s => s.NotifySignatures = value); OnPropertyChanged(); } }
    public bool UsbPromptScan { get => S.UsbPromptScan; set { Set<bool>(s => s.UsbPromptScan = value); OnPropertyChanged(); } }
    public bool UsbOnlyNew { get => S.UsbOnlyNewDevices; set { Set<bool>(s => s.UsbOnlyNewDevices = value); OnPropertyChanged(); } }
    public bool AlertNewApps { get => S.AlertNewNetworkApps; set { Set<bool>(s => s.AlertNewNetworkApps = value); OnPropertyChanged(); } }
    public bool ConfirmRules { get => S.ConfirmRuleChanges; set { Set<bool>(s => s.ConfirmRuleChanges = value); OnPropertyChanged(); } }
    public bool MonitorChanges { get => S.MonitorSecurityChanges; set { Set<bool>(s => s.MonitorSecurityChanges = value); OnPropertyChanged(); } }
    public bool RecordConnections { get => S.RecordConnections; set { Set<bool>(s => s.RecordConnections = value); OnPropertyChanged(); } }
    public int RetentionDays { get => S.RetentionDays; set { Set<int>(s => s.RetentionDays = Math.Clamp(value, 7, 3650)); OnPropertyChanged(); } }
    public bool ThemeSystem { get => S.Theme == ThemeMode.System; set { if (value) SetTheme(ThemeMode.System); } }
    public bool ThemeLight { get => S.Theme == ThemeMode.Light; set { if (value) SetTheme(ThemeMode.Light); } }
    public bool ThemeDark { get => S.Theme == ThemeMode.Dark; set { if (value) SetTheme(ThemeMode.Dark); } }

    void SetTheme(ThemeMode m)
    {
        S.Theme = m; _settings.Save(); _theme.Apply();
        OnPropertyChanged(nameof(ThemeSystem)); OnPropertyChanged(nameof(ThemeLight)); OnPropertyChanged(nameof(ThemeDark));
    }

    public SettingsViewModel(ISettingsStore settings, ThemeService theme, IDialogService dialogs, ISecurityStore store, IPrivilegedClient client, IAuditLog audit, SecurityStateService state,
        SecureWall.Security.Updates.AppUpdateService updates)
    {
        _settings = settings; _theme = theme; _dialogs = dialogs; _store = store; _client = client; _audit = audit; _state = state; _updates = updates;
        // Réglage vide (enregistré avant l'ajout de l'adresse officielle) : on propose l'adresse par défaut.
        _updateUrl = string.IsNullOrWhiteSpace(settings.Current.AppUpdateUrl) ? AppSettings.DefaultAppUpdateUrl : settings.Current.AppUpdateUrl;
    }

    [RelayCommand]
    async Task CheckUpdateAsync()
    {
        if (string.IsNullOrWhiteSpace(UpdateUrl)) { UpdateStatus = "Saisissez l'adresse du manifeste de mise à jour."; UpdateLevel = Level.Warning; return; }
        try
        {
            UpdateBusy = true; UpdateIndeterminate = true; UpdateAvailable = false; UpdateNotes = ""; _pendingUpdate = null; OnPropertyChanged(nameof(UpdateInstallText));
            UpdateStatus = "Recherche en cours…"; UpdateLevel = Level.Info;
            _settings.Current.AppUpdateUrl = UpdateUrl.Trim(); _settings.Save();
            var r = await _updates.CheckAsync(UpdateUrl.Trim());
            UpdateStatus = r.Message;
            // Vert : à jour ; bleu : nouvelle version ; rouge : recherche impossible ou manifeste refusé.
            UpdateLevel = r.Manifest != null ? Level.Info : r.UpToDate ? Level.Good : Level.Bad;
            if (r.Manifest is { } m)
            {
                _pendingUpdate = m; UpdateAvailable = true;
                UpdateNotes = string.IsNullOrWhiteSpace(m.Notes) ? "" : m.Notes.Trim();
                OnPropertyChanged(nameof(UpdateInstallText));
            }
        }
        catch (Exception ex) { AppLog.Error(ex, "Recherche de mise à jour"); UpdateStatus = "Recherche impossible : " + ex.Message; UpdateLevel = Level.Bad; }
        finally
        {
            UpdateBusy = false; UpdateIndeterminate = false;
            UpdateLastCheck = "Dernière vérification : " + DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss");   // change à chaque clic, même si le résultat est identique
        }
    }

    [RelayCommand]
    async Task InstallUpdateAsync()
    {
        if (_pendingUpdate is not { } m) return;
        if (!_dialogs.Confirm("Installer la mise à jour",
                $"SecureWall {m.Version} va être téléchargé depuis GitHub ({m.Size / 1024.0 / 1024.0:N1} Mo), puis son empreinte SHA-256 sera comparée à celle du manifeste signé.\n\n" +
                "L'installateur se lance ensuite et Windows vous demandera l'autorisation de l'exécuter. Vos réglages et votre historique sont conservés.", "Télécharger", warning: false)) return;
        try
        {
            _installerLock?.Dispose(); _installerLock = null;   // libère un installateur déjà préparé avant d'en télécharger un autre
            UpdateBusy = true; UpdateIndeterminate = false; UpdateProgress = 0; UpdateStatus = "Téléchargement en cours…"; UpdateLevel = Level.Info;
            var dir = Path.Combine(SecureWall.Infrastructure.Configuration.AppPaths.UserDataDir, "updates");
            var (path, msg) = await _updates.DownloadAsync(m, dir, new Progress<double>(p => UpdateProgress = p));
            UpdateStatus = msg; UpdateLevel = path == null ? Level.Bad : Level.Good;
            if (path == null) return;
            // Verrou + contrôle final : le fichier ne peut plus être remplacé entre ici et son exécution avec élévation.
            var (locked, lockMsg) = _updates.OpenVerified(path, m);
            if (locked == null) { UpdateStatus = lockMsg; UpdateLevel = Level.Bad; return; }
            _installerLock = locked;
            _audit.Write("Mise à jour de l'application", $"Lancement de l'installateur {m.Version}");
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(path) { UseShellExecute = true, Verb = "runas" });
            UpdateStatus = "Installateur lancé. Suivez l'assistant ; SecureWall se fermera pour la mise à jour si nécessaire.";
        }
        catch (System.ComponentModel.Win32Exception) { UpdateStatus = "Installation annulée (autorisation Windows refusée)."; UpdateLevel = Level.Warning; }
        catch (Exception ex) { AppLog.Error(ex, "Installation de la mise à jour"); UpdateStatus = "Échec : " + ex.Message; UpdateLevel = Level.Bad; }
        finally { UpdateBusy = false; }
    }

    public override async Task OnNavigatedToAsync()
    {
        using (var k = Registry.CurrentUser.OpenSubKey(RunKeyPath)) StartWithWindows = k?.GetValue("SecureWall") != null;
        ServiceAvailable = await _client.IsAvailableAsync(PageToken);
        ServiceText = ServiceAvailable ? "Service privilégié SecureWall : actif" : "Service privilégié SecureWall : non démarré ou non installé";
    }

    partial void OnStartWithWindowsChanged(bool value)
    {
        try
        {
            using var k = Registry.CurrentUser.CreateSubKey(RunKeyPath, writable: true);
            if (value) k.SetValue("SecureWall", $"\"{Environment.ProcessPath}\" --minimized");
            else k.DeleteValue("SecureWall", throwOnMissingValue: false);
            _audit.Write("Démarrage avec Windows", value ? "Activé" : "Désactivé");
        }
        catch (Exception ex) { Fail("Impossible de modifier le démarrage avec Windows : " + ex.Message); }
    }

    [RelayCommand]
    void ExportSettings()
    {
        var path = _dialogs.SaveFile("reglages-securewall.json", "Réglages SecureWall (*.json)|*.json");
        if (path == null) return;
        File.WriteAllText(path, _settings.ExportJson());
        _audit.Write("Sauvegarde des réglages", Path.GetFileName(path));
        Success("Réglages exportés.");
    }

    [RelayCommand]
    void ImportSettings()
    {
        var path = _dialogs.PickFile("Réglages SecureWall (*.json)|*.json", "Importer des réglages");
        if (path == null) return;
        if (!_dialogs.Confirm("Importer les réglages", "Les réglages actuels seront remplacés par ceux du fichier.", "Importer")) return;
        var r = _settings.ImportJson(File.ReadAllText(path));
        _audit.Write("Restauration des réglages", Path.GetFileName(path) + (r.Success ? "" : " — échec"));
        if (r.Success) { _theme.Apply(); Success(r.Message + " Rouvrez la page pour voir les valeurs à jour."); } else Fail(r.Message);
    }

    [RelayCommand]
    void ClearHistory()
    {
        if (!_dialogs.Confirm("Effacer l'historique",
                "Supprimer définitivement l'historique local de SecureWall : événements, journal d'audit, analyses, applications réseau, connexions et statistiques ?\n\n" +
                "L'historique de protection de Microsoft Defender (Windows Security) n'est pas concerné.", "Tout effacer", warning: true)) return;
        _store.ClearHistory();
        _audit.Write("Nettoyage de l'historique", "Historique local effacé");
        Success("Historique local effacé.");
    }

    [RelayCommand]
    void ClearLogs()
    {
        if (!_dialogs.Confirm("Supprimer les journaux", "Supprimer les fichiers journaux de l'application ?", "Supprimer")) return;
        try
        {
            foreach (var f in Directory.GetFiles(SecureWall.Infrastructure.Configuration.AppPaths.LogDir, "*.log"))
                try { File.Delete(f); } catch { /* fichier en cours d'utilisation */ }
            Success("Journaux supprimés.");
        }
        catch (Exception ex) { Fail(ex.Message); }
    }

    [RelayCommand] void OpenDataFolder() => Process.Start(new ProcessStartInfo("explorer.exe", DataFolder) { UseShellExecute = false });
    [RelayCommand] void RunFirstRun() { _settings.Current.FirstRunCompleted = false; _settings.Save(); App.Current.ShowFirstRun(); }
}
