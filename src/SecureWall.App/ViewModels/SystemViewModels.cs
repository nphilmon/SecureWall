using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureWall.App.Services;
using SecureWall.Infrastructure.Windows;

namespace SecureWall.App.ViewModels;

/// <summary>Icônes des exécutables (cache, extraction à la demande).</summary>
public static class IconCache
{
    static readonly Dictionary<string, BitmapSource?> Cache = new(StringComparer.OrdinalIgnoreCase);

    public static BitmapSource? Get(string path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        lock (Cache)
        {
            if (Cache.TryGetValue(path, out var c)) return c;
            BitmapSource? bmp = null;
            try
            {
                if (File.Exists(path))
                {
                    using var icon = System.Drawing.Icon.ExtractAssociatedIcon(path);
                    if (icon != null)
                    {
                        bmp = Imaging.CreateBitmapSourceFromHIcon(icon.Handle, System.Windows.Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                        bmp.Freeze();
                    }
                }
            }
            catch { /* icône indisponible */ }
            Cache[path] = bmp;
            return bmp;
        }
    }
}

public sealed partial class ProcessRow : ObservableObject
{
    public int Pid { get; }
    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _user = "";
    [ObservableProperty] private string _path = "";
    [ObservableProperty] private string _publisher = "—";
    [ObservableProperty] private string _signatureText = "";
    [ObservableProperty] private Level _signatureLevel;
    [ObservableProperty] private double _cpu;
    [ObservableProperty] private double _memoryMb;
    [ObservableProperty] private int _connections;
    [ObservableProperty] private string _startText = "";
    [ObservableProperty] private string _indicators = "";
    public SignatureStatus SignatureStatus { get; private set; }
    public bool Unusual { get; private set; }
    public System.Windows.Media.ImageSource? Icon => IconCache.Get(Path);

    public ProcessRow(ProcessEntry e) { Pid = e.Pid; Update(e); }

    public void Update(ProcessEntry e)
    {
        Name = e.Name; User = e.User; Path = e.Path; Publisher = e.Publisher; SignatureText = e.Signature.Text; SignatureLevel = e.Signature.Level;
        Cpu = Math.Round(e.Cpu, 1); MemoryMb = Math.Round(e.MemoryMb, 0); Connections = e.Connections; StartText = e.StartText; Indicators = e.Indicators;
        SignatureStatus = e.Signature.Status; Unusual = e.UnusualLocation;
    }
}

public sealed partial class ProcessMonitorViewModel : PageViewModel
{
    readonly IProcessService _processes;
    readonly ProgramActions _actions;
    readonly INavigator _nav;

    public override string Title => "Processus";
    public override string Subtitle => "Les indicateurs sont des faits : un processus non signé ou inhabituel n'est pas pour autant un logiciel malveillant.";

    public ObservableCollection<ProcessRow> Items { get; } = new();
    public ICollectionView View { get; }

    [ObservableProperty] private string _search = "";
    [ObservableProperty] private bool _onlyNetwork;
    [ObservableProperty] private bool _onlyUnsigned;
    [ObservableProperty] private ProcessRow? _selected;
    [ObservableProperty] private string _countText = "";

    public ProcessMonitorViewModel(IProcessService processes, ProgramActions actions, INavigator nav)
    {
        _processes = processes; _actions = actions; _nav = nav;
        View = CollectionViewSource.GetDefaultView(Items);
        View.Filter = o => o is ProcessRow r && Matches(r);
    }

    bool Matches(ProcessRow r)
    {
        if (OnlyNetwork && r.Connections == 0) return false;
        if (OnlyUnsigned && r.SignatureStatus is SignatureStatus.SignedValid or SignatureStatus.Pending) return false;
        if (string.IsNullOrWhiteSpace(Search)) return true;
        return r.Name.Contains(Search, StringComparison.OrdinalIgnoreCase) || r.Path.Contains(Search, StringComparison.OrdinalIgnoreCase)
               || r.Publisher.Contains(Search, StringComparison.OrdinalIgnoreCase) || r.Pid.ToString() == Search.Trim();
    }

    partial void OnSearchChanged(string value) => View.Refresh();
    partial void OnOnlyNetworkChanged(bool value) => View.Refresh();
    partial void OnOnlyUnsignedChanged(bool value) => View.Refresh();

    public override async Task OnNavigatedToAsync()
    {
        await GuardAsync(RefreshAsync, "Chargement des processus");
        StartTimer(TimeSpan.FromSeconds(5), RefreshAsync);
    }

    async Task RefreshAsync()
    {
        var list = await _processes.GetProcessesAsync(PageToken);
        Reconciler.Sync(Items, list, e => e.Pid, r => r.Pid, e => new ProcessRow(e), (r, e) => r.Update(e));
        CountText = $"{Items.Count} processus";
        View.Refresh();
    }

    [RelayCommand] Task Analyze(ProcessRow? r) { if (r != null && !string.IsNullOrEmpty(r.Path)) _actions.Analyze(r.Path); return Task.CompletedTask; }
    [RelayCommand] void OpenLocation(ProcessRow? r) { if (r != null) _actions.OpenLocation(r.Path); }
    [RelayCommand] void Properties(ProcessRow? r) { if (r != null) _actions.Properties(r.Path); }
    [RelayCommand] void ShowConnections(ProcessRow? r) { if (r != null) _nav.Navigate(AppPage.Connections, new ConnectionFilter(Pid: r.Pid)); }
    [RelayCommand] Task ScanFile(ProcessRow? r) => r == null ? Task.CompletedTask : _actions.ScanFileAsync(r.Path);
}

public sealed partial class ConnectionRow : ObservableObject
{
    public string Key { get; }
    public int Pid { get; }
    public string Protocol { get; }
    public string ProcessName { get; }
    public string ProcessPath { get; }
    public string Local { get; }
    public string Remote { get; }
    public string RemoteAddress { get; }
    public int LocalPort { get; }
    public int RemotePort { get; }
    public bool IsExternal { get; }
    public bool IsListening { get; }
    [ObservableProperty] private string _state = "";
    [ObservableProperty] private string _sent = "—";
    [ObservableProperty] private string _received = "—";
    public System.Windows.Media.ImageSource? Icon => IconCache.Get(ProcessPath);
    public string Scope => IsListening ? "Écoute" : IsExternal ? "Externe" : "Local";

    public static string KeyOf(NetConnection c) => $"{c.Protocol}|{c.LocalAddress}:{c.LocalPort}|{c.RemoteAddress}:{c.RemotePort}|{c.Pid}";

    public ConnectionRow(NetConnection c)
    {
        Key = KeyOf(c); Pid = c.Pid; Protocol = c.Protocol; ProcessName = c.ProcessName; ProcessPath = c.ProcessPath;
        Local = c.Local; Remote = c.Remote; RemoteAddress = c.RemoteAddress; LocalPort = c.LocalPort; RemotePort = c.RemotePort;
        IsExternal = c.IsExternal; IsListening = c.IsListening;
        Update(c);
    }

    public void Update(NetConnection c) { State = c.State; Sent = c.SentText; Received = c.ReceivedText; }
}

public sealed partial class ConnectionsViewModel : PageViewModel, IParameterReceiver
{
    readonly INetworkMonitor _network;
    readonly ProgramActions _actions;
    readonly ISettingsStore _settings;

    public override string Title => "Connexions";
    public override string Subtitle => "Connexions TCP/UDP actives, par processus. Les octets par connexion proviennent du service privilégié (TCP IPv4).";

    public ObservableCollection<ConnectionRow> Items { get; } = new();
    public ICollectionView View { get; }
    public string[] ProtocolOptions { get; } = { "Tous", "TCP", "UDP" };
    public string[] StateOptions { get; } = { "Tous", "Établie", "À l'écoute", "Sans connexion", "Autres" };

    [ObservableProperty] private string _appFilter = "";
    [ObservableProperty] private string _protocol = "Tous";
    [ObservableProperty] private string _portFilter = "";
    [ObservableProperty] private string _ipFilter = "";
    [ObservableProperty] private string _stateFilter = "Tous";
    [ObservableProperty] private bool _hideLocal;
    [ObservableProperty] private bool _hideListening = true;
    [ObservableProperty] private int? _pidFilter;
    [ObservableProperty] private ConnectionRow? _selected;
    [ObservableProperty] private string _countText = "";

    public ConnectionsViewModel(INetworkMonitor network, ProgramActions actions, ISettingsStore settings)
    {
        _network = network; _actions = actions; _settings = settings;
        View = CollectionViewSource.GetDefaultView(Items);
        View.Filter = o => o is ConnectionRow r && Matches(r);
    }

    public void Receive(object parameter)
    {
        if (parameter is ConnectionFilter f)
        {
            PidFilter = f.Pid; AppFilter = f.Application ?? "";
            HideListening = false; HideLocal = false; StateFilter = "Tous"; Protocol = "Tous"; PortFilter = ""; IpFilter = "";
        }
    }

    bool Matches(ConnectionRow r)
    {
        if (PidFilter is { } pid && r.Pid != pid) return false;
        if (HideLocal && !r.IsExternal) return false;
        if (HideListening && r.IsListening) return false;
        if (Protocol != "Tous" && r.Protocol != Protocol) return false;
        if (!string.IsNullOrWhiteSpace(AppFilter) && !r.ProcessName.Contains(AppFilter, StringComparison.OrdinalIgnoreCase) && !r.ProcessPath.Contains(AppFilter, StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.IsNullOrWhiteSpace(PortFilter) && !(r.LocalPort.ToString() == PortFilter.Trim() || r.RemotePort.ToString() == PortFilter.Trim())) return false;
        if (!string.IsNullOrWhiteSpace(IpFilter) && !r.Local.Contains(IpFilter.Trim(), StringComparison.OrdinalIgnoreCase) && !r.Remote.Contains(IpFilter.Trim(), StringComparison.OrdinalIgnoreCase)) return false;
        if (StateFilter != "Tous")
        {
            var known = new[] { "Établie", "À l'écoute", "Sans connexion" };
            if (StateFilter == "Autres" ? known.Contains(r.State) : r.State != StateFilter) return false;
        }
        return true;
    }

    partial void OnAppFilterChanged(string value) => View.Refresh();
    partial void OnProtocolChanged(string value) => View.Refresh();
    partial void OnPortFilterChanged(string value) => View.Refresh();
    partial void OnIpFilterChanged(string value) => View.Refresh();
    partial void OnStateFilterChanged(string value) => View.Refresh();
    partial void OnHideLocalChanged(bool value) => View.Refresh();
    partial void OnHideListeningChanged(bool value) => View.Refresh();
    partial void OnPidFilterChanged(int? value) => View.Refresh();

    public override async Task OnNavigatedToAsync()
    {
        await GuardAsync(RefreshAsync, "Chargement des connexions");
        StartTimer(TimeSpan.FromSeconds(Math.Max(2, _settings.Current.RefreshSeconds)), RefreshAsync);
    }

    async Task RefreshAsync()
    {
        var list = await _network.GetConnectionsAsync(PageToken);
        Reconciler.Sync(Items, list, ConnectionRow.KeyOf, r => r.Key, c => new ConnectionRow(c), (r, c) => r.Update(c));
        CountText = $"{View.Cast<object>().Count():N0} affichées sur {Items.Count:N0}";
        View.Refresh();
    }

    [RelayCommand] void ClearPid() => PidFilter = null;
    [RelayCommand] void OpenLocation(ConnectionRow? r) { if (r != null) _actions.OpenLocation(r.ProcessPath); }
    [RelayCommand] void Analyze(ConnectionRow? r) { if (r != null && !string.IsNullOrEmpty(r.ProcessPath)) _actions.Analyze(r.ProcessPath); }
    [RelayCommand]
    void CopyRemote(ConnectionRow? r)
    {
        if (r != null && !string.IsNullOrEmpty(r.RemoteAddress)) System.Windows.Clipboard.SetText(r.RemoteAddress);
    }
}

public sealed partial class ApplicationRow : ObservableObject
{
    public long Id { get; }
    public string Name { get; }
    public string Path { get; }
    public DateTime FirstSeen { get; }
    public DateTime LastSeen { get; }
    [ObservableProperty] private string _publisher = "—";
    [ObservableProperty] private string _signatureText = "";
    [ObservableProperty] private Level _signatureLevel;
    [ObservableProperty] private int _connections;
    [ObservableProperty] private string _currentRule = "—";
    [ObservableProperty] private Level _ruleLevel = Level.Neutral;
    public System.Windows.Media.ImageSource? Icon => IconCache.Get(Path);
    public string FirstSeenText => FirstSeen.ToString("g");
    public string LastSeenText => LastSeen.ToString("g");

    public ApplicationRow(ApplicationRecord r) { Id = r.Id; Name = r.Name; Path = r.Path; FirstSeen = r.FirstSeen; LastSeen = r.LastSeen; }
}

public sealed partial class ApplicationsViewModel : PageViewModel
{
    readonly ISecurityStore _store;
    readonly INetworkMonitor _network;
    readonly ISignatureService _signatures;
    readonly IFirewallRuleService _rules;
    readonly ProgramActions _actions;
    readonly INavigator _nav;
    readonly IDialogService _dialogs;
    readonly ISettingsStore _settings;
    readonly RuleWizardLauncher _wizard;

    public override string Title => "Applications";
    public override string Subtitle => "Programmes ayant utilisé le réseau depuis l'installation de SecureWall.";

    public ObservableCollection<ApplicationRow> Items { get; } = new();
    public ICollectionView View { get; }
    [ObservableProperty] private string _search = "";
    [ObservableProperty] private ApplicationRow? _selected;
    [ObservableProperty] private string _countText = "";

    public ApplicationsViewModel(ISecurityStore store, INetworkMonitor network, ISignatureService signatures, IFirewallRuleService rules,
        ProgramActions actions, INavigator nav, IDialogService dialogs, ISettingsStore settings, RuleWizardLauncher wizard)
    {
        _store = store; _network = network; _signatures = signatures; _rules = rules; _actions = actions; _nav = nav; _dialogs = dialogs; _settings = settings; _wizard = wizard;
        View = CollectionViewSource.GetDefaultView(Items);
        View.Filter = o => o is ApplicationRow r && (string.IsNullOrWhiteSpace(Search)
            || r.Name.Contains(Search, StringComparison.OrdinalIgnoreCase) || r.Path.Contains(Search, StringComparison.OrdinalIgnoreCase)
            || r.Publisher.Contains(Search, StringComparison.OrdinalIgnoreCase));
    }

    partial void OnSearchChanged(string value) => View.Refresh();

    public override async Task OnNavigatedToAsync()
    {
        await GuardAsync(RefreshAsync, "Chargement des applications");
        StartTimer(TimeSpan.FromSeconds(8), RefreshAsync);
    }

    async Task RefreshAsync()
    {
        var apps = await Task.Run(_store.GetApplications, PageToken);
        var conns = await _network.GetConnectionsAsync(PageToken);
        var rules = await _rules.GetRulesAsync(PageToken);
        var byPath = rules.Where(r => !string.IsNullOrEmpty(r.Program)).ToLookup(r => r.Program, StringComparer.OrdinalIgnoreCase);
        var counts = conns.Where(c => c.IsEstablished).GroupBy(c => c.ProcessPath, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

        Reconciler.Sync(Items, apps, a => a.Id, r => r.Id, a => new ApplicationRow(a), (row, a) =>
        {
            var sig = _signatures.GetOrQueue(a.Path);
            row.Publisher = string.IsNullOrEmpty(sig.Publisher) ? (string.IsNullOrEmpty(a.Publisher) ? "—" : a.Publisher) : sig.Publisher;
            row.SignatureText = sig.Status == SignatureStatus.Pending && Enum.TryParse<SignatureStatus>(a.SignatureStatus, out var st) ? new SignatureInfo { Status = st }.Text : sig.Text;
            row.SignatureLevel = sig.Level;
            row.Connections = counts.TryGetValue(a.Path, out var n) ? n : 0;
            var mine = byPath[a.Path].ToList();
            var block = mine.FirstOrDefault(r => r.Enabled && r.Action == FirewallAction.Block);
            var allow = mine.FirstOrDefault(r => r.Enabled && r.Action == FirewallAction.Allow);
            (row.CurrentRule, row.RuleLevel) = block != null ? ($"Bloquer — {block.Name}", Level.Bad) : allow != null ? ($"Autoriser — {allow.Name}", Level.Good) : ("Aucune règle spécifique", Level.Neutral);
        });
        CountText = $"{Items.Count:N0} application(s)";
        View.Refresh();
    }

    async Task CreateSimpleRuleAsync(ApplicationRow row, FirewallAction action)
    {
        if (action == FirewallAction.Block && CriticalProcessPolicy.IsCriticalWindowsComponent(row.Path))
        {
            _dialogs.Info("Composant Windows", "Ce programme fait partie de Windows. SecureWall ne le bloque pas automatiquement : cela pourrait empêcher le système de fonctionner. Utilisez l'assistant de règle si vous êtes certain de vouloir le faire.");
            return;
        }
        if (_settings.Current.ConfirmRuleChanges &&
            !_dialogs.Confirm(action == FirewallAction.Allow ? "Autoriser ce programme" : "Bloquer ce programme",
                $"Créer une règle de pare-feu « {(action == FirewallAction.Allow ? "Autoriser" : "Bloquer")} » en sortie pour :\n{row.Path}\n\nUne sauvegarde du pare-feu est effectuée avant la modification.", "Créer la règle", warning: action == FirewallAction.Block)) return;

        var spec = new FirewallRuleSpec
        {
            Name = $"SecureWall - {(action == FirewallAction.Allow ? "Autoriser" : "Bloquer")} {row.Name}",
            Description = "Créée depuis la page Applications de SecureWall.",
            Program = row.Path, Direction = FirewallDirection.Outbound, Action = action, Protocol = FirewallProtocol.Any, Profiles = FirewallProfiles.All,
        };
        await GuardAsync(async () =>
        {
            var r = await _rules.CreateRuleAsync(spec);
            if (r.Success) Success($"Règle créée pour {row.Name}."); else Fail(r.Message);
            await RefreshAsync();
        }, "Création de la règle");
    }

    [RelayCommand] Task Allow(ApplicationRow? r) => r == null ? Task.CompletedTask : CreateSimpleRuleAsync(r, FirewallAction.Allow);
    [RelayCommand] Task Block(ApplicationRow? r) => r == null ? Task.CompletedTask : CreateSimpleRuleAsync(r, FirewallAction.Block);
    [RelayCommand] void ShowConnections(ApplicationRow? r) { if (r != null) _nav.Navigate(AppPage.Connections, new ConnectionFilter(Application: r.Name)); }
    [RelayCommand] void Analyze(ApplicationRow? r) { if (r != null) _actions.Analyze(r.Path); }
    [RelayCommand] void OpenLocation(ApplicationRow? r) { if (r != null) _actions.OpenLocation(r.Path); }

    [RelayCommand]
    async Task CreateRuleAsync(ApplicationRow? r)
    {
        if (r == null) return;
        var spec = _wizard.Show(new FirewallRuleSpec { Program = r.Path, Name = $"SecureWall - {r.Name}" }, edit: false);
        if (spec == null) return;
        await GuardAsync(async () =>
        {
            var res = await _rules.CreateRuleAsync(spec);
            if (res.Success) Success("Règle créée."); else Fail(res.Message);
            await RefreshAsync();
        }, "Création de la règle");
    }
}

public sealed partial class StartupViewModel : PageViewModel
{
    readonly IStartupService _startup;
    readonly ProgramActions _actions;
    readonly IDialogService _dialogs;

    public override string Title => "Démarrage";
    public override string Subtitle => "Programmes lancés automatiquement avec Windows.";

    public ObservableCollection<StartupEntry> Items { get; } = new();
    [ObservableProperty] private StartupEntry? _selected;

    public StartupViewModel(IStartupService startup, ProgramActions actions, IDialogService dialogs)
    {
        _startup = startup; _actions = actions; _dialogs = dialogs;
    }

    public override async Task OnNavigatedToAsync()
    {
        await GuardAsync(LoadAsync, "Chargement du démarrage");
        StartTimer(TimeSpan.FromSeconds(3), async () =>
        {
            // Les signatures sont vérifiées en arrière-plan : on actualise l'affichage quand elles arrivent.
            if (Items.Any(i => i.Signature.Status == SignatureStatus.Pending)) await LoadAsync();
        });
    }

    async Task LoadAsync()
    {
        var list = await _startup.GetEntriesAsync(PageToken);
        var sel = Selected?.Key;
        Items.Clear();
        foreach (var e in list.OrderBy(e => e.Name)) Items.Add(e);
        Selected = Items.FirstOrDefault(i => i.Key == sel);
    }

    [RelayCommand] Task Analyze(StartupEntry? e) { if (e != null && !string.IsNullOrEmpty(e.Path)) _actions.Analyze(e.Path); return Task.CompletedTask; }
    [RelayCommand] void OpenLocation(StartupEntry? e) { if (e != null) _actions.OpenLocation(e.Path); }
    [RelayCommand] void Properties(StartupEntry? e) { if (e != null) _actions.Properties(e.Path); }

    [RelayCommand]
    async Task ToggleAsync(StartupEntry? e)
    {
        if (e == null) return;
        var enable = !e.Enabled;
        if (!_dialogs.Confirm(enable ? "Activer au démarrage" : "Désactiver au démarrage",
                enable ? $"« {e.Name} » sera de nouveau lancé automatiquement à l'ouverture de session de Windows."
                       : $"« {e.Name} » ne sera plus lancé automatiquement avec Windows. Le programme n'est pas supprimé : vous pourrez le réactiver ici ou dans le Gestionnaire des tâches.\n\n" +
                         "Cela peut empêcher certaines fonctions (synchronisation, mises à jour, pilotes d'accessoires) de fonctionner au démarrage.",
                enable ? "Activer" : "Désactiver")) return;
        await GuardAsync(async () =>
        {
            var r = await _startup.SetEnabledAsync(e, enable);
            if (r.Success) Success("Modification enregistrée."); else Fail(r.Message);
            await LoadAsync();
        }, "Modification du démarrage");
    }

    [RelayCommand] Task Refresh() => GuardAsync(LoadAsync, "Actualisation");
}
