using System.ComponentModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureWall.App.Services;
using SecureWall.Core.Logic;
using SecureWall.Security.Monitoring;

namespace SecureWall.App.ViewModels;

/// <summary>Mode urgence : confirmation + exécution, partagés par l'en-tête, la page Pare-feu et la zone de notification.</summary>
public sealed class EmergencyController
{
    readonly EmergencyModeService _emergency;
    readonly IDialogService _dialogs;
    readonly SecurityStateService _state;

    /// <summary>Rétablissement automatique choisi (minutes, 0 = manuel). Partagé par l'en-tête, la page Pare-feu et la zone de notification.</summary>
    public int AutoRestoreMinutes { get; set; }

    public EmergencyController(EmergencyModeService emergency, IDialogService dialogs, SecurityStateService state)
    {
        _emergency = emergency; _dialogs = dialogs; _state = state;
    }

    public async Task CutoffAsync()
    {
        var minutes = AutoRestoreMinutes > 0 ? AutoRestoreMinutes : (int?)null;
        var duration = minutes is { } m
            ? $"Internet sera rétabli automatiquement dans {EmergencyText.Duration(TimeSpan.FromMinutes(m))} (vous pouvez aussi cliquer sur « Restaurer Internet » avant)."
            : "Internet restera coupé jusqu'à ce que vous cliquiez sur « Restaurer Internet ».";
        if (!_dialogs.Confirm("Couper les connexions Internet",
                "Cette action bloque tout le trafic entre cet ordinateur et Internet grâce au pare-feu Windows (votre réseau local reste accessible).\n\n" +
                "Navigateur, messagerie, mises à jour et protection cloud perdront l'accès à Internet. " + duration + "\n\n" +
                "L'état précédent du pare-feu est sauvegardé automatiquement.", "Couper Internet", warning: true)) return;
        var r = await _emergency.CutoffAsync(minutes);
        if (!r.Success) _dialogs.Error("Mode urgence", r.Message);
        await _state.RefreshAsync();
    }

    public async Task RestoreAsync()
    {
        var r = await _emergency.RestoreAsync();
        if (!r.Success) _dialogs.Error("Mode urgence", r.Message);
        await _state.RefreshAsync();
    }
}

public sealed partial class RuleWizardViewModel : ObservableObject
{
    public static readonly string[] StepTitles =
    {
        "Type de règle", "Application", "Protocole", "Ports", "Adresses IP", "Action", "Profil réseau", "Nom", "Confirmation",
    };

    readonly bool _edit;
    public string? OriginalName { get; }

    [ObservableProperty] private int _step;
    [ObservableProperty] private string _error = "";

    // 1. Type
    [ObservableProperty] private bool _typeProgram = true;
    [ObservableProperty] private bool _typePort;
    [ObservableProperty] private bool _typeCustom;
    [ObservableProperty] private bool _inbound;
    // 2. Application
    [ObservableProperty] private string _program = "";
    // 3. Protocole
    [ObservableProperty] private FirewallProtocol _protocol = FirewallProtocol.Any;
    // 4. Ports
    [ObservableProperty] private string _localPorts = "";
    [ObservableProperty] private string _remotePorts = "";
    // 5. IP
    [ObservableProperty] private string _localAddresses = "";
    [ObservableProperty] private string _remoteAddresses = "";
    // 6. Action
    [ObservableProperty] private bool _allow;
    [ObservableProperty] private bool _enabled = true;
    // 7. Profils
    [ObservableProperty] private bool _domain = true;
    [ObservableProperty] private bool _private = true;
    [ObservableProperty] private bool _public = true;
    // 8. Nom
    [ObservableProperty] private string _ruleName = "";
    [ObservableProperty] private string _description = "";

    public static FirewallProtocol[] Protocols { get; } = { FirewallProtocol.Any, FirewallProtocol.Tcp, FirewallProtocol.Udp, FirewallProtocol.Icmpv4, FirewallProtocol.Icmpv6 };
    public bool PortsAvailable => Protocol is FirewallProtocol.Tcp or FirewallProtocol.Udp;
    public int LastStep => StepTitles.Length - 1;
    public string StepTitle => StepTitles[Step];
    public string Progress => $"Étape {Step + 1} sur {StepTitles.Length}";
    public bool CanBack => Step > 0;
    public bool IsLast => Step == LastStep;
    public bool IsEdit => _edit;
    public FirewallRuleSpec? Result { get; private set; }

    public RuleWizardViewModel(FirewallRuleSpec? initial, bool edit)
    {
        _edit = edit;
        if (initial == null) return;
        OriginalName = edit ? initial.Name : null;
        Program = initial.Program; Protocol = initial.Protocol; LocalPorts = initial.LocalPorts; RemotePorts = initial.RemotePorts;
        LocalAddresses = initial.LocalAddresses; RemoteAddresses = initial.RemoteAddresses; Allow = initial.Action == FirewallAction.Allow;
        Inbound = initial.Direction == FirewallDirection.Inbound; Enabled = initial.Enabled;
        Domain = initial.Profiles.HasFlag(FirewallProfiles.Domain); Private = initial.Profiles.HasFlag(FirewallProfiles.Private); Public = initial.Profiles.HasFlag(FirewallProfiles.Public);
        RuleName = initial.Name; Description = initial.Description;
        TypeProgram = !string.IsNullOrEmpty(initial.Program); TypePort = string.IsNullOrEmpty(initial.Program) && initial.Protocol is FirewallProtocol.Tcp or FirewallProtocol.Udp;
        TypeCustom = !TypeProgram && !TypePort;
        if (!edit && string.IsNullOrEmpty(RuleName)) RuleName = "";
    }

    partial void OnStepChanged(int value)
    {
        foreach (var n in new[] { nameof(StepTitle), nameof(Progress), nameof(CanBack), nameof(IsLast) }) OnPropertyChanged(n);
        if (value == LastStep) OnPropertyChanged(nameof(Summary));
    }

    partial void OnProtocolChanged(FirewallProtocol value)
    {
        OnPropertyChanged(nameof(PortsAvailable));
        if (!PortsAvailable) { LocalPorts = ""; RemotePorts = ""; }
    }

    partial void OnTypePortChanged(bool value) { if (value && Protocol is not (FirewallProtocol.Tcp or FirewallProtocol.Udp)) Protocol = FirewallProtocol.Tcp; }

    public FirewallRuleSpec BuildSpec()
    {
        var profiles = (Domain ? FirewallProfiles.Domain : 0) | (Private ? FirewallProfiles.Private : 0) | (Public ? FirewallProfiles.Public : 0);
        return new FirewallRuleSpec
        {
            Name = RuleName.Trim(), Description = Description.Trim(), Enabled = Enabled,
            Direction = Inbound ? FirewallDirection.Inbound : FirewallDirection.Outbound,
            Action = Allow ? FirewallAction.Allow : FirewallAction.Block, Protocol = Protocol,
            Program = TypeProgram || TypeCustom ? Program.Trim() : Program.Trim(),
            LocalPorts = PortsAvailable ? LocalPorts.Trim() : "", RemotePorts = PortsAvailable ? RemotePorts.Trim() : "",
            LocalAddresses = LocalAddresses.Trim(), RemoteAddresses = RemoteAddresses.Trim(), Profiles = profiles,
        };
    }

    public string Summary
    {
        get
        {
            var s = BuildSpec();
            var prof = s.Profiles == FirewallProfiles.All ? "Tous" : s.Profiles.ToString();
            return $"Nom : {s.Name}\n" +
                   $"Action : {(s.Action == FirewallAction.Allow ? "Autoriser" : "Bloquer")} le trafic {(s.Direction == FirewallDirection.Inbound ? "entrant" : "sortant")}\n" +
                   $"Programme : {(string.IsNullOrEmpty(s.Program) ? "tous les programmes" : s.Program)}\n" +
                   $"Protocole : {s.Protocol}\n" +
                   $"Port local : {(string.IsNullOrEmpty(s.LocalPorts) ? "tous" : s.LocalPorts)}   Port distant : {(string.IsNullOrEmpty(s.RemotePorts) ? "tous" : s.RemotePorts)}\n" +
                   $"IP locale : {(string.IsNullOrEmpty(s.LocalAddresses) ? "toutes" : s.LocalAddresses)}   IP distante : {(string.IsNullOrEmpty(s.RemoteAddresses) ? "toutes" : s.RemoteAddresses)}\n" +
                   $"Profils : {prof}\nÉtat : {(s.Enabled ? "activée" : "désactivée")}";
        }
    }

    bool ValidateStep()
    {
        Error = "";
        var s = BuildSpec();
        string? e = Step switch
        {
            1 when !string.IsNullOrWhiteSpace(s.Program) && !RuleValidator.IsValidProgramPath(s.Program) => "Le chemin du programme est invalide (chemin absolu requis).",
            1 when (TypeProgram) && string.IsNullOrWhiteSpace(s.Program) => "Choisissez un programme, ou revenez à l'étape 1 pour un autre type de règle.",
            1 when !string.IsNullOrWhiteSpace(s.Program) && !File.Exists(s.Program) => "Ce programme est introuvable.",
            3 when TypePort && PortsAvailable && string.IsNullOrWhiteSpace(s.LocalPorts) && string.IsNullOrWhiteSpace(s.RemotePorts) => "Indiquez au moins un port pour une règle de type « Port ».",
            3 when !RuleValidator.IsValidPortList(s.LocalPorts) => "Port local invalide (exemples : 80, 443, 8000-8100).",
            3 when !RuleValidator.IsValidPortList(s.RemotePorts) => "Port distant invalide (exemples : 80, 443, 8000-8100).",
            4 when !RuleValidator.IsValidAddressList(s.LocalAddresses) => "Adresse IP locale invalide.",
            4 when !RuleValidator.IsValidAddressList(s.RemoteAddresses) => "Adresse IP distante invalide (exemples : 192.168.1.10, 10.0.0.0/8, 1.2.3.4-1.2.3.9, Internet).",
            6 when s.Profiles == FirewallProfiles.None => "Sélectionnez au moins un profil réseau.",
            7 when !RuleValidator.IsSafeName(s.Name) => "Saisissez un nom (200 caractères maximum, sans le caractère « | »).",
            _ => null,
        };
        if (e != null) { Error = e; return false; }
        return true;
    }

    [RelayCommand]
    void Next()
    {
        if (!ValidateStep()) return;
        if (Step < LastStep) Step++;
    }

    [RelayCommand] void Back() { Error = ""; if (Step > 0) Step--; }

    /// <summary>Retourne true si la règle est valide et prête à être créée.</summary>
    public bool TryFinish()
    {
        var spec = BuildSpec();
        var errors = RuleValidator.Validate(spec);
        if (errors.Count > 0) { Error = string.Join("\n", errors); return false; }
        Result = spec;
        return true;
    }
}

public sealed class RuleWizardLauncher
{
    public FirewallRuleSpec? Show(FirewallRuleSpec? initial, bool edit)
    {
        var vm = new RuleWizardViewModel(initial, edit);
        var w = new Views.RuleWizardWindow { DataContext = vm, Owner = System.Windows.Application.Current.MainWindow is { IsVisible: true } m ? m : null };
        return w.ShowDialog() == true ? vm.Result : null;
    }
}

public sealed partial class RulesViewModel : PageViewModel
{
    readonly IFirewallRuleService _rules;
    readonly IDialogService _dialogs;
    readonly RuleWizardLauncher _wizard;
    readonly ISettingsStore _settings;
    readonly ProgramActions _actions;
    readonly BaselineRulesService _baseline;

    public override string Title => "Règles";
    public override string Subtitle => "Règles de Windows Defender Firewall. Chaque modification crée d'abord une sauvegarde du pare-feu.";

    public ObservableCollection<FirewallRule> Items { get; } = new();
    public ICollectionView View { get; }

    [ObservableProperty] private string _search = "";
    [ObservableProperty] private string _direction = "all";
    [ObservableProperty] private string _actionFilter = "all";
    [ObservableProperty] private string _statusFilter = "all";
    [ObservableProperty] private bool _onlyMine;
    [ObservableProperty] private FirewallRule? _selected;
    [ObservableProperty] private string _countText = "";

    public RulesViewModel(IFirewallRuleService rules, IDialogService dialogs, RuleWizardLauncher wizard, ISettingsStore settings, ProgramActions actions, BaselineRulesService baseline)
    {
        _baseline = baseline; _rules = rules; _dialogs = dialogs; _wizard = wizard; _settings = settings; _actions = actions;
        View = CollectionViewSource.GetDefaultView(Items);
        View.Filter = o => o is FirewallRule r && Matches(r);
    }

    bool Matches(FirewallRule r)
    {
        if (OnlyMine && !r.CreatedBySecureWall) return false;
        if (Direction == "in" && r.Direction != FirewallDirection.Inbound) return false;
        if (Direction == "out" && r.Direction != FirewallDirection.Outbound) return false;
        if (ActionFilter == "allow" && r.Action != FirewallAction.Allow) return false;
        if (ActionFilter == "block" && r.Action != FirewallAction.Block) return false;
        if (StatusFilter == "on" && !r.Enabled) return false;
        if (StatusFilter == "off" && r.Enabled) return false;
        if (string.IsNullOrWhiteSpace(Search)) return true;
        return r.Name.Contains(Search, StringComparison.OrdinalIgnoreCase) || r.Program.Contains(Search, StringComparison.OrdinalIgnoreCase)
               || r.LocalPorts.Contains(Search, StringComparison.OrdinalIgnoreCase) || r.RemotePorts.Contains(Search, StringComparison.OrdinalIgnoreCase)
               || r.RemoteAddresses.Contains(Search, StringComparison.OrdinalIgnoreCase) || r.LocalAddresses.Contains(Search, StringComparison.OrdinalIgnoreCase);
    }

    partial void OnSearchChanged(string value) => Refilter();
    partial void OnDirectionChanged(string value) => Refilter();
    partial void OnActionFilterChanged(string value) => Refilter();
    partial void OnStatusFilterChanged(string value) => Refilter();
    partial void OnOnlyMineChanged(bool value) => Refilter();

    void Refilter()
    {
        View.Refresh();
        CountText = $"{View.Cast<object>().Count():N0} règle(s) affichée(s) sur {Items.Count:N0}";
    }

    public override Task OnNavigatedToAsync() => GuardAsync(LoadAsync, "Chargement des règles");

    async Task LoadAsync()
    {
        var name = Selected?.Name;
        var list = await _rules.GetRulesAsync(PageToken);
        Items.Clear();
        foreach (var r in list.OrderBy(r => r.Name, StringComparer.CurrentCultureIgnoreCase)) Items.Add(r);
        Selected = name == null ? null : Items.FirstOrDefault(r => r.Name == name);
        Refilter();
    }

    bool ConfirmForeign(FirewallRule r, string what)
    {
        if (!_settings.Current.ConfirmRuleChanges) return true;
        var warn = r.CreatedBySecureWall ? "" : "\n\nCette règle n'a pas été créée par SecureWall (Windows ou un programme installé). La modifier peut empêcher des applications ou des services de fonctionner.";
        return _dialogs.Confirm("Confirmer la modification", $"{what} : « {r.Name} »{warn}\n\nUne sauvegarde du pare-feu est créée avant la modification et peut être restaurée depuis la page Pare-feu.", "Confirmer", warning: !r.CreatedBySecureWall);
    }

    async Task Apply(Func<Task<OperationResult>> op, string context)
    {
        await GuardAsync(async () =>
        {
            var r = await op();
            if (r.Success) Success(string.IsNullOrEmpty(r.Message) ? "Modification effectuée." : r.Message); else Fail(r.Message);
            await LoadAsync();
        }, context);
    }

    [RelayCommand]
    async Task NewAsync()
    {
        var spec = _wizard.Show(null, edit: false);
        if (spec != null) await Apply(() => _rules.CreateRuleAsync(spec), "Création de la règle");
    }

    [RelayCommand]
    async Task OpenBaselineAsync()
    {
        var vm = new BaselineViewModel(_baseline, _rules, _dialogs, _settings);
        vm.Applied += () => _ = LoadAsync();
        await vm.LoadAsync();
        new Views.BaselineWindow { DataContext = vm, Owner = System.Windows.Application.Current.MainWindow is { IsVisible: true } m ? m : null }.ShowDialog();
        await GuardAsync(LoadAsync, "Actualisation");
    }

    [RelayCommand]
    async Task EditAsync(FirewallRule? r)
    {
        if (r == null) return;
        if (!ConfirmForeign(r, "Modifier la règle")) return;
        var spec = _wizard.Show(r.ToSpec(), edit: true);
        if (spec != null) await Apply(() => _rules.UpdateRuleAsync(r.Name, spec), "Modification de la règle");
    }

    [RelayCommand] Task DuplicateAsync(FirewallRule? r) => r == null ? Task.CompletedTask : Apply(() => _rules.DuplicateRuleAsync(r), "Duplication de la règle");

    [RelayCommand]
    async Task AllowAsync(FirewallRule? r)
    {
        if (r == null || r.Action == FirewallAction.Allow) return;
        if (!ConfirmForeign(r, "Passer la règle en « Autoriser »")) return;
        var spec = r.ToSpec(); spec.Action = FirewallAction.Allow;
        await Apply(() => _rules.UpdateRuleAsync(r.Name, spec), "Modification de la règle");
    }

    [RelayCommand]
    async Task BlockAsync(FirewallRule? r)
    {
        if (r == null || r.Action == FirewallAction.Block) return;
        if (!ConfirmForeign(r, "Passer la règle en « Bloquer »")) return;
        var spec = r.ToSpec(); spec.Action = FirewallAction.Block;
        await Apply(() => _rules.UpdateRuleAsync(r.Name, spec), "Modification de la règle");
    }

    [RelayCommand]
    async Task ToggleEnabledAsync(FirewallRule? r)
    {
        if (r == null) return;
        if (!ConfirmForeign(r, r.Enabled ? "Désactiver la règle" : "Activer la règle")) return;
        await Apply(() => _rules.SetRuleEnabledAsync(r.Name, !r.Enabled), "Modification de la règle");
    }

    [RelayCommand]
    async Task DeleteAsync(FirewallRule? r)
    {
        if (r == null) return;
        if (!_dialogs.Confirm("Supprimer la règle", $"Supprimer définitivement la règle « {r.Name} » ?" +
                (r.CreatedBySecureWall ? "" : "\n\nCette règle n'a pas été créée par SecureWall : sa suppression peut bloquer des applications ou des services.") +
                "\n\nUne sauvegarde du pare-feu est créée avant la suppression.", "Supprimer", warning: true)) return;
        await Apply(() => _rules.DeleteRuleAsync(r.Name), "Suppression de la règle");
    }

    [RelayCommand] void OpenProgram(FirewallRule? r) { if (r != null && !string.IsNullOrEmpty(r.Program)) _actions.OpenLocation(r.Program); }

    [RelayCommand]
    async Task ExportAsync()
    {
        var path = _dialogs.SaveFile("regles-securewall.json", "Règles SecureWall (*.json)|*.json");
        if (path == null) return;
        var onlyMine = _dialogs.Confirm("Exporter les règles", "Exporter uniquement les règles créées par SecureWall ?\n\nOK = règles SecureWall seulement\nAnnuler = toutes les règles du pare-feu", "Règles SecureWall");
        await GuardAsync(async () =>
        {
            await File.WriteAllTextAsync(path, await _rules.ExportRulesJsonAsync(onlyMine));
            Success("Règles exportées.");
        }, "Export des règles");
    }

    [RelayCommand]
    async Task ImportAsync()
    {
        var path = _dialogs.PickFile("Règles SecureWall (*.json)|*.json", "Importer des règles");
        if (path == null) return;
        if (!_dialogs.Confirm("Importer des règles", "Les règles du fichier seront validées puis créées dans le pare-feu Windows (les noms déjà existants sont ignorés). Une sauvegarde est créée avant chaque ajout.", "Importer")) return;
        await Apply(async () => await _rules.ImportRulesJsonAsync(await File.ReadAllTextAsync(path)), "Import des règles");
    }

    [RelayCommand] Task Refresh() => GuardAsync(LoadAsync, "Actualisation");
}

public sealed partial class FirewallViewModel : PageViewModel
{
    readonly IFirewallService _firewall;
    readonly INetworkProfileService _networks;
    readonly IPrivilegedClient _client;
    readonly IDialogService _dialogs;
    readonly EmergencyController _emergency;
    readonly SecurityStateService _state;
    readonly SecurityMonitor _monitor;
    readonly IAuditLog _audit;
    readonly ISettingsStore _settings;
    readonly INavigator _nav;

    public override string Title => "Pare-feu";
    public override string Subtitle => "Windows Defender Firewall — état réel des profils. Les modifications passent par le service privilégié.";

    public ObservableCollection<FirewallProfileInfo> Profiles { get; } = new();
    public ObservableCollection<NetworkProfileInfo> Networks { get; } = new();
    public ObservableCollection<string> Backups { get; } = new();

    [ObservableProperty] private SecuritySummary _summary = new();
    [ObservableProperty] private string? _selectedBackup;
    [ObservableProperty] private string _auditText = "";
    [ObservableProperty] private Level _auditLevel = Level.Neutral;

    public bool ServiceAvailable => Summary.ServiceAvailable;
    public bool EmergencyActive => Summary.EmergencyActive;
    public string EmergencyCountdown => Summary.EmergencyActive && Summary.EmergencyAutoRestoreAt is { } at
        ? "Internet sera rétabli automatiquement dans " + EmergencyText.Duration(at - DateTime.Now) + "."
        : Summary.EmergencyActive ? "Internet reste coupé jusqu'à ce que vous le rétablissiez." : "";
    public static string[] AutoRestoreLabels { get; } = EmergencyText.AutoRestoreOptions.Select(o => o.Label).ToArray();
    public int AutoRestoreIndex
    {
        get => Math.Max(0, Array.FindIndex(EmergencyText.AutoRestoreOptions, o => o.Minutes == _emergency.AutoRestoreMinutes));
        set { _emergency.AutoRestoreMinutes = EmergencyText.AutoRestoreOptions[Math.Clamp(value, 0, EmergencyText.AutoRestoreOptions.Length - 1)].Minutes; OnPropertyChanged(); }
    }
    public bool AlertNewApps
    {
        get => _settings.Current.AlertNewNetworkApps;
        set { _settings.Current.AlertNewNetworkApps = value; _settings.Save(); OnPropertyChanged(); }
    }
    public bool ConfirmRules
    {
        get => _settings.Current.ConfirmRuleChanges;
        set { _settings.Current.ConfirmRuleChanges = value; _settings.Save(); OnPropertyChanged(); }
    }

    public FirewallViewModel(IFirewallService firewall, INetworkProfileService networks, IPrivilegedClient client, IDialogService dialogs,
        EmergencyController emergency, SecurityStateService state, SecurityMonitor monitor, IAuditLog audit, ISettingsStore settings, INavigator nav)
    {
        _firewall = firewall; _networks = networks; _client = client; _dialogs = dialogs; _emergency = emergency; _state = state;
        _monitor = monitor; _audit = audit; _settings = settings; _nav = nav;
    }

    partial void OnSummaryChanged(SecuritySummary value) { OnPropertyChanged(nameof(ServiceAvailable)); OnPropertyChanged(nameof(EmergencyActive)); OnPropertyChanged(nameof(EmergencyCountdown)); }

    public override async Task OnNavigatedToAsync()
    {
        await GuardAsync(LoadAsync, "Chargement du pare-feu");
        StartTimer(TimeSpan.FromSeconds(10), LoadAsync);
    }

    async Task LoadAsync()
    {
        Summary = await _state.RefreshAsync(PageToken);
        var profiles = await _firewall.GetProfilesAsync(PageToken);
        Profiles.Clear(); foreach (var p in profiles) Profiles.Add(p);
        var nets = await _networks.GetNetworkProfilesAsync(PageToken);
        Networks.Clear(); foreach (var n in nets) Networks.Add(n);
        if (Summary.ServiceAvailable)
        {
            var b = await _firewall.ListBackupsAsync(PageToken);
            var sel = SelectedBackup;
            Backups.Clear(); foreach (var x in b) Backups.Add(x);
            SelectedBackup = Backups.Contains(sel ?? "") ? sel : Backups.FirstOrDefault();
        }
        (AuditText, AuditLevel) = !Summary.ServiceAvailable ? ("Service privilégié indisponible : les connexions bloquées ne peuvent pas être lues.", Level.Neutral)
            : !_monitor.BlockedConnectionsReadable ? ("Le journal de sécurité Windows n'a pas encore été lu.", Level.Neutral)
            : _monitor.BlockedConnectionsAuditing ? ("L'audit des connexions bloquées est actif : elles sont comptées dans les statistiques.", Level.Good)
            : ("L'audit des connexions bloquées est désactivé dans Windows : aucune connexion bloquée ne peut être comptée.", Level.Info);
    }

    [RelayCommand]
    async Task ToggleProfileAsync(FirewallProfileInfo? p)
    {
        if (p == null) return;
        var enable = !p.Enabled;
        if (!enable && !_dialogs.Confirm("Désactiver le pare-feu",
                $"Vous allez désactiver le pare-feu Windows pour le profil « {p.Name} »{(p.IsCurrent ? " (actuellement actif)" : "")}.\n\n" +
                "Sans pare-feu, votre PC est plus exposé aux attaques réseau. N'effectuez cette opération que temporairement et si vous savez pourquoi.", "Désactiver le pare-feu", warning: true)) return;
        if (enable && !_dialogs.Confirm("Activer le pare-feu", $"Activer le pare-feu Windows pour le profil « {p.Name} » ?", "Activer")) return;
        await GuardAsync(async () =>
        {
            var r = await _firewall.SetProfileEnabledAsync(p.Profile, enable);
            if (r.Success) Success($"Profil « {p.Name} » {(enable ? "activé" : "désactivé")}."); else Fail(r.Message);
            await LoadAsync();
        }, "Modification du pare-feu");
    }

    [RelayCommand]
    async Task BackupAsync()
    {
        await GuardAsync(async () =>
        {
            var r = await _firewall.CreateBackupAsync();
            if (r.Success) Success("Sauvegarde du pare-feu créée : " + r.Message); else Fail(r.Message);
            await LoadAsync();
        }, "Sauvegarde du pare-feu");
    }

    [RelayCommand]
    async Task RestoreBackupAsync()
    {
        if (SelectedBackup == null) return;
        if (!_dialogs.Confirm("Restaurer le pare-feu",
                $"Remplacer TOUTES les règles et paramètres actuels du pare-feu par la sauvegarde « {SelectedBackup} » ?\n\nL'état actuel est sauvegardé juste avant, vous pourrez donc revenir en arrière.", "Restaurer", warning: true)) return;
        var name = SelectedBackup;
        await GuardAsync(async () =>
        {
            var r = await _firewall.RestoreBackupAsync(name);
            if (r.Success) Success(r.Message); else Fail(r.Message);
            await LoadAsync();
        }, "Restauration du pare-feu");
    }

    [RelayCommand]
    async Task EnableAuditAsync()
    {
        if (!_dialogs.Confirm("Activer l'audit des connexions bloquées",
                "Cette action modifie la stratégie d'audit de Windows : les connexions refusées par le pare-feu seront inscrites dans le journal Sécurité (événements 5152/5157). " +
                "SecureWall les lit pour les compter.\n\nCe journal peut grossir sur un PC très sollicité. Vous pouvez désactiver l'audit à tout moment.", "Activer l'audit")) return;
        await GuardAsync(async () =>
        {
            var r = await _client.SendAsync(PrivilegedOperation.FirewallSetBlockAuditing, new() { ["enabled"] = "1" });
            _audit.Write("Audit des connexions bloquées", r.Success ? "Activé" : "Échec : " + r.Message);
            if (r.Success) Success(r.Message); else Fail(r.Message);
            await LoadAsync();
        }, "Activation de l'audit");
    }

    [RelayCommand]
    async Task DisableAuditAsync()
    {
        await GuardAsync(async () =>
        {
            var r = await _client.SendAsync(PrivilegedOperation.FirewallSetBlockAuditing, new() { ["enabled"] = "0" });
            _audit.Write("Audit des connexions bloquées", r.Success ? "Désactivé" : "Échec : " + r.Message);
            if (r.Success) Success(r.Message); else Fail(r.Message);
            await LoadAsync();
        }, "Désactivation de l'audit");
    }

    [RelayCommand] async Task CutoffAsync() { await _emergency.CutoffAsync(); await LoadAsync(); }
    [RelayCommand] async Task RestoreInternetAsync() { await _emergency.RestoreAsync(); await LoadAsync(); }
    [RelayCommand] void GoToRules() => _nav.Navigate(AppPage.Rules);
    [RelayCommand] Task Refresh() => GuardAsync(LoadAsync, "Actualisation");
    [RelayCommand] void OpenWindowsFirewall() => System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("wf.msc") { UseShellExecute = true });
}
