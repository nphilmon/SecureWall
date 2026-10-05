using System.Diagnostics;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureWall.App.Services;
using SecureWall.Infrastructure.Windows;
using SecureWall.Security.Monitoring;

namespace SecureWall.App.ViewModels;

/// <summary>Actions communes sur un programme / fichier (analyse Defender, emplacement, propriétés).</summary>
public sealed class ProgramActions
{
    readonly IDefenderService _defender;
    readonly IDialogService _dialogs;
    readonly IServiceProvider _sp;

    public ProgramActions(IDefenderService defender, IDialogService dialogs, IServiceProvider sp)
    {
        _defender = defender; _dialogs = dialogs; _sp = sp;
    }

    public void OpenLocation(string path)
    {
        if (string.IsNullOrEmpty(path) || !(File.Exists(path) || Directory.Exists(path))) { _dialogs.Info("Emplacement introuvable", "Le fichier n'existe plus à cet emplacement."); return; }
        ShellActions.ShowInExplorer(path);
    }

    public void Properties(string path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) { _dialogs.Info("Propriétés", "Fichier introuvable."); return; }
        ShellActions.ShowProperties(path);
    }

    public async Task ScanFileAsync(string path)
    {
        if (string.IsNullOrEmpty(path) || !(File.Exists(path) || Directory.Exists(path))) { _dialogs.Info("Analyse impossible", "Le fichier n'existe pas ou n'est pas accessible."); return; }
        var r = await _defender.StartCustomScanAsync(new[] { path });
        _dialogs.Info("Analyse Microsoft Defender", r.Status switch
        {
            "Terminée" when r.ThreatsFound == 0 => $"Aucune menace détectée par Microsoft Defender dans :\n{path}",
            "Terminée" => $"Microsoft Defender a détecté {r.ThreatsFound} menace(s) :\n" + string.Join("\n", r.Threats.Select(t => $"• {t.Name} — {t.Status}")),
            "Impossible" => "Analyse impossible : " + (r.Message ?? "Microsoft Defender n'est pas disponible."),
            _ => $"Analyse {r.Status.ToLowerInvariant()}. {r.Message}",
        });
    }

    public void Analyze(string path)
    {
        var vm = (ProgramAnalysisViewModel)_sp.GetService(typeof(ProgramAnalysisViewModel))!;
        var w = new Views.ProgramAnalysisWindow { DataContext = vm, Owner = System.Windows.Application.Current.MainWindow is { IsVisible: true } m ? m : null };
        w.Show();
        _ = vm.AnalyzeAsync(path);
    }
}

public sealed partial class ProgramAnalysisViewModel : ObservableObject
{
    readonly ISignatureService _signatures;
    readonly IDefenderService _defender;
    readonly INetworkMonitor _network;
    readonly IFirewallRuleService _rules;

    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _path = "";
    [ObservableProperty] private bool _isBusy = true;
    [ObservableProperty] private string _busyText = "Analyse en cours…";
    [ObservableProperty] private SignatureInfo _signature = SignatureInfo.Pending;
    [ObservableProperty] private string _defenderText = "En attente…";
    [ObservableProperty] private Level _defenderLevel = Level.Neutral;

    public ObservableCollection<ProgramReportItem> Detections { get; } = new();
    public ObservableCollection<ProgramReportItem> Informations { get; } = new();
    public ObservableCollection<NetConnection> Connections { get; } = new();
    public ObservableCollection<FirewallRule> Rules { get; } = new();

    public ProgramAnalysisViewModel(ISignatureService signatures, IDefenderService defender, INetworkMonitor network, IFirewallRuleService rules)
    {
        _signatures = signatures; _defender = defender; _network = network; _rules = rules;
    }

    public async Task AnalyzeAsync(string path)
    {
        Path = path;
        Name = System.IO.Path.GetFileName(path);
        try
        {
            if (!File.Exists(path))
            {
                DefenderText = "Analyse impossible : fichier introuvable";
                DefenderLevel = Level.Neutral;
                Informations.Add(new ProgramReportItem { Label = "Analyse impossible", Value = "Le fichier n'existe pas ou n'est pas accessible.", Level = Level.Neutral });
                return;
            }

            var sigTask = _signatures.VerifyAsync(path);
            var connTask = _network.GetConnectionsAsync();
            var rulesTask = _rules.GetRulesAsync();
            Signature = await sigTask;
            var conns = (await connTask).Where(c => string.Equals(c.ProcessPath, path, StringComparison.OrdinalIgnoreCase) && !c.IsListening).ToList();
            foreach (var c in conns) Connections.Add(c);
            foreach (var r in FirewallRuleService.RulesForProgram(await rulesTask, path)) Rules.Add(r);

            BusyText = "Analyse antivirus par Microsoft Defender…";
            var scan = await _defender.StartCustomScanAsync(new[] { path });
            var detected = scan.Threats.Count > 0;
            DefenderText = scan.Status switch
            {
                "Terminée" when detected => $"Menace détectée par Microsoft Defender : {scan.Threats[0].Name}",
                "Terminée" => "Aucune menace détectée par Microsoft Defender",
                _ => "Analyse impossible : " + (scan.Message ?? scan.Status),
            };
            DefenderLevel = scan.Status != "Terminée" ? Level.Neutral : detected ? Level.Bad : Level.Good;

            // Distinction explicite : détection réelle d'un moteur ≠ information inhabituelle.
            if (detected)
                foreach (var t in scan.Threats)
                    Detections.Add(new ProgramReportItem { Label = "Menace détectée par Microsoft Defender", Value = $"{t.Name} (gravité {t.Severity.ToLowerInvariant()}, {t.Status.ToLowerInvariant()})", Level = Level.Bad, IsDetection = true });
            else if (scan.Status == "Terminée")
                Detections.Add(new ProgramReportItem { Label = "Aucune menace détectée", Value = "Microsoft Defender n'a rien détecté dans ce fichier.", Level = Level.Good, IsDetection = true });
            else
                Detections.Add(new ProgramReportItem { Label = "Analyse impossible", Value = scan.Message ?? "Microsoft Defender n'a pas pu analyser ce fichier.", Level = Level.Neutral, IsDetection = true });

            switch (Signature.Status)
            {
                case SignatureStatus.Unsigned: Informations.Add(new() { Label = "Fichier non signé", Value = "Beaucoup de logiciels légitimes ne sont pas signés : ce n'est pas une preuve de malveillance.", Level = Level.Info }); break;
                case SignatureStatus.Invalid: Informations.Add(new() { Label = "Signature invalide", Value = Signature.Detail, Level = Level.Warning }); break;
                case SignatureStatus.Unknown: Informations.Add(new() { Label = "Signature inconnue", Value = "Le type de fichier ne permet pas de vérifier une signature.", Level = Level.Neutral }); break;
            }
            if (string.IsNullOrEmpty(Signature.Publisher) && Signature.Status != SignatureStatus.Pending)
                Informations.Add(new() { Label = "Éditeur inconnu", Value = "Aucun éditeur n'est associé à ce fichier.", Level = Level.Info });
            if (CriticalProcessPolicy.IsUnusualLocation(path))
                Informations.Add(new() { Label = "Chemin inhabituel", Value = "Le programme s'exécute depuis un dossier temporaire, de téléchargements ou la racine d'un disque.", Level = Level.Info });
            if (conns.Any(c => c.IsExternal && c.IsEstablished))
                Informations.Add(new() { Label = "Connexions externes actives", Value = $"{conns.Count(c => c.IsExternal && c.IsEstablished)} connexion(s) vers Internet en cours. Ce n'est pas anormal en soi.", Level = Level.Info });
            if (Informations.Count == 0)
                Informations.Add(new() { Label = "Aucune information inhabituelle", Value = "Aucun fait particulier à signaler.", Level = Level.Good });
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Analyse de programme");
            Informations.Add(new() { Label = "Analyse incomplète", Value = ex.Message, Level = Level.Neutral });
        }
        finally { IsBusy = false; }
    }
}

public sealed partial class ScheduleItemViewModel : ObservableObject
{
    public ScheduleConfig Config { get; }
    [ObservableProperty] private bool _enabled;
    [ObservableProperty] private ScheduleFrequency _frequency;
    [ObservableProperty] private DayOfWeek _dayOfWeek;
    [ObservableProperty] private int _dayOfMonth;
    [ObservableProperty] private string _time;
    [ObservableProperty] private ScanKind _kind;
    [ObservableProperty] private string _customPath;
    [ObservableProperty] private string _status = "";

    public string Label => Config.Label;
    public static ScheduleFrequency[] Frequencies { get; } = Enum.GetValues<ScheduleFrequency>();
    public static DayOfWeek[] Days { get; } = { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday, DayOfWeek.Saturday, DayOfWeek.Sunday };
    public static int[] MonthDays { get; } = Enumerable.Range(1, 28).ToArray();
    public static ScanKind[] Kinds { get; } = { ScanKind.Quick, ScanKind.Full, ScanKind.Custom };
    public bool ShowDayOfWeek => Frequency == ScheduleFrequency.Weekly;
    public bool ShowDayOfMonth => Frequency == ScheduleFrequency.Monthly;
    public bool ShowPath => Kind == ScanKind.Custom;

    public ScheduleItemViewModel(ScheduleConfig c)
    {
        Config = c; _enabled = c.Enabled; _frequency = c.Frequency; _dayOfWeek = c.DayOfWeek; _dayOfMonth = c.DayOfMonth;
        _time = c.Time; _kind = c.ScanKind; _customPath = c.CustomPath;
    }

    partial void OnFrequencyChanged(ScheduleFrequency value) { OnPropertyChanged(nameof(ShowDayOfWeek)); OnPropertyChanged(nameof(ShowDayOfMonth)); }
    partial void OnKindChanged(ScanKind value) => OnPropertyChanged(nameof(ShowPath));

    public void WriteBack()
    {
        Config.Enabled = Enabled; Config.Frequency = Frequency; Config.DayOfWeek = DayOfWeek; Config.DayOfMonth = DayOfMonth;
        Config.Time = Time; Config.ScanKind = Kind; Config.CustomPath = CustomPath;
    }
}

public sealed partial class ScanViewModel : PageViewModel, IParameterReceiver
{
    readonly IDefenderService _defender;
    readonly ISecurityStore _store;
    readonly IDialogService _dialogs;
    readonly ISettingsStore _settings;
    readonly ScheduledScanService _schedules;
    readonly SecurityStateService _state;
    CancellationTokenSource? _scanCts;

    public override string Title => "Analyses";
    public override string Subtitle => "Les analyses sont réalisées par Microsoft Defender. SecureWall les déclenche et en affiche le résultat.";

    [ObservableProperty] private bool _isScanning;
    [ObservableProperty] private double _progress;
    [ObservableProperty] private bool _isIndeterminate = true;
    [ObservableProperty] private string _stateText = "Aucune analyse en cours";
    [ObservableProperty] private string _currentItem = "—";
    [ObservableProperty] private string _elapsedText = "00:00:00";
    [ObservableProperty] private string _filesText = "—";
    [ObservableProperty] private string _threatsText = "—";
    [ObservableProperty] private string _startedText = "—";
    [ObservableProperty] private string _endedText = "—";
    [ObservableProperty] private string _resultText = "";
    [ObservableProperty] private Level _resultLevel = Level.Neutral;
    [ObservableProperty] private string? _selectedDrive;

    public ObservableCollection<DefenderThreat> LastThreats { get; } = new();
    public ObservableCollection<ScanRecord> RecentScans { get; } = new();
    public ObservableCollection<string> Drives { get; } = new();
    public ObservableCollection<ScheduleItemViewModel> Schedules { get; } = new();

    public ScanViewModel(IDefenderService defender, ISecurityStore store, IDialogService dialogs, ISettingsStore settings, ScheduledScanService schedules, SecurityStateService state)
    {
        _defender = defender; _store = store; _dialogs = dialogs; _settings = settings; _schedules = schedules; _state = state;
        foreach (var s in settings.Current.Schedules) Schedules.Add(new ScheduleItemViewModel(s));
    }

    public override async Task OnNavigatedToAsync()
    {
        Drives.Clear();
        foreach (var d in DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType is DriveType.Fixed or DriveType.Removable or DriveType.Network))
            Drives.Add(d.Name);
        SelectedDrive ??= Drives.FirstOrDefault();
        await LoadRecentAsync();
        foreach (var s in Schedules) s.Status = await _schedules.ExistsAsync(s.Config) ? "Tâche planifiée active" : (s.Enabled ? "Non appliquée" : "Désactivée");
    }

    async Task LoadRecentAsync()
    {
        var list = await Task.Run(() => _store.GetScans(15));
        RecentScans.Clear();
        foreach (var s in list) RecentScans.Add(s);
    }

    /// <summary>Point d'entrée externe (tableau de bord, barre d'état, ligne de commande).</summary>
    public Task RunExternalAsync(ScanKind kind, IReadOnlyList<string>? paths = null) => kind switch
    {
        ScanKind.Quick => RunAsync(ScanKind.Quick, null),
        ScanKind.Full => RunAsync(ScanKind.Full, null),
        _ => RunAsync(ScanKind.Custom, paths),
    };

    public void Receive(object parameter)
    {
        if (parameter is "quick") _ = RunAsync(ScanKind.Quick, null);
    }

    async Task RunAsync(ScanKind kind, IReadOnlyList<string>? paths)
    {
        if (IsScanning) { _dialogs.Info("Analyse en cours", "Une analyse est déjà en cours. Attendez sa fin ou annulez-la."); return; }
        IsScanning = true;
        ResultText = ""; LastThreats.Clear();
        StartedText = DateTime.Now.ToString("G"); EndedText = "—"; ThreatsText = "0"; FilesText = "—"; Progress = 0; IsIndeterminate = true;
        _scanCts = new CancellationTokenSource();
        var progress = new Progress<ScanProgress>(p =>
        {
            StateText = p.State; if (p.CurrentItem != null) CurrentItem = p.CurrentItem;
            ElapsedText = p.Elapsed.ToString(@"hh\:mm\:ss");
            FilesText = p.FilesTotal is { } t ? $"{t:N0} fichiers dans la cible (analyse gérée par Defender)" : "Nombre de fichiers non communiqué par Defender";
            IsIndeterminate = p.Percent is null; if (p.Percent is { } pc) Progress = pc;
        });
        try
        {
            var task = kind switch
            {
                ScanKind.Quick => _defender.StartQuickScanAsync(progress, _scanCts.Token),
                ScanKind.Full => _defender.StartFullScanAsync(progress, _scanCts.Token),
                _ => _defender.StartCustomScanAsync(paths ?? Array.Empty<string>(), progress, _scanCts.Token),
            };
            var r = await task;
            EndedText = r.End.ToString("G");
            ThreatsText = r.ThreatsFound.ToString();
            if (r.FilesScanned is { } f) FilesText = $"{f:N0} fichiers dans la cible";
            foreach (var t in r.Threats) LastThreats.Add(t);
            (ResultText, ResultLevel) = r.Status switch
            {
                "Terminée" when r.ThreatsFound == 0 => ($"Analyse terminée : aucune menace détectée par Microsoft Defender ({(r.End - r.Start):hh\\:mm\\:ss}).", Level.Good),
                "Terminée" => ($"Analyse terminée : Microsoft Defender a détecté {r.ThreatsFound} menace(s). Consultez la page Menaces.", Level.Bad),
                "Annulée" => ("Analyse annulée.", Level.Warning),
                "Impossible" => ("Analyse impossible : " + (r.Message ?? "Microsoft Defender n'est pas disponible."), Level.Neutral),
                _ => ("L'analyse a échoué : " + r.Message, Level.Bad),
            };
            StateText = r.Status;
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Analyse");
            ResultText = "L'analyse a échoué : " + ex.Message; ResultLevel = Level.Bad; StateText = "Échec";
        }
        finally
        {
            IsScanning = false; IsIndeterminate = false; Progress = 0;
            _scanCts?.Dispose(); _scanCts = null;
            await LoadRecentAsync();
            _ = _state.RefreshAsync();
        }
    }

    [RelayCommand] Task QuickAsync() => RunAsync(ScanKind.Quick, null);

    [RelayCommand]
    Task FullAsync()
    {
        if (!_dialogs.Confirm("Analyse complète", "Une analyse complète peut durer plusieurs heures et ralentir légèrement le PC. Elle sera exécutée par Microsoft Defender.", "Lancer l'analyse")) return Task.CompletedTask;
        return RunAsync(ScanKind.Full, null);
    }

    [RelayCommand]
    Task ScanFileAsync()
    {
        var files = _dialogs.PickFiles(title: "Choisir les fichiers à analyser");
        return files.Count == 0 ? Task.CompletedTask : RunAsync(ScanKind.Custom, files);
    }

    [RelayCommand]
    Task ScanFolderAsync()
    {
        var f = _dialogs.PickFolder("Choisir le dossier à analyser");
        return f == null ? Task.CompletedTask : RunAsync(ScanKind.Custom, new[] { f });
    }

    [RelayCommand]
    Task ScanDriveAsync() => SelectedDrive == null ? Task.CompletedTask : RunAsync(ScanKind.Custom, new[] { SelectedDrive });

    [RelayCommand] void Cancel() { _scanCts?.Cancel(); StateText = "Annulation…"; }

    [RelayCommand]
    void BrowseSchedulePath(ScheduleItemViewModel item)
    {
        var f = _dialogs.PickFolder("Dossier à analyser");
        if (f != null) item.CustomPath = f;
    }

    [RelayCommand]
    async Task ApplySchedulesAsync()
    {
        await GuardAsync(async () =>
        {
            var errors = new List<string>();
            foreach (var s in Schedules)
            {
                if (!TimeOnly.TryParseExact(s.Time, "HH:mm", out _)) { errors.Add($"{s.Label} : heure invalide (format HH:mm)."); continue; }
                s.WriteBack();
                var r = await _schedules.ApplyAsync(s.Config, Environment.ProcessPath!);
                s.Status = r.Success ? (s.Enabled ? "Tâche planifiée active" : "Désactivée") : "Erreur";
                if (!r.Success) errors.Add($"{s.Label} : {r.Message}");
            }
            _settings.Save();
            if (errors.Count == 0) Success("Analyses planifiées enregistrées dans le Planificateur de tâches Windows.");
            else Fail(string.Join("\n", errors));
        }, "Planification des analyses");
    }
}

public sealed partial class ThreatsViewModel : PageViewModel
{
    readonly IDefenderService _defender;
    readonly ProgramActions _actions;
    readonly QuarantineService _quarantine;
    readonly IDialogService _dialogs;
    readonly SecurityStateService _state;
    List<DefenderThreat> _all = new();

    public override string Title => "Menaces";
    public override string Subtitle => "Historique de protection tenu par Microsoft Defender.";

    public ObservableCollection<DefenderThreat> Items { get; } = new();
    [ObservableProperty] private string _filter = "all";
    [ObservableProperty] private string _search = "";
    [ObservableProperty] private DefenderThreat? _selected;
    [ObservableProperty] private int _activeCount;

    public ThreatsViewModel(IDefenderService defender, ProgramActions actions, QuarantineService quarantine, IDialogService dialogs, SecurityStateService state)
    {
        _defender = defender; _actions = actions; _quarantine = quarantine; _dialogs = dialogs; _state = state;
    }

    partial void OnFilterChanged(string value) => Apply();
    partial void OnSearchChanged(string value) => Apply();

    public override Task OnNavigatedToAsync() => GuardAsync(LoadAsync, "Chargement des menaces");

    async Task LoadAsync()
    {
        _all = (await _defender.GetProtectionHistoryAsync(PageToken)).ToList();
        ActiveCount = _all.Count(t => t.IsActive || t.StatusId == 1);
        Apply();
    }

    void Apply()
    {
        var q = _all.AsEnumerable();
        q = Filter switch
        {
            "active" => q.Where(t => t.IsActive || t.StatusId == 1),
            "removed" => q.Where(t => t.StatusId is 2 or 4),
            "blocked" => q.Where(t => t.StatusId == 6),
            "quarantine" => q.Where(t => t.StatusId == 3),
            "allowed" => q.Where(t => t.StatusId == 5),
            _ => q,
        };
        if (!string.IsNullOrWhiteSpace(Search))
            q = q.Where(t => $"{t.Name} {t.FilePath} {t.Process} {t.Category}".Contains(Search, StringComparison.OrdinalIgnoreCase));
        Items.Clear();
        foreach (var t in q.Take(2000)) Items.Add(t);
    }

    [RelayCommand] Task Refresh() => GuardAsync(LoadAsync, "Actualisation");
    [RelayCommand] void OpenLocation(DefenderThreat? t) { if (t != null) _actions.OpenLocation(t.FilePath); }
    [RelayCommand] Task ScanFile(DefenderThreat? t) => t == null ? Task.CompletedTask : _actions.ScanFileAsync(t.FilePath);

    [RelayCommand]
    async Task TreatActiveAsync()
    {
        if (!_dialogs.Confirm("Traiter les menaces actives", "Microsoft Defender va appliquer son action recommandée (suppression ou quarantaine) aux menaces actives. Continuer ?", "Traiter", warning: true)) return;
        var r = await _quarantine.RemoveActiveThreatsAsync();
        if (r.Success) Success(r.Message); else Fail(r.Message);
        await GuardAsync(LoadAsync, "Actualisation");
        _ = _state.RefreshAsync();
    }

    [RelayCommand] void OpenWindowsSecurity() => Process.Start(new ProcessStartInfo("windowsdefender://threat") { UseShellExecute = true });
}

public sealed partial class QuarantineViewModel : PageViewModel
{
    readonly QuarantineService _quarantine;
    readonly IDialogService _dialogs;
    readonly ProgramActions _actions;
    readonly SecurityStateService _state;

    public override string Title => "Quarantaine";
    public override string Subtitle => "Éléments isolés par Microsoft Defender. Ils ne peuvent plus s'exécuter.";

    public ObservableCollection<DefenderThreat> Items { get; } = new();
    [ObservableProperty] private DefenderThreat? _selected;

    public QuarantineViewModel(QuarantineService quarantine, IDialogService dialogs, ProgramActions actions, SecurityStateService state)
    {
        _quarantine = quarantine; _dialogs = dialogs; _actions = actions; _state = state;
    }

    public override Task OnNavigatedToAsync() => GuardAsync(LoadAsync, "Chargement de la quarantaine");

    async Task LoadAsync()
    {
        var list = await _quarantine.GetQuarantinedAsync(PageToken);
        Items.Clear();
        foreach (var t in list) Items.Add(t);
    }

    [RelayCommand]
    async Task RestoreAsync(DefenderThreat? t)
    {
        if (t == null) return;
        if (!_dialogs.Confirm("⚠ Restaurer un élément dangereux",
                $"« {t.Name} » a été identifié comme une menace (gravité {t.Severity.ToLowerInvariant()}) par Microsoft Defender.\n\n" +
                "La restauration remet le fichier à son emplacement d'origine ; il pourra alors s'exécuter et endommager vos données ou votre système.\n" +
                "Defender pourra le détecter de nouveau.\n\nN'effectuez cette opération que si vous êtes certain qu'il s'agit d'un faux positif.",
                "Restaurer malgré le risque", warning: true)) return;
        await GuardAsync(async () =>
        {
            var r = await _quarantine.RestoreAsync(t);
            if (r.Success) Success(r.Message); else Fail(r.Message);
            await LoadAsync();
            _ = _state.RefreshAsync();
        }, "Restauration");
    }

    [RelayCommand]
    void Delete(DefenderThreat? t)
    {
        _dialogs.Info("Suppression définitive",
            "Windows ne fournit pas d'interface programmable pour supprimer un élément déjà en quarantaine.\n\n" +
            "SecureWall va ouvrir l'historique de protection de Windows Security : sélectionnez l'élément puis « Actions » → « Supprimer ». " +
            "Microsoft Defender purge de toute façon automatiquement la quarantaine au bout de 90 jours.");
        QuarantineService.OpenWindowsSecurityHistory();
    }

    [RelayCommand]
    void Details(DefenderThreat? t)
    {
        if (t == null) return;
        _dialogs.Info("Détails de l'élément",
            $"Menace : {t.Name}\nCatégorie : {t.Category}\nGravité : {t.Severity}\n\nFichier : {t.FileName}\nChemin : {t.FilePath}\nProcessus : {(string.IsNullOrEmpty(t.Process) ? "—" : t.Process)}\n" +
            $"Utilisateur : {t.User}\n\nDétecté le : {t.DetectionDateText}\nAction : {t.Action}\nStatut : {t.Status}\nMoteur : {t.Engine}");
    }

    [RelayCommand] Task Refresh() => GuardAsync(LoadAsync, "Actualisation");
}
