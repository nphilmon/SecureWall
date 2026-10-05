using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureWall.App.Services;

namespace SecureWall.App.ViewModels;

public sealed partial class BaselineItemViewModel : ObservableObject
{
    public BaselineRuleItem Item { get; }
    [ObservableProperty] private bool _isSelected;
    public string Name => Item.Spec.Name.Replace("SecureWall Base - ", "");
    public string Description => Item.Spec.Description;
    public string Summary => Item.Summary;
    public string StatusText => Item.StatusText;
    public bool CanSelect => Item.Status == BaselineStatus.New;
    public Level StatusLevel => Item.Status == BaselineStatus.New ? Level.Info : Level.Good;

    public BaselineItemViewModel(BaselineRuleItem item) { Item = item; _isSelected = item.IsSelected; }
    partial void OnIsSelectedChanged(bool value) => Item.IsSelected = value;
}

public sealed partial class BaselineViewModel : ObservableObject
{
    readonly BaselineRulesService _service;
    readonly IFirewallRuleService _rules;
    readonly IDialogService _dialogs;
    readonly ISettingsStore _settings;
    BaselineRuleSet _set;

    public ObservableCollection<BaselineItemViewModel> Items { get; } = new();
    [ObservableProperty] private string _title = "";
    [ObservableProperty] private string _message = "";
    [ObservableProperty] private Level _messageLevel = Level.Info;
    [ObservableProperty] private bool _busy;
    [ObservableProperty] private string _updateUrl;
    public string SourceText => _set.Source;
    public string VersionText => $"Version {_set.Version} · publiée le {_set.Published} · signature vérifiée";
    public string AppliedText => _service.AppliedVersion is { } v ? $"Dernier jeu appliqué : v{v}" : "Aucun jeu appliqué pour l'instant";
    public event Action? Applied;

    public BaselineViewModel(BaselineRulesService service, IFirewallRuleService rules, IDialogService dialogs, ISettingsStore settings)
    {
        _service = service; _rules = rules; _dialogs = dialogs; _settings = settings;
        _updateUrl = settings.Current.BaselineUpdateUrl;
        _set = service.LoadCurrent();
        Title = _set.Name;
    }

    public async Task LoadAsync()
    {
        var existing = await _rules.GetRulesAsync();
        Items.Clear();
        foreach (var i in BaselineRulesService.Preview(_set, existing)) Items.Add(new BaselineItemViewModel(i));
        Title = _set.Name;
        OnPropertyChanged(nameof(SourceText)); OnPropertyChanged(nameof(VersionText)); OnPropertyChanged(nameof(AppliedText));
    }

    [RelayCommand]
    async Task CheckUpdateAsync()
    {
        if (string.IsNullOrWhiteSpace(UpdateUrl))
        {
            Message = "Indiquez l'adresse du jeu de règles signé (HTTPS, raw.githubusercontent.com) pour rechercher une mise à jour."; MessageLevel = Level.Warning; return;
        }
        Busy = true;
        try
        {
            _settings.Current.BaselineUpdateUrl = UpdateUrl.Trim();
            _settings.Save();
            var (set, msg) = await _service.CheckForUpdateAsync(UpdateUrl.Trim());
            Message = msg;
            MessageLevel = set != null ? Level.Good : msg.StartsWith("Vous disposez") ? Level.Info : Level.Bad;
            if (set != null) { _set = _service.LoadCurrent(); await LoadAsync(); }
        }
        catch (Exception ex) { AppLog.Error(ex, "Mise à jour des règles de base"); Message = ex.Message; MessageLevel = Level.Bad; }
        finally { Busy = false; }
    }

    [RelayCommand]
    async Task ApplyAsync()
    {
        var chosen = Items.Where(i => i.IsSelected && i.CanSelect).Select(i => i.Item).ToList();
        if (chosen.Count == 0) { Message = "Cochez au moins une règle à ajouter."; MessageLevel = Level.Warning; return; }
        if (!_dialogs.Confirm("Ajouter les règles de base",
                $"{chosen.Count} règle(s) de blocage seront créées dans le pare-feu Windows (groupe SecureWall). Une sauvegarde du pare-feu est effectuée avant chaque ajout et vous pourrez les supprimer à tout moment depuis la page Règles.\n\n" +
                "Elles bloquent des protocoles risques (Telnet, partages Windows et Bureau à distance exposés à Internet…) : si vous utilisez volontairement l'un d'eux, décochez-le.", "Ajouter les règles")) return;
        Busy = true;
        try
        {
            var r = await _service.ApplyAsync(_set, Items.Select(i => i.Item));
            Message = r.Message; MessageLevel = r.Success ? Level.Good : Level.Bad;
            await LoadAsync();
            if (r.Success) Applied?.Invoke();
        }
        finally { Busy = false; }
    }
}
