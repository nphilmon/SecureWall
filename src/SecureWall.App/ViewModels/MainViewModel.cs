using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using SecureWall.App.Services;
using SecureWall.Core.Logic;
using SecureWall.Core.Models;
using SecureWall.Security.Monitoring;

namespace SecureWall.App.ViewModels;

public sealed record NavItem(AppPage Page, string Title, string Glyph)
{
    public override string ToString() => Title;
}

public sealed partial class MainViewModel : ObservableObject, INavigator
{
    readonly IServiceProvider _sp;
    readonly SecurityStateService _state;
    readonly EmergencyController _emergency;
    bool _navigating;

    public ObservableCollection<NavItem> Items { get; } = new()
    {
        new(AppPage.Dashboard, "Tableau de bord", ""),
        new(AppPage.Antivirus, "Antivirus", ""),
        new(AppPage.Scans, "Analyses", ""),
        new(AppPage.Threats, "Menaces", ""),
        new(AppPage.Quarantine, "Quarantaine", ""),
        new(AppPage.Processes, "Processus", ""),
        new(AppPage.Connections, "Connexions", ""),
        new(AppPage.Map, "Carte", ""),
        new(AppPage.Applications, "Applications", ""),
        new(AppPage.Firewall, "Pare-feu", ""),
        new(AppPage.Rules, "Règles", ""),
        new(AppPage.Dns, "DNS", ""),
        new(AppPage.Usb, "USB", ""),
        new(AppPage.Startup, "Démarrage", ""),
        new(AppPage.History, "Historique", ""),
        new(AppPage.Statistics, "Statistiques", ""),
        new(AppPage.SecurityCenter, "Centre de sécurité", ""),
        new(AppPage.WhatsNew, "Nouveautés", ""),
        new(AppPage.Settings, "Paramètres", ""),
    };

    [ObservableProperty] private NavItem? _selected;
    [ObservableProperty] private PageViewModel? _currentPage;
    [ObservableProperty] private SecuritySummary _summary = new();
    [ObservableProperty] private bool _serviceMissing;
    [ObservableProperty] private bool _emergencyActive;
    [ObservableProperty] private string _banner = "";
    [ObservableProperty] private bool _bannerDismissed;
    public bool ShowServiceBanner => ServiceMissing && !BannerDismissed;
    partial void OnServiceMissingChanged(bool value) => OnPropertyChanged(nameof(ShowServiceBanner));
    partial void OnBannerDismissedChanged(bool value) => OnPropertyChanged(nameof(ShowServiceBanner));
    [RelayCommand] void DismissBanner() => BannerDismissed = true;

    public string StateText => Summary.StateText;
    public string EmergencyBadge => EmergencyText.Badge(Summary.EmergencyActive, Summary.EmergencyAutoRestoreAt, DateTime.Now);

    public MainViewModel(IServiceProvider sp, SecurityStateService state, EmergencyController emergency)
    {
        _sp = sp; _state = state; _emergency = emergency;
        _state.Changed += s => Application.Current.Dispatcher.InvokeAsync(() => Apply(s));
        Apply(_state.Current);
        // Compte à rebours du rétablissement automatique : actualisation du libellé chaque 20 s.
        var countdown = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(20) };
        countdown.Tick += (_, _) => { if (Summary.EmergencyActive) OnPropertyChanged(nameof(EmergencyBadge)); };
        countdown.Start();
    }

    /// <summary>Affiche la première page. Appelé après la construction (la résolution des pages dépend de ce modèle).</summary>
    public void ShowInitialPage() => Selected = Items[0];

    void Apply(SecuritySummary s)
    {
        Summary = s;
        ServiceMissing = s.Updated != DateTime.MinValue && !s.ServiceAvailable;
        EmergencyActive = s.EmergencyActive;
        OnPropertyChanged(nameof(StateText));
        OnPropertyChanged(nameof(EmergencyBadge));
    }

    partial void OnSelectedChanged(NavItem? value)
    {
        if (value != null && !_navigating) _ = ShowAsync(value.Page, null);
    }

    public void Navigate(AppPage page, object? parameter = null)
    {
        Application.Current.Dispatcher.InvokeAsync(async () =>
        {
            _navigating = true;
            Selected = Items.First(i => i.Page == page);
            _navigating = false;
            await ShowAsync(page, parameter);
            if (Application.Current.MainWindow is { } w)
            {
                if (!w.IsVisible) w.Show();
                if (w.WindowState == WindowState.Minimized) w.WindowState = WindowState.Normal;
                w.Activate();
            }
        });
    }

    async Task ShowAsync(AppPage page, object? parameter)
    {
        CurrentPage?.OnNavigatedFrom();
        var vm = Resolve(page);
        CurrentPage = vm;
        if (parameter != null && vm is IParameterReceiver r) r.Receive(parameter);
        try { await vm.OnNavigatedToAsync(); }
        catch (Exception ex) { AppLog.Error(ex, "Chargement de la page " + page); }
    }

    PageViewModel Resolve(AppPage page) => page switch
    {
        AppPage.Dashboard => _sp.GetRequiredService<DashboardViewModel>(),
        AppPage.Antivirus => _sp.GetRequiredService<AntivirusDashboardViewModel>(),
        AppPage.Scans => _sp.GetRequiredService<ScanViewModel>(),
        AppPage.Threats => _sp.GetRequiredService<ThreatsViewModel>(),
        AppPage.Quarantine => _sp.GetRequiredService<QuarantineViewModel>(),
        AppPage.Processes => _sp.GetRequiredService<ProcessMonitorViewModel>(),
        AppPage.Connections => _sp.GetRequiredService<ConnectionsViewModel>(),
        AppPage.Applications => _sp.GetRequiredService<ApplicationsViewModel>(),
        AppPage.Firewall => _sp.GetRequiredService<FirewallViewModel>(),
        AppPage.Rules => _sp.GetRequiredService<RulesViewModel>(),
        AppPage.Dns => _sp.GetRequiredService<DnsViewModel>(),
        AppPage.Map => _sp.GetRequiredService<WorldMapViewModel>(),
        AppPage.WhatsNew => _sp.GetRequiredService<WhatsNewViewModel>(),
        AppPage.Usb => _sp.GetRequiredService<UsbViewModel>(),
        AppPage.Startup => _sp.GetRequiredService<StartupViewModel>(),
        AppPage.History => _sp.GetRequiredService<HistoryViewModel>(),
        AppPage.Statistics => _sp.GetRequiredService<StatisticsViewModel>(),
        AppPage.SecurityCenter => _sp.GetRequiredService<SecurityCenterViewModel>(),
        _ => _sp.GetRequiredService<SettingsViewModel>(),
    };

    [RelayCommand] public Task EmergencyCutoffAsync() => _emergency.CutoffAsync();
    [RelayCommand] public Task EmergencyRestoreAsync() => _emergency.RestoreAsync();

    [RelayCommand] void GoToSettings() => Navigate(AppPage.Settings);
}
