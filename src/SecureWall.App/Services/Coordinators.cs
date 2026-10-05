using System.Windows;
using SecureWall.Infrastructure.Notifications;
using SecureWall.Security.Devices;
using SecureWall.Security.Monitoring;

namespace SecureWall.App.Services;

/// <summary>Réagit à l'insertion d'un support USB : journal, notification, proposition d'analyse. Ne bloque jamais le périphérique.</summary>
public sealed class UsbCoordinator
{
    readonly IUsbMonitor _usb;
    readonly ISettingsStore _settings;
    readonly INotificationService _notify;
    readonly ISecurityStore _store;
    readonly IDefenderService _defender;
    readonly IDialogService _dialogs;

    public UsbCoordinator(IUsbMonitor usb, ISettingsStore settings, INotificationService notify, ISecurityStore store, IDefenderService defender, IDialogService dialogs)
    {
        _usb = usb; _settings = settings; _notify = notify; _store = store; _defender = defender; _dialogs = dialogs;
    }

    public void Start() => _usb.DeviceConnected += OnConnected;

    void OnConnected(UsbDevice d)
    {
        _store.AddEvent("USB", $"Périphérique détecté : {d.DisplayName} ({d.DriveLetter}) — {d.Type}, {d.SizeText}{(d.IsNew ? " — nouveau périphérique" : "")}");
        _notify.Notify(NotificationKind.UsbConnected, "Périphérique USB détecté", $"{d.DisplayName} ({d.DriveLetter}){(d.IsNew ? " — nouveau" : "")}", AppPage.Usb);
        var s = _settings.Current;
        if (!s.UsbPromptScan || (s.UsbOnlyNewDevices && !d.IsNew)) return;

        Application.Current.Dispatcher.InvokeAsync(async () =>
        {
            if (!_dialogs.Confirm("Analyser le périphérique USB ?",
                    $"« {d.DisplayName} » ({d.DriveLetter}) vient d'être connecté.\nSouhaitez-vous l'analyser avec Microsoft Defender ?\n\nAucun accès au périphérique n'est bloqué.", "Analyser")) return;
            var r = await _defender.StartCustomScanAsync(new[] { d.DriveLetter + "\\" });
            if (r.Completed) { _store.MarkDeviceScanned(d.Identifier); d.LastScan = DateTime.Now; }
        });
    }
}

public enum AppAlertChoice { AllowOnce, AlwaysAllow, BlockOnce, AlwaysBlock }

/// <summary>
/// Mode optionnel "Me prévenir lorsqu'une nouvelle application accède au réseau".
/// Limite assumée : la détection s'appuie sur les connexions observées (elle intervient après la première tentative de connexion,
/// SecureWall n'installe aucun pilote de filtrage). Les composants critiques de Windows ne sont jamais proposés au blocage.
/// </summary>
public sealed class NewAppAlertCoordinator
{
    const string TempPrefix = "SecureWall - Blocage temporaire";

    readonly INetworkMonitor _network;
    readonly ISettingsStore _settings;
    readonly INotificationService _notify;
    readonly IFirewallRuleService _rules;
    readonly ISecurityStore _store;
    readonly HashSet<string> _session = new(StringComparer.OrdinalIgnoreCase);
    readonly List<string> _tempRules = new();

    public NewAppAlertCoordinator(INetworkMonitor network, ISettingsStore settings, INotificationService notify, IFirewallRuleService rules, ISecurityStore store)
    {
        _network = network; _settings = settings; _notify = notify; _rules = rules; _store = store;
    }

    public void Start() => _network.NewApplicationDetected += OnNewApp;

    void OnNewApp(NetworkAppInfo app, NetConnection conn)
    {
        _store.AddEvent("Réseau", $"Nouvelle application réseau : {app.Name} → {conn.RemoteAddress}:{conn.RemotePort} ({conn.Protocol})");
        if (!_settings.Current.AlertNewNetworkApps) return;
        if (!_session.Add(app.Path)) return;
        _notify.Notify(NotificationKind.NewNetworkApp, "Nouvelle application réseau", $"{app.Name} se connecte à {conn.RemoteAddress}:{conn.RemotePort}", AppPage.Applications);

        Application.Current.Dispatcher.InvokeAsync(async () =>
        {
            var w = new Views.NewAppAlertWindow(app, conn) { Owner = Application.Current.MainWindow is { IsVisible: true } m ? m : null };
            w.ShowDialog();
            if (w.Choice is not { } choice) return;
            switch (choice)
            {
                case AppAlertChoice.AllowOnce: break;   // simplement ne plus redemander pendant la session
                case AppAlertChoice.AlwaysAllow: await CreateAsync(app, FirewallAction.Allow, temporary: false); break;
                case AppAlertChoice.AlwaysBlock: await CreateAsync(app, FirewallAction.Block, temporary: false); break;
                case AppAlertChoice.BlockOnce: await CreateAsync(app, FirewallAction.Block, temporary: true); break;
            }
        });
    }

    async Task CreateAsync(NetworkAppInfo app, FirewallAction action, bool temporary)
    {
        var name = temporary ? $"{TempPrefix} {app.Name}" : $"SecureWall - {(action == FirewallAction.Allow ? "Autoriser" : "Bloquer")} {app.Name}";
        var r = await _rules.CreateRuleAsync(new FirewallRuleSpec
        {
            Name = name, Program = app.Path, Direction = FirewallDirection.Outbound, Action = action, Protocol = FirewallProtocol.Any, Profiles = FirewallProfiles.All,
            Description = temporary ? "Blocage temporaire créé par SecureWall (supprimé à la fermeture de l'application)." : "Créée depuis l'alerte « nouvelle application réseau ».",
        });
        if (r.Success && temporary) _tempRules.Add(name);
        if (!r.Success) MessageBox.Show(r.Message, "SecureWall", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    /// <summary>Supprime les blocages temporaires (« bloquer une fois ») créés pendant la session ou restés d'une session précédente.</summary>
    public async Task CleanupTemporaryAsync()
    {
        try
        {
            var all = await _rules.GetRulesAsync();
            foreach (var r in all.Where(r => r.Name.StartsWith(TempPrefix, StringComparison.Ordinal) && r.CreatedBySecureWall))
                await _rules.DeleteRuleAsync(r.Name);
            _tempRules.Clear();
        }
        catch { /* service indisponible : sera retenté au prochain démarrage */ }
    }
}

/// <summary>Icône de la zone de notification et son menu.</summary>
public sealed class TrayController : IDisposable
{
    readonly TrayIconHost _tray;
    readonly System.Windows.Forms.ToolStripMenuItem _status;
    readonly Func<AppPage, Task> _go;

    public TrayController(SecurityStateService state, EmergencyController emergency, Action open, Action<AppPage, object?> navigate, Action quit)
    {
        System.Drawing.Icon icon;
        try { icon = new System.Drawing.Icon(Application.GetResourceStream(new Uri("pack://application:,,,/Resources/securewall.ico")).Stream); }
        catch { icon = System.Drawing.SystemIcons.Shield; }

        _tray = new TrayIconHost(icon, "SecureWall Security");
        _go = p => { navigate(p, null); return Task.CompletedTask; };
        _tray.DoubleClicked += () => open();
        _tray.AddItem("Ouvrir SecureWall", open);
        _status = _tray.AddItem("Protection : vérification…", () => navigate(AppPage.SecurityCenter, null));
        _tray.AddSeparator();
        _tray.AddItem("Analyse rapide", () => navigate(AppPage.Scans, "quick"));
        _tray.AddItem("Pare-feu", () => navigate(AppPage.Firewall, null));
        _tray.AddSeparator();
        _tray.AddItem("Couper Internet", () => _ = Application.Current.Dispatcher.InvokeAsync(emergency.CutoffAsync));
        _tray.AddItem("Restaurer Internet", () => _ = Application.Current.Dispatcher.InvokeAsync(emergency.RestoreAsync));
        _tray.AddSeparator();
        _tray.AddItem("Paramètres", () => navigate(AppPage.Settings, null));
        _tray.AddItem("Quitter", quit);

        state.Changed += s => Application.Current.Dispatcher.InvokeAsync(() =>
        {
            var text = s.State == GlobalState.Protected ? "Protection : active" : $"Protection : {s.StateText.ToLowerInvariant()}";
            _status.Text = text;
            _tray.SetTooltip("SecureWall — " + s.StateText);
        });
    }

    public void ShowBalloon(string title, string message, Action? click = null) => _tray.ShowBalloon(title, message, click);
    public void Dispose() => _tray.Dispose();
}
