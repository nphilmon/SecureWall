using System.Windows;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureWall.App.Services;
using SecureWall.Infrastructure.Configuration;
using SecureWall.Infrastructure.Notifications;
using SecureWall.Security.Devices;
using SecureWall.Security.Monitoring;

namespace SecureWall.App;

public partial class App : Application
{
    public new static App Current => (App)Application.Current;
    public IServiceProvider Services { get; private set; } = null!;

    Mutex? _mutex;
    EventWaitHandle? _activate;
    TrayController? _tray;
    bool _quitting;
    bool _headless;
    ILogger? _log;

    public bool IsQuitting => _quitting;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        try { await StartAsync(e); }
        catch (Exception ex)
        {
            try { _log?.LogCritical(ex, "Échec du démarrage"); } catch { }
            MessageBox.Show("SecureWall n'a pas pu démarrer :\n\n" + ex, "SecureWall Security", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    async Task StartAsync(StartupEventArgs e)
    {
        var args = e.Args;
        var scheduled = Array.IndexOf(args, "--scheduled-scan");
        _headless = scheduled >= 0;

        if (!_headless && !AcquireSingleInstance(args.Contains("--restart")))
        {
            try { EventWaitHandle.OpenExisting("SecureWall.Activate").Set(); } catch { /* première instance fermée entre-temps */ }
            Shutdown();
            return;
        }

        Services = CompositionRoot.Build();
        AppLog.Factory = Services.GetRequiredService<ILoggerFactory>();
        _log = AppLog.Logger;
        DispatcherUnhandledException += OnDispatcherException;
        TaskScheduler.UnobservedTaskException += (_, ev) => { _log?.LogError(ev.Exception, "Exception de tâche non observée"); ev.SetObserved(); };
        AppDomain.CurrentDomain.UnhandledException += (_, ev) => _log?.LogCritical(ev.ExceptionObject as Exception, "Exception non gérée");

#if DEBUG
        var themeArg = Array.IndexOf(args, "--theme");
        if (themeArg >= 0 && themeArg + 1 < args.Length && Enum.TryParse<ThemeMode>(args[themeArg + 1], true, out var forced))
            Services.GetRequiredService<ISettingsStore>().Current.Theme = forced;   // non enregistré : essais uniquement
#endif
        Services.GetRequiredService<ThemeService>().Apply();

        if (_headless)
        {
            await RunScheduledScanAsync(args, scheduled);
            Shutdown();
            return;
        }

        StartBackgroundServices();
        BuildTray();

        var mainVm = Services.GetRequiredService<MainViewModel>();
        var main = new Views.MainWindow { DataContext = mainVm };
#if DEBUG
        var sz = Array.IndexOf(args, "--size");
        if (sz >= 0 && sz + 1 < args.Length && args[sz + 1].Split('x') is { Length: 2 } wh && double.TryParse(wh[0], out var ww) && double.TryParse(wh[1], out var hh))
        { main.Width = ww; main.Height = hh; }
#endif
        if (args.Contains("--offscreen"))   // essais automatisés : fenêtre hors écran, sans prendre le focus
        {
            main.WindowStartupLocation = WindowStartupLocation.Manual;
            main.Left = -5000; main.Top = 0; main.ShowActivated = false;
        }
        mainVm.ShowInitialPage();
        var pageArg = Array.IndexOf(args, "--page");
        if (pageArg >= 0 && pageArg + 1 < args.Length && Enum.TryParse<AppPage>(args[pageArg + 1], true, out var startPage)) mainVm.Navigate(startPage);
        MainWindow = main;
        var settings = Services.GetRequiredService<ISettingsStore>();
        // Après une mise à jour, la page Nouveautés s'ouvre seule une fois (jamais au démarrage réduit dans la zone de notification).
        if (pageArg < 0 && !args.Contains("--minimized") && settings.Current.FirstRunCompleted &&
            SecureWall.Core.Models.ReleaseNotes.ShouldShow(settings.Current.LastSeenVersion, typeof(App).Assembly.GetName().Version?.ToString(3) ?? ""))
            mainVm.Navigate(AppPage.WhatsNew);
        if (!args.Contains("--minimized") || !settings.Current.FirstRunCompleted) main.Show();
        if (!settings.Current.FirstRunCompleted) ShowFirstRun();

        _ = Services.GetRequiredService<NewAppAlertCoordinator>().CleanupTemporaryAsync();
#if DEBUG
        var snap = Array.IndexOf(args, "--snapshot-all");
        if (snap >= 0 && snap + 1 < args.Length) _ = SnapshotAllAsync(main, mainVm, args[snap + 1]);
#endif
    }

#if DEBUG
    /// <summary>Outil de développement (build Debug uniquement) : enregistre une capture PNG de chaque page, hors écran.</summary>
    async Task SnapshotAllAsync(Window win, MainViewModel vm, string dir)
    {
        Directory.CreateDirectory(dir);
        await Task.Delay(4000);
        foreach (var page in Enum.GetValues<AppPage>())
        {
            vm.Navigate(page);
            await Task.Delay(6000);
            win.UpdateLayout();
            var w = (int)win.ActualWidth; var h = (int)win.ActualHeight;
            var rtb = new System.Windows.Media.Imaging.RenderTargetBitmap(w, h, 96, 96, System.Windows.Media.PixelFormats.Pbgra32);
            rtb.Render((System.Windows.Media.Visual)win.Content);
            var enc = new System.Windows.Media.Imaging.PngBitmapEncoder();
            enc.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(rtb));
            using var f = File.Create(Path.Combine(dir, page + ".png"));
            enc.Save(f);
        }
        await QuitAsync();
    }
#endif

    bool AcquireSingleInstance(bool waitForPrevious)
    {
        _mutex = new Mutex(true, @"Local\SecureWall.SingleInstance", out var created);
        if (!created && waitForPrevious)
        {
            try { created = _mutex.WaitOne(TimeSpan.FromSeconds(10)); } catch (AbandonedMutexException) { created = true; }
        }
        if (!created) return false;

        _activate = new EventWaitHandle(false, EventResetMode.AutoReset, "SecureWall.Activate");
        var t = new Thread(() =>
        {
            while (_activate.WaitOne())
            {
                if (_quitting) break;
                Dispatcher.InvokeAsync(ShowMainWindow);
            }
        }) { IsBackground = true, Name = "SecureWall.Activate" };
        t.Start();
        return true;
    }

    void StartBackgroundServices()
    {
        var sp = Services;
        sp.GetRequiredService<INetworkMonitor>().Start();
        sp.GetRequiredService<IUsbMonitor>().Start();
        sp.GetRequiredService<SecurityMonitor>().Start();
        sp.GetRequiredService<SecurityStateService>().Start();
        sp.GetRequiredService<UsbCoordinator>().Start();
        sp.GetRequiredService<NewAppAlertCoordinator>().Start();
    }

    void BuildTray()
    {
        var sp = Services;
        var nav = sp.GetRequiredService<INavigator>();
        _tray = new TrayController(sp.GetRequiredService<SecurityStateService>(), sp.GetRequiredService<EmergencyController>(),
            ShowMainWindow, (page, param) => nav.Navigate(page, param), () => _ = QuitAsync());
        var notif = (NotificationService)sp.GetRequiredService<INotificationService>();
        notif.Fallback = (title, msg, page) => Dispatcher.InvokeAsync(() => _tray.ShowBalloon(title, msg, () => nav.Navigate(page)));
        notif.OpenRequested += page => Dispatcher.InvokeAsync(() => nav.Navigate(page));
    }

    public void ShowMainWindow()
    {
        if (MainWindow == null) return;
        if (!MainWindow.IsVisible) MainWindow.Show();
        if (MainWindow.WindowState == WindowState.Minimized) MainWindow.WindowState = WindowState.Normal;
        MainWindow.Activate();
    }

    public void ShowFirstRun()
    {
        var vm = Services.GetRequiredService<FirstRunViewModel>();
        var w = new Views.FirstRunWindow { DataContext = vm, Owner = MainWindow is { IsVisible: true } ? MainWindow : null };
        vm.Finished += () => w.Close();
        w.ShowDialog();
        if (vm.RequestQuickScan) Services.GetRequiredService<INavigator>().Navigate(AppPage.Scans, "quick");
    }

    async Task RunScheduledScanAsync(string[] args, int idx)
    {
        try
        {
            var kindText = idx + 1 < args.Length ? args[idx + 1] : "Quick";
            var pathIdx = Array.IndexOf(args, "--path");
            var defender = Services.GetRequiredService<IDefenderService>();
            ScanResult r = kindText switch
            {
                "Full" => await defender.StartFullScanAsync(),
                "Custom" when pathIdx >= 0 && pathIdx + 1 < args.Length => await defender.StartCustomScanAsync(new[] { args[pathIdx + 1] }),
                _ => await defender.StartQuickScanAsync(),
            };
            _log?.LogInformation("Analyse planifiée {Kind} : {Status}, {Threats} menace(s)", kindText, r.Status, r.ThreatsFound);
            await Task.Delay(1500);   // laisse le temps d'afficher la notification
        }
        catch (Exception ex) { _log?.LogError(ex, "Analyse planifiée"); }
    }

    void OnDispatcherException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        _log?.LogError(e.Exception, "Exception de l'interface");
        e.Handled = true;
        MessageBox.Show("Une erreur inattendue est survenue. L'application continue de fonctionner.\n\n" + e.Exception.Message +
                        "\n\nLes détails sont enregistrés dans le journal (Paramètres → Confidentialité).", "SecureWall Security", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    public async Task QuitAsync()
    {
        if (_quitting) return;
        _quitting = true;
        try { await Services.GetRequiredService<NewAppAlertCoordinator>().CleanupTemporaryAsync(); } catch { /* ignoré */ }
        Services.GetRequiredService<INetworkMonitor>().Stop();
        Services.GetRequiredService<IUsbMonitor>().Stop();
        Services.GetRequiredService<SecurityMonitor>().Stop();
        Services.GetRequiredService<SecurityStateService>().Dispose();
        _tray?.Dispose();
        (Services.GetRequiredService<INotificationService>() as IDisposable)?.Dispose();
        _activate?.Set();
        try { _mutex?.ReleaseMutex(); } catch { /* ignoré */ }
        Shutdown();
    }
}

