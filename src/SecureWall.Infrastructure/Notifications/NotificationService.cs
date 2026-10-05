using CommunityToolkit.WinUI.Notifications;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using Windows.UI.Notifications;

namespace SecureWall.Infrastructure.Notifications;

/// <summary>
/// Notifications natives Windows (toasts). Chaque notification porte la page à ouvrir au clic.
/// Si les toasts sont indisponibles (session sans shell, stratégie de groupe…), repli sur une bulle de la zone de notification.
/// </summary>
public sealed class NotificationService : INotificationService, IDisposable
{
    readonly ISettingsStore _settings;
    readonly object _lock = new();
    readonly Dictionary<string, DateTime> _lastSent = new();

    public event Action<AppPage>? OpenRequested;
    /// <summary>Repli : (titre, message, page) → bulle de la zone de notification.</summary>
    public Action<string, string, AppPage>? Fallback { get; set; }

    public NotificationService(ISettingsStore settings)
    {
        _settings = settings;
        try
        {
            ToastNotificationManagerCompat.OnActivated += e =>
            {
                var args = ToastArguments.Parse(e.Argument);
                if (args.TryGetValue("page", out var p) && Enum.TryParse<AppPage>(p, out var page))
                    OpenRequested?.Invoke(page);
                else OpenRequested?.Invoke(AppPage.Dashboard);
            };
        }
        catch { /* toasts non disponibles : repli sur la zone de notification */ }
    }

    bool IsEnabled(NotificationKind kind)
    {
        var s = _settings.Current;
        if (!s.NotificationsEnabled) return false;
        return kind switch
        {
            NotificationKind.ThreatDetected or NotificationKind.ThreatRemoved or NotificationKind.Quarantined => s.NotifyThreats,
            NotificationKind.ScanCompleted => s.NotifyScans,
            NotificationKind.UsbConnected => s.NotifyUsb,
            NotificationKind.SignaturesOutdated => s.NotifySignatures,
            _ => s.NotifyFirewall,
        };
    }

    public void Notify(NotificationKind kind, string title, string message, AppPage page = AppPage.Dashboard)
    {
        if (!IsEnabled(kind)) return;

        // Anti-spam : même notification au plus une fois par 30 s.
        var key = kind + "|" + title + "|" + message;
        lock (_lock)
        {
            if (_lastSent.TryGetValue(key, out var t) && (DateTime.Now - t).TotalSeconds < 30) return;
            _lastSent[key] = DateTime.Now;
            if (_lastSent.Count > 200) foreach (var k in _lastSent.Where(kv => (DateTime.Now - kv.Value).TotalMinutes > 5).Select(kv => kv.Key).ToList()) _lastSent.Remove(k);
        }

        try
        {
            new ToastContentBuilder()
                .AddArgument("page", page.ToString())
                .AddText(title)
                .AddText(message)
                .Show();
        }
        catch
        {
            Fallback?.Invoke(title, message, page);
        }
    }

    public void Dispose()
    {
        try { ToastNotificationManagerCompat.History.Clear(); } catch { /* ignoré */ }
    }
}
