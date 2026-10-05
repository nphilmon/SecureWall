using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Extensions.Logging;
using SecureWall.Core.Enums;

namespace SecureWall.App.ViewModels;

public interface INavigator
{
    void Navigate(AppPage page, object? parameter = null);
}

public interface IParameterReceiver
{
    void Receive(object parameter);
}

/// <summary>Journalisation centrale des exceptions de l'interface.</summary>
public static class AppLog
{
    public static ILoggerFactory? Factory { get; set; }
    public static ILogger Logger => Factory?.CreateLogger("SecureWall") ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
    public static void Error(Exception ex, string context) => Logger.LogError(ex, "{Context}", context);
}

public abstract partial class PageViewModel : ObservableObject
{
    DispatcherTimer? _timer;
    CancellationTokenSource? _cts;

    public abstract string Title { get; }
    public virtual string Subtitle => "";

    [ObservableProperty] private bool _isBusy;
    /// <summary>Message d'état / d'erreur affiché en haut de la page (compréhensible, sans détail technique brut).</summary>
    [ObservableProperty] private string _message = "";
    [ObservableProperty] private Level _messageLevel = Level.Info;

    /// <summary>Jeton annulé automatiquement lorsque l'utilisateur quitte la page.</summary>
    protected CancellationToken PageToken => (_cts ??= new CancellationTokenSource()).Token;

    public virtual Task OnNavigatedToAsync() => Task.CompletedTask;

    public virtual void OnNavigatedFrom()
    {
        _timer?.Stop();
        _timer = null;
        _cts?.Cancel();
        _cts = null;
    }

    protected void StartTimer(TimeSpan interval, Func<Task> tick)
    {
        _timer?.Stop();
        var running = false;
        _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = interval };
        _timer.Tick += async (_, _) =>
        {
            if (running) return;
            running = true;
            try { await tick(); }
            catch (OperationCanceledException) { }
            catch (Exception ex) { AppLog.Error(ex, Title + " (actualisation)"); }
            finally { running = false; }
        };
        _timer.Start();
    }

    protected void Info(string text) { Message = text; MessageLevel = Level.Info; }
    protected void Success(string text) { Message = text; MessageLevel = Level.Good; }
    protected void Warn(string text) { Message = text; MessageLevel = Level.Warning; }
    protected void Fail(string text) { Message = text; MessageLevel = Level.Bad; }

    /// <summary>Exécute une action en gérant occupation, annulation et erreurs de façon centralisée.</summary>
    protected async Task GuardAsync(Func<Task> action, string context)
    {
        try
        {
            IsBusy = true;
            await action();
        }
        catch (OperationCanceledException) { /* navigation ou annulation */ }
        catch (Exception ex)
        {
            AppLog.Error(ex, context);
            Fail($"{context} : une erreur est survenue ({ex.Message}). Les détails sont dans le journal de l'application.");
        }
        finally { IsBusy = false; }
    }

    protected static Task OnUi(Action a) => Application.Current.Dispatcher.InvokeAsync(a).Task;
}

/// <summary>Synchronise une collection observable avec une nouvelle liste sans la recréer (conserve sélection et défilement).</summary>
public static class Reconciler
{
    public static void Sync<TSrc, TRow, TKey>(ObservableCollection<TRow> target, IEnumerable<TSrc> source, Func<TSrc, TKey> srcKey,
        Func<TRow, TKey> rowKey, Func<TSrc, TRow> create, Action<TRow, TSrc> update) where TKey : notnull
    {
        var map = target.ToDictionary(rowKey);
        var seen = new HashSet<TKey>();
        var order = new List<TRow>();
        foreach (var s in source)
        {
            var k = srcKey(s);
            if (!seen.Add(k)) continue;
            if (map.TryGetValue(k, out var row)) { update(row, s); order.Add(row); }
            else { var n = create(s); order.Add(n); target.Add(n); }
        }
        for (var i = target.Count - 1; i >= 0; i--)
            if (!seen.Contains(rowKey(target[i]))) target.RemoveAt(i);
    }
}

public sealed record ConnectionFilter(int? Pid = null, string? Application = null);
