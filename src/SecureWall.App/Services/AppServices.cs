using System.Windows;
using Microsoft.Win32;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;

namespace SecureWall.App.Services;

public interface IDialogService
{
    bool Confirm(string title, string message, string confirmText = "Continuer", bool warning = false);
    void Info(string title, string message);
    void Error(string title, string message);
    string? PickFile(string filter = "Tous les fichiers|*.*", string? title = null);
    IReadOnlyList<string> PickFiles(string filter = "Tous les fichiers|*.*", string? title = null);
    string? PickFolder(string? title = null);
    string? SaveFile(string defaultName, string filter);
}

public sealed class DialogService : IDialogService
{
    static Window? Owner => Application.Current.MainWindow is { IsVisible: true } w ? w : null;

    public bool Confirm(string title, string message, string confirmText = "Continuer", bool warning = false)
    {
        var r = Owner != null
            ? MessageBox.Show(Owner, message, title, MessageBoxButton.OKCancel, warning ? MessageBoxImage.Warning : MessageBoxImage.Question, MessageBoxResult.Cancel)
            : MessageBox.Show(message, title, MessageBoxButton.OKCancel, warning ? MessageBoxImage.Warning : MessageBoxImage.Question, MessageBoxResult.Cancel);
        return r == MessageBoxResult.OK;
    }

    public void Info(string title, string message)
    {
        if (Owner != null) MessageBox.Show(Owner, message, title, MessageBoxButton.OK, MessageBoxImage.Information);
        else MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information);
    }

    public void Error(string title, string message)
    {
        if (Owner != null) MessageBox.Show(Owner, message, title, MessageBoxButton.OK, MessageBoxImage.Error);
        else MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Error);
    }

    public string? PickFile(string filter = "Tous les fichiers|*.*", string? title = null)
    {
        var d = new OpenFileDialog { Filter = filter, Title = title ?? "Choisir un fichier", CheckFileExists = true };
        return d.ShowDialog() == true ? d.FileName : null;
    }

    public IReadOnlyList<string> PickFiles(string filter = "Tous les fichiers|*.*", string? title = null)
    {
        var d = new OpenFileDialog { Filter = filter, Title = title ?? "Choisir des fichiers", CheckFileExists = true, Multiselect = true };
        return d.ShowDialog() == true ? d.FileNames : Array.Empty<string>();
    }

    public string? PickFolder(string? title = null)
    {
        var d = new OpenFolderDialog { Title = title ?? "Choisir un dossier" };
        return d.ShowDialog() == true ? d.FolderName : null;
    }

    public string? SaveFile(string defaultName, string filter)
    {
        var d = new SaveFileDialog { FileName = defaultName, Filter = filter };
        return d.ShowDialog() == true ? d.FileName : null;
    }
}

/// <summary>Applique le thème clair, sombre ou système en remplaçant le dictionnaire de ressources de thème.</summary>
public sealed class ThemeService
{
    readonly ISettingsStore _settings;

    public ThemeService(ISettingsStore settings)
    {
        _settings = settings;
        SystemEvents.UserPreferenceChanged += (_, e) =>
        {
            if (e.Category == UserPreferenceCategory.General && _settings.Current.Theme == ThemeMode.System)
                Application.Current.Dispatcher.BeginInvoke(Apply);
        };
    }

    public static bool SystemUsesDarkTheme()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return k?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch { return false; }
    }

    public void Apply()
    {
        var dark = _settings.Current.Theme switch { ThemeMode.Dark => true, ThemeMode.Light => false, _ => SystemUsesDarkTheme() };
        var uri = new Uri($"pack://application:,,,/SecureWall;component/Themes/{(dark ? "Dark" : "Light")}.xaml");
        var dicts = Application.Current.Resources.MergedDictionaries;
        var existing = dicts.FirstOrDefault(d => d.Source?.OriginalString.Contains("Themes/Light.xaml") == true || d.Source?.OriginalString.Contains("Themes/Dark.xaml") == true);
        var fresh = new ResourceDictionary { Source = uri };
        if (existing != null) dicts[dicts.IndexOf(existing)] = fresh; else dicts.Insert(0, fresh);
        ThemeChanged?.Invoke();
    }

    public event Action? ThemeChanged;
}
