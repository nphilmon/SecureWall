using CommunityToolkit.Mvvm.Input;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Models;

namespace SecureWall.App.ViewModels;

public sealed record WhatsNewFeature(ReleaseFeature Feature)
{
    public string Category => Feature.Category;
    public string Title => Feature.Title;
    public string Description => Feature.Description;
    public bool CanOpen => Feature.Page != null;
    public string OpenLabel => Feature.PageLabel ?? "Ouvrir";
    public Level Level => Feature.Category switch
    {
        ReleaseNotes.New => Level.Info, ReleaseNotes.Improved => Level.Good, ReleaseNotes.Fixed => Level.Warning, ReleaseNotes.Security => Level.Good, _ => Level.Neutral,
    };
}

public sealed record WhatsNewEntry(ReleaseEntry Entry, bool IsCurrent)
{
    public string Header => IsCurrent ? $"Version {Entry.Version} — installée" : $"Version {Entry.Version}";
    public string Date => Entry.Date;
    public string Title => Entry.Title;
    public IReadOnlyList<WhatsNewFeature> Features { get; } = Entry.Features.Select(f => new WhatsNewFeature(f)).ToList();
}

public sealed partial class WhatsNewViewModel : PageViewModel
{
    readonly INavigator _nav;
    readonly ISettingsStore _settings;

    public override string Title => "Nouveautés";
    public override string Subtitle => "Ce qui change dans SecureWall, version après version.";

    public string CurrentVersion { get; } = typeof(WhatsNewViewModel).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
    public IReadOnlyList<WhatsNewEntry> Entries { get; }

    public WhatsNewViewModel(INavigator nav, ISettingsStore settings)
    {
        _nav = nav; _settings = settings;
        Entries = ReleaseNotes.All.Select(e => new WhatsNewEntry(e, e.Version == CurrentVersion)).ToList();
    }

    public override Task OnNavigatedToAsync()
    {
        MarkSeen();
        return Task.CompletedTask;
    }

    /// <summary>Mémorise que les nouveautés de cette version ont été vues : la page ne s'ouvrira plus seule.</summary>
    public void MarkSeen()
    {
        if (_settings.Current.LastSeenVersion == CurrentVersion) return;
        _settings.Current.LastSeenVersion = CurrentVersion;
        _settings.Save();
    }

    [RelayCommand]
    void Open(WhatsNewFeature? f)
    {
        if (f?.Feature.Page is { } page) _nav.Navigate(page, f.Feature.PageParameter);
    }
}
