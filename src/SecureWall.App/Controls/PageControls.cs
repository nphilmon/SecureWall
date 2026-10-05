using System.Windows;
using System.Windows.Controls;
using SecureWall.Core.Enums;

namespace SecureWall.App.Controls;

/// <summary>En-tête de page : titre, sous-titre et zone d'actions (contenu). Le modèle visuel est défini dans Themes/Controls.xaml.</summary>
public sealed class PageHeader : ContentControl
{
    public static readonly DependencyProperty TitleProperty = DependencyProperty.Register(nameof(Title), typeof(string), typeof(PageHeader), new PropertyMetadata(""));
    public static readonly DependencyProperty SubtitleProperty = DependencyProperty.Register(nameof(Subtitle), typeof(string), typeof(PageHeader), new PropertyMetadata(""));

    static PageHeader() => DefaultStyleKeyProperty.OverrideMetadata(typeof(PageHeader), new FrameworkPropertyMetadata(typeof(PageHeader)));

    public string Title { get => (string)GetValue(TitleProperty); set => SetValue(TitleProperty, value); }
    public string Subtitle { get => (string)GetValue(SubtitleProperty); set => SetValue(SubtitleProperty, value); }
}

/// <summary>Bandeau d'information / de succès / d'erreur affiché en haut d'une page.</summary>
public sealed class MessageBar : Border
{
    public static readonly DependencyProperty TextProperty = DependencyProperty.Register(nameof(Text), typeof(string), typeof(MessageBar), new PropertyMetadata("", (d, _) => ((MessageBar)d).Update()));
    public static readonly DependencyProperty LevelProperty = DependencyProperty.Register(nameof(Level), typeof(Level), typeof(MessageBar), new PropertyMetadata(Level.Info, (d, _) => ((MessageBar)d).Update()));

    public string Text { get => (string)GetValue(TextProperty); set => SetValue(TextProperty, value); }
    public Level Level { get => (Level)GetValue(LevelProperty); set => SetValue(LevelProperty, value); }

    readonly TextBlock _text = new() { TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };

    public MessageBar()
    {
        CornerRadius = new CornerRadius(8);
        Padding = new Thickness(14, 10, 14, 10);
        Margin = new Thickness(0, 0, 0, 12);
        Child = _text;
        Update();
    }

    void Update()
    {
        var n = Level switch { Level.Good => "Good", Level.Warning => "Warn", Level.Bad => "Bad", Level.Info => "Info", _ => "Neutral" };
        SetResourceReference(BackgroundProperty, n + "SoftBrush");
        _text.SetResourceReference(TextBlock.ForegroundProperty, n + "Brush");
        _text.Text = Text;
        Visibility = string.IsNullOrWhiteSpace(Text) ? Visibility.Collapsed : Visibility.Visible;
        System.Windows.Automation.AutomationProperties.SetLiveSetting(this, System.Windows.Automation.AutomationLiveSetting.Polite);
    }
}
