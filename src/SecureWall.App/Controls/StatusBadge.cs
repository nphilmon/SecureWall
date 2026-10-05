using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using SecureWall.Core.Enums;

namespace SecureWall.App.Controls;

/// <summary>Badge d'état (pastille colorée). Les couleurs suivent le thème courant (références dynamiques).</summary>
public sealed class StatusBadge : Border
{
    readonly TextBlock _label = new() { FontSize = 12, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };

    public static readonly DependencyProperty TextProperty = DependencyProperty.Register(nameof(Text), typeof(string), typeof(StatusBadge),
        new PropertyMetadata("", (d, _) => ((StatusBadge)d).Update()));
    public static readonly DependencyProperty LevelProperty = DependencyProperty.Register(nameof(Level), typeof(Level), typeof(StatusBadge),
        new PropertyMetadata(Level.Neutral, (d, _) => ((StatusBadge)d).Update()));

    public string Text { get => (string)GetValue(TextProperty); set => SetValue(TextProperty, value); }
    public Level Level { get => (Level)GetValue(LevelProperty); set => SetValue(LevelProperty, value); }

    public StatusBadge()
    {
        CornerRadius = new CornerRadius(12);
        Padding = new Thickness(10, 3, 10, 3);
        HorizontalAlignment = HorizontalAlignment.Left;
        VerticalAlignment = VerticalAlignment.Center;
        Child = _label;
        Update();
    }

    void Update()
    {
        var n = Level switch { Level.Good => "Good", Level.Warning => "Warn", Level.Bad => "Bad", Level.Info => "Info", _ => "Neutral" };
        SetResourceReference(BackgroundProperty, n + "SoftBrush");
        _label.SetResourceReference(TextBlock.ForegroundProperty, n + "Brush");
        _label.Text = Text;
        AutomationProperties.SetName(this, Text);
    }
}
