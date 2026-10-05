using System.Collections;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using SecureWall.Core.Enums;
using SecureWall.Core.Models;

namespace SecureWall.App.Converters;

/// <summary>Level → pinceau du thème courant (texte, ou fond doux si Soft=true).</summary>
public sealed class LevelToBrushConverter : IValueConverter
{
    public bool Soft { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var level = value is Level l ? l : Level.Neutral;
        var name = level switch { Level.Good => "Good", Level.Warning => "Warn", Level.Bad => "Bad", Level.Info => "Info", _ => "Neutral" };
        var key = name + (Soft ? "SoftBrush" : "Brush");
        return Application.Current.TryFindResource(key) as Brush ?? Brushes.Gray;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value is not true;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => value is not true;
}

public sealed class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value == null ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class NotNullToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value == null || (value is string s && s.Length == 0) ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Visible si la collection contient des éléments.</summary>
public sealed class CountToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var n = value switch { int i => i, ICollection c => c.Count, IEnumerable e => e.Cast<object>().Count(), _ => 0 };
        return n > 0 ? Visibility.Visible : Visibility.Collapsed;
    }
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Visible si la collection est vide (message "aucun élément").</summary>
public sealed class EmptyToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var n = value switch { int i => i, ICollection c => c.Count, IEnumerable e => e.Cast<object>().Count(), _ => 0 };
        return n == 0 ? Visibility.Visible : Visibility.Collapsed;
    }
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class NotNullToBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value != null;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Fraction 0..1 → largeur proportionnelle (étoile) pour les barres de statistiques.</summary>
public sealed class FractionToStarConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        new GridLength(Math.Max(0.0001, value is double d ? d : 0), GridUnitType.Star);
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Affiche les énumérations courantes en français dans les listes déroulantes.</summary>
public sealed class EnumTextConverter : IValueConverter
{
    static readonly CultureInfo Fr = new("fr-FR");

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        ScheduleFrequency f => f switch { ScheduleFrequency.Daily => "Quotidienne", ScheduleFrequency.Weekly => "Hebdomadaire", _ => "Mensuelle" },
        DayOfWeek d => Fr.DateTimeFormat.GetDayName(d) is { Length: > 0 } n ? char.ToUpper(n[0]) + n[1..] : d.ToString(),
        ScanKind k => k switch { ScanKind.Quick => "Rapide", ScanKind.Full => "Complète", ScanKind.File => "Fichier", _ => "Personnalisée" },
        FirewallProtocol p => p switch { FirewallProtocol.Any => "Tous", FirewallProtocol.Tcp => "TCP", FirewallProtocol.Udp => "UDP", FirewallProtocol.Icmpv4 => "ICMPv4", _ => "ICMPv6" },
        null => "",
        _ => value.ToString() ?? "",
    };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
