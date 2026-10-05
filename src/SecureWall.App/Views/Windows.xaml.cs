using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Globalization;
using SecureWall.App.Services;
using SecureWall.App.ViewModels;

namespace SecureWall.App.Views;

/// <summary>Visible lorsque l'étape courante (int) est égale au paramètre.</summary>
public sealed class StepVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is int s && int.TryParse(parameter?.ToString(), out var p) && s == p ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public partial class RuleWizardWindow : Window
{
    public RuleWizardWindow() => InitializeComponent();

    void OnBrowse(object sender, RoutedEventArgs e)
    {
        var path = new DialogService().PickFile("Programmes (*.exe)|*.exe|Tous les fichiers|*.*", "Choisir le programme");
        if (path != null && DataContext is RuleWizardViewModel vm) vm.Program = path;
    }

    void OnFinish(object sender, RoutedEventArgs e)
    {
        if (DataContext is RuleWizardViewModel vm && vm.TryFinish()) DialogResult = true;
    }
}

public partial class NewAppAlertWindow : Window
{
    public AppAlertChoice? Choice { get; private set; }

    public NewAppAlertWindow(NetworkAppInfo app, NetConnection conn)
    {
        InitializeComponent();
        NameText.Text = app.Name;
        PublisherText.Text = string.IsNullOrEmpty(app.Publisher) ? "Éditeur inconnu" : app.Publisher;
        SignatureText.Text = app.Signature.Text;
        PathText.Text = app.Path;
        DestinationText.Text = $"{conn.RemoteAddress}";
        PortText.Text = conn.RemotePort.ToString();
        ProtocolText.Text = conn.Protocol;
        AppIcon.Source = IconCache.Get(app.Path);
    }

    void Pick(AppAlertChoice c) { Choice = c; Close(); }
    void OnAllowOnce(object s, RoutedEventArgs e) => Pick(AppAlertChoice.AllowOnce);
    void OnAlwaysAllow(object s, RoutedEventArgs e) => Pick(AppAlertChoice.AlwaysAllow);
    void OnBlockOnce(object s, RoutedEventArgs e) => Pick(AppAlertChoice.BlockOnce);
    void OnAlwaysBlock(object s, RoutedEventArgs e) => Pick(AppAlertChoice.AlwaysBlock);
}

public partial class ProgramAnalysisWindow : Window
{
    public ProgramAnalysisWindow() => InitializeComponent();

    void OnClose(object sender, RoutedEventArgs e) => Close();
}

public partial class FirstRunWindow : Window
{
    public FirstRunWindow() => InitializeComponent();
}

public partial class BaselineWindow : Window
{
    public BaselineWindow() => InitializeComponent();
}
