using System.ComponentModel;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;

namespace SecureWall.App.Views;

public partial class MainWindow : Window
{
    public MainWindow() => InitializeComponent();

    protected override void OnClosing(CancelEventArgs e)
    {
        var app = App.Current;
        if (!app.IsQuitting && app.Services.GetRequiredService<ISettingsStore>().Current.MinimizeToTray)
        {
            e.Cancel = true;
            Hide();   // la surveillance continue dans la zone de notification
            return;
        }
        base.OnClosing(e);
        if (!e.Cancel && !app.IsQuitting) _ = app.QuitAsync();
    }
}
