using System.Windows;
using System.Windows.Controls;
using SecureWall.App.ViewModels;

namespace SecureWall.App.Views;

public partial class StatisticsView : UserControl
{
    public StatisticsView() => InitializeComponent();

    void OnPeriod(object sender, RoutedEventArgs e) { if (sender is RadioButton { Tag: string t } && DataContext is StatisticsViewModel vm) vm.Period = t; }
}
