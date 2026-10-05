using System.Windows;
using System.Windows.Controls;
using SecureWall.App.ViewModels;

namespace SecureWall.App.Views;

public partial class RulesView : UserControl
{
    public RulesView() => InitializeComponent();

    void OnDirection(object sender, RoutedEventArgs e) { if (sender is RadioButton { Tag: string t } && DataContext is RulesViewModel vm) vm.Direction = t; }
    void OnAction(object sender, RoutedEventArgs e) { if (sender is RadioButton { Tag: string t } && DataContext is RulesViewModel vm) vm.ActionFilter = t; }
    void OnStatus(object sender, RoutedEventArgs e) { if (sender is RadioButton { Tag: string t } && DataContext is RulesViewModel vm) vm.StatusFilter = t; }
}
