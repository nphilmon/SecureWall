using System.Windows;
using System.Windows.Controls;
using SecureWall.App.ViewModels;

namespace SecureWall.App.Views;

public partial class ThreatsView : UserControl
{
    public ThreatsView() => InitializeComponent();

    void OnFilter(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string tag } && DataContext is ThreatsViewModel vm) vm.Filter = tag;
    }
}
