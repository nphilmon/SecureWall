using System.Windows.Controls;
using System.Windows.Input;
using SecureWall.App.ViewModels;

namespace SecureWall.App.Views;

public partial class WorldMapView : UserControl
{
    public WorldMapView() => InitializeComponent();

    void Country_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (sender is System.Windows.FrameworkElement { DataContext: MapCountry country } && DataContext is WorldMapViewModel vm)
            vm.SelectCountryCommand.Execute(country);
    }
}
