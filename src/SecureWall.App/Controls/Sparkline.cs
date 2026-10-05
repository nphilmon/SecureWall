using System.Collections;
using System.Collections.Specialized;
using System.Windows;
using System.Windows.Media;

namespace SecureWall.App.Controls;

/// <summary>Courbe compacte (débit réseau). Dessin direct, sans élément visuel par point.</summary>
public sealed class Sparkline : FrameworkElement
{
    public static readonly DependencyProperty ValuesProperty = DependencyProperty.Register(nameof(Values), typeof(IEnumerable), typeof(Sparkline),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, (d, e) => ((Sparkline)d).OnValuesChanged(e)));
    public static readonly DependencyProperty StrokeProperty = DependencyProperty.Register(nameof(Stroke), typeof(Brush), typeof(Sparkline),
        new FrameworkPropertyMetadata(Brushes.DodgerBlue, FrameworkPropertyMetadataOptions.AffectsRender));

    public IEnumerable? Values { get => (IEnumerable?)GetValue(ValuesProperty); set => SetValue(ValuesProperty, value); }
    public Brush Stroke { get => (Brush)GetValue(StrokeProperty); set => SetValue(StrokeProperty, value); }

    void OnValuesChanged(DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is INotifyCollectionChanged o) o.CollectionChanged -= OnCollectionChanged;
        if (e.NewValue is INotifyCollectionChanged n) n.CollectionChanged += OnCollectionChanged;
    }

    void OnCollectionChanged(object? s, NotifyCollectionChangedEventArgs e) => InvalidateVisual();

    protected override void OnRender(DrawingContext dc)
    {
        var data = Values?.Cast<object>().Select(Convert.ToDouble).ToArray();
        if (data == null || data.Length < 2 || ActualWidth < 4 || ActualHeight < 4) return;
        var max = Math.Max(data.Max(), 1);
        var w = ActualWidth;
        var h = ActualHeight - 4;
        var step = w / (data.Length - 1);

        var line = new StreamGeometry();
        using (var ctx = line.Open())
        {
            ctx.BeginFigure(new Point(0, h - data[0] / max * h + 2), false, false);
            for (var i = 1; i < data.Length; i++)
                ctx.LineTo(new Point(i * step, h - data[i] / max * h + 2), true, true);
        }
        line.Freeze();

        var area = new StreamGeometry();
        using (var ctx = area.Open())
        {
            ctx.BeginFigure(new Point(0, ActualHeight), true, true);
            for (var i = 0; i < data.Length; i++) ctx.LineTo(new Point(i * step, h - data[i] / max * h + 2), false, false);
            ctx.LineTo(new Point(w, ActualHeight), false, false);
        }
        area.Freeze();

        var fill = Stroke.Clone();
        fill.Opacity = 0.14;
        dc.DrawGeometry(fill, null, area);
        dc.DrawGeometry(null, new Pen(Stroke, 1.8) { LineJoin = PenLineJoin.Round }, line);
    }
}
