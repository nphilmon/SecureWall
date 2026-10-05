using System.Globalization;

namespace SecureWall.Core.Logic;

public sealed record MapShape(string Code, string Name, string PathData);

/// <summary>Fond de carte intégré (Natural Earth 110m, domaine public) : une ligne par pays « CODE⇥Nom⇥tracé SVG », projection équirectangulaire.</summary>
public sealed class WorldMapData
{
    public double Width { get; init; } = 1000;
    public double Height { get; init; } = 394.4;
    public IReadOnlyList<MapShape> Shapes { get; init; } = Array.Empty<MapShape>();

    public static WorldMapData Parse(string text)
    {
        double w = 1000, h = 394.4;
        var shapes = new List<MapShape>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;
            if (line.StartsWith('#'))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 6 && parts[1] == "VIEWBOX"
                    && double.TryParse(parts[4], NumberStyles.Float, CultureInfo.InvariantCulture, out var vw)
                    && double.TryParse(parts[5], NumberStyles.Float, CultureInfo.InvariantCulture, out var vh)) { w = vw; h = vh; }
                continue;
            }
            var cols = line.Split('\t');
            if (cols.Length != 3 || cols[0].Length != 2 || !cols[2].StartsWith('M')) continue;
            shapes.Add(new MapShape(cols[0].ToUpperInvariant(), cols[1], cols[2]));
        }
        return new WorldMapData { Width = w, Height = h, Shapes = shapes };
    }
}
