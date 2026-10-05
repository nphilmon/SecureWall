namespace SecureWall.Core.Logic;

/// <summary>Textes du mode urgence (logique pure, testée).</summary>
public static class EmergencyText
{
    /// <summary>Durées proposées pour le rétablissement automatique : (minutes, libellé). 0 = jusqu'à action manuelle.</summary>
    public static readonly (int Minutes, string Label)[] AutoRestoreOptions =
    {
        (0, "Jusqu'à ce que je le rétablisse"), (5, "5 minutes"), (15, "15 minutes"), (30, "30 minutes"), (60, "1 heure"), (240, "4 heures"),
    };

    public static string Duration(TimeSpan t)
    {
        if (t <= TimeSpan.Zero) return "quelques secondes";
        if (t.TotalMinutes < 1) return "moins d'une minute";
        var totalMin = (int)Math.Ceiling(t.TotalMinutes);
        if (totalMin < 60) return totalMin + " min";
        var h = totalMin / 60; var m = totalMin % 60;
        return m == 0 ? h + " h" : $"{h} h {m:00}";
    }

    /// <summary>Texte du badge d'en-tête.</summary>
    public static string Badge(bool active, DateTime? autoRestoreAt, DateTime now)
    {
        if (!active) return "";
        return autoRestoreAt is { } at
            ? $"Mode urgence : Internet coupé · rétabli dans {Duration(at - now)}"
            : "Mode urgence : Internet coupé";
    }
}
