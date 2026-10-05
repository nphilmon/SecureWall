using SecureWall.Infrastructure.Windows;

namespace SecureWall.Security.Monitoring;

public sealed record SecurityProduct(string Kind, string Name, bool Enabled, bool UpToDate);

/// <summary>Produits de sécurité enregistrés dans le Centre de sécurité Windows (WMI root\SecurityCenter2, lecture seule).</summary>
public static class WindowsSecurityCenter
{
    public static Task<IReadOnlyList<SecurityProduct>> ReadAsync() => Task.Run<IReadOnlyList<SecurityProduct>>(() =>
    {
        var list = new List<SecurityProduct>();
        foreach (var (cls, kind) in new[] { ("AntivirusProduct", "Antivirus"), ("FirewallProduct", "Pare-feu"), ("AntiSpywareProduct", "Anti-logiciels espions") })
        {
            try
            {
                foreach (var r in Wmi.Query(@"root\SecurityCenter2", $"SELECT * FROM {cls}"))
                {
                    var state = (uint)r.Long("productState");
                    // productState : 0x1000 = produit actif ; 0x10 = signatures périmées (décodage communément documenté).
                    list.Add(new SecurityProduct(kind, r.Str("displayName"), (state & 0x1000) != 0, (state & 0x10) == 0));
                }
            }
            catch { /* classe indisponible (Windows Server, politique) */ }
        }
        return list;
    });
}
