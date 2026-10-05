using SecureWall.Core.Enums;
using SecureWall.Core.Logic;

namespace SecureWall.Tests;

public class SecurityEventTests
{
    static SecuritySnapshot Healthy() => new()
    {
        DefenderEnabled = true, RealTimeEnabled = true, FirewallDomain = true, FirewallPrivate = true, FirewallPublic = true,
        ExclusionsKnown = true, DefenderPrefsSignature = "2|1|1|False|False",
        Rules = new() { ["R1"] = "h1", ["R2"] = "h2" }, StartupKeys = new() { "hkcu-run|OneDrive|c:\\onedrive.exe" },
    };

    static SecuritySnapshot Copy(SecuritySnapshot s) => new()
    {
        DefenderEnabled = s.DefenderEnabled, RealTimeEnabled = s.RealTimeEnabled, FirewallDomain = s.FirewallDomain, FirewallPrivate = s.FirewallPrivate,
        FirewallPublic = s.FirewallPublic, ExclusionsKnown = s.ExclusionsKnown, Exclusions = new(s.Exclusions), DefenderPrefsSignature = s.DefenderPrefsSignature,
        Rules = new(s.Rules), StartupKeys = new(s.StartupKeys),
    };

    [Fact]
    public void FirstRun_ProducesNoAlerts() => Assert.Empty(SecurityChangeDetector.Compare(null, Healthy()));

    [Fact]
    public void NoChange_ProducesNoAlerts() => Assert.Empty(SecurityChangeDetector.Compare(Healthy(), Healthy()));

    [Fact]
    public void FirewallDisabled_RaisesWarningWithNotification()
    {
        var now = Copy(Healthy()); now.FirewallPublic = false;
        var c = Assert.Single(SecurityChangeDetector.Compare(Healthy(), now));
        Assert.Equal("Pare-feu", c.EventType);
        Assert.Equal("Attention", c.Severity);
        Assert.Equal(NotificationKind.FirewallDisabled, c.Notify);
        Assert.Contains("Public", c.Description);
    }

    [Fact]
    public void FirewallReEnabled_IsReportedAsSuccessWithoutNotification()
    {
        var before = Copy(Healthy()); before.FirewallPrivate = false;
        var c = Assert.Single(SecurityChangeDetector.Compare(before, Healthy()));
        Assert.Equal("Succès", c.Severity);
        Assert.Null(c.Notify);
    }

    [Fact]
    public void DefenderAndRealtimeDisabled_AreDetected()
    {
        var now = Copy(Healthy()); now.DefenderEnabled = false; now.RealTimeEnabled = false;
        var changes = SecurityChangeDetector.Compare(Healthy(), now);
        Assert.Equal(2, changes.Count);
        Assert.All(changes, c => Assert.Equal(NotificationKind.DefenderDisabled, c.Notify));
    }

    [Fact]
    public void NewExclusion_IsDetectedWithClearWarning()
    {
        var now = Copy(Healthy()); now.Exclusions.Add(@"Dossier/fichier : C:\Jeux");
        var c = Assert.Single(SecurityChangeDetector.Compare(Healthy(), now));
        Assert.Contains("réduit la protection", c.Description);
        Assert.Equal(NotificationKind.SecurityChange, c.Notify);
    }

    [Fact]
    public void Exclusions_AreIgnoredWhenNotVisibleWithoutAdminRights()
    {
        var before = Healthy(); before.ExclusionsKnown = false;
        var now = Copy(Healthy()); now.ExclusionsKnown = false; now.Exclusions.Add("x");
        Assert.Empty(SecurityChangeDetector.Compare(before, now));
    }

    [Fact]
    public void NewAndModifiedRules_AreDetected()
    {
        var now = Copy(Healthy());
        now.Rules["R3"] = "h3";        // ajoutée
        now.Rules["R1"] = "h1-bis";    // modifiée
        var changes = SecurityChangeDetector.Compare(Healthy(), now);
        Assert.Contains(changes, c => c.Description.StartsWith("Nouvelle règle") && c.Description.Contains("R3"));
        Assert.Contains(changes, c => c.Description.StartsWith("Règle de pare-feu modifiée") && c.Description.Contains("R1"));
    }

    [Fact]
    public void MassRuleAddition_IsSummarisedNotFlooded()
    {
        var now = Copy(Healthy());
        for (var i = 0; i < 50; i++) now.Rules["Nouvelle " + i] = "h";
        var changes = SecurityChangeDetector.Compare(Healthy(), now);
        Assert.True(changes.Count <= 7);
        Assert.Contains(changes, c => c.Description.Contains("50 nouvelles règles"));
    }

    [Fact]
    public void NewStartupEntry_IsDetected()
    {
        var now = Copy(Healthy()); now.StartupKeys.Add("hkcu-run|Inconnu|c:\\x\\inconnu.exe");
        var c = Assert.Single(SecurityChangeDetector.Compare(Healthy(), now));
        Assert.Equal("Démarrage", c.EventType);
        Assert.Contains("Inconnu", c.Description);
    }

    [Fact]
    public void DefenderSettingsChange_IsReportedNeutrally()
    {
        var now = Copy(Healthy()); now.DefenderPrefsSignature = "0|1|1|True|False";
        var c = Assert.Single(SecurityChangeDetector.Compare(Healthy(), now));
        Assert.Equal("Information", c.Severity);
    }
}
