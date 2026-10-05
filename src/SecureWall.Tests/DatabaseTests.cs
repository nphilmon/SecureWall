using Microsoft.Data.Sqlite;
using SecureWall.Core.Enums;
using SecureWall.Core.Models;
using SecureWall.Infrastructure.Configuration;

namespace SecureWall.Tests;

public class DatabaseTests : IDisposable
{
    readonly TempDb _db = new();
    public void Dispose() => _db.Dispose();

    [Fact]
    public void Schema_ContainsAllRequiredTablesAndIndexes()
    {
        using var c = new SqliteConnection($"Data Source={_db.Path}");
        c.Open();
        var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT name FROM sqlite_master WHERE type IN ('table','index')";
        var names = new List<string>();
        using (var r = cmd.ExecuteReader()) while (r.Read()) names.Add(r.GetString(0));

        foreach (var t in new[] { "Applications", "Connections", "FirewallEvents", "AntivirusScans", "Threats", "Devices", "SecurityEvents", "AuditLogs", "Settings" })
            Assert.Contains(t, names);
        foreach (var i in new[] { "IX_Connections_Time", "IX_Connections_App", "IX_FwEvents_Time", "IX_Threats_Date", "IX_Events_Time", "IX_Audit_Time" })
            Assert.Contains(i, names);
    }

    [Fact]
    public void Application_IsInsertedOnceAndUpdatedAfterwards()
    {
        var id1 = _db.Store.UpsertApplication("app.exe", @"C:\A\app.exe", "", "", out var isNew1);
        var id2 = _db.Store.UpsertApplication("app.exe", @"c:\a\APP.exe", "Éditeur", "SignedValid", out var isNew2);   // chemin insensible à la casse
        Assert.True(isNew1);
        Assert.False(isNew2);
        Assert.Equal(id1, id2);
        var app = _db.Store.GetApplication(@"C:\A\app.exe")!;
        Assert.Equal("Éditeur", app.Publisher);
        Assert.Single(_db.Store.GetApplications());
    }

    [Fact]
    public void Connections_AreStoredAndAggregatedForStatistics()
    {
        var a = _db.Store.UpsertApplication("a.exe", @"C:\a.exe", "", "", out _);
        var b = _db.Store.UpsertApplication("b.exe", @"C:\b.exe", "", "", out _);
        var now = DateTime.Now;
        ConnectionRecord Row(string ip, int port) => new() { Protocol = "TCP", LocalAddress = "192.168.1.2", LocalPort = 50000, RemoteAddress = ip, RemotePort = port, State = "Établie", Timestamp = now };
        _db.Store.AddConnections(a, new[] { Row("1.1.1.1", 443), Row("1.1.1.1", 443), Row("8.8.8.8", 53) });
        _db.Store.AddConnections(b, new[] { Row("1.1.1.1", 443) });

        var since = now.AddHours(-1);
        var top = _db.Store.TopApplications(since, 5);
        Assert.Equal(3, top["a.exe"]);
        Assert.Equal(1, top["b.exe"]);
        Assert.Equal(3, _db.Store.TopPorts(since, 5)["443"]);
        Assert.Equal(3, _db.Store.TopDestinations(since, 5)["1.1.1.1"]);
        Assert.Equal(4, _db.Store.ConnectionsByHour(since).Values.Sum());
    }

    [Fact]
    public void Threat_UpsertReportsInsertThenStatusChange()
    {
        var t = new DefenderThreat { DetectionId = "id-1", Name = "Virus:Test", FilePath = @"C:\x.exe", SeverityId = 5, StatusId = 1, DetectionTime = DateTime.Now };
        var (inserted, prev) = _db.Store.UpsertThreat(t);
        Assert.True(inserted); Assert.Null(prev);

        var quarantined = new DefenderThreat { DetectionId = "id-1", Name = "Virus:Test", FilePath = @"C:\x.exe", SeverityId = 5, StatusId = 3, ActionId = 2, DetectionTime = t.DetectionTime };
        var (inserted2, prev2) = _db.Store.UpsertThreat(quarantined);
        Assert.False(inserted2);
        Assert.Equal("Actif", prev2);
        var rec = Assert.Single(_db.Store.GetThreats());
        Assert.Equal("Mis en quarantaine", rec.Status);
        Assert.Single(_db.Store.GetThreats(status: "Mis en quarantaine"));
        Assert.Empty(_db.Store.GetThreats(status: "Supprimé"));
    }

    [Fact]
    public void Events_SupportPagingAndSearch()
    {
        for (var i = 0; i < 25; i++) _db.Store.AddEvent("Test", i % 5 == 0 ? $"Alerte spéciale {i}" : $"Événement {i}");
        Assert.Equal(10, _db.Store.GetEvents(10).Count);
        Assert.Equal(5, _db.Store.GetEvents(10, 20).Count);
        var found = _db.Store.GetEvents(50, 0, "spéciale");
        Assert.Equal(5, found.Count);
        Assert.Equal(25, _db.Store.GetEvents(100).Count);
    }

    [Fact]
    public void Devices_RememberFirstSeenAndLastScan()
    {
        Assert.Null(_db.Store.GetDevice("dev-1"));
        _db.Store.SeenDevice("Clé 1", "dev-1");
        Assert.Null(_db.Store.GetDevice("dev-1")!.LastScanDate);
        _db.Store.MarkDeviceScanned("dev-1");
        _db.Store.SeenDevice("Clé 1 (renommée)", "dev-1");
        var d = _db.Store.GetDevice("dev-1")!;
        Assert.NotNull(d.LastScanDate);
        Assert.Equal("Clé 1 (renommée)", d.DeviceName);
        Assert.Single(_db.Store.GetDevices());
    }

    [Fact]
    public void Scans_AreRecordedWithStatus()
    {
        var id = _db.Store.StartScan("Rapide", "Système");
        Assert.Equal("En cours", _db.Store.GetScans().Single().Status);
        _db.Store.FinishScan(id, null, 2, "Terminée");
        var s = _db.Store.GetScans().Single();
        Assert.Equal("Terminée", s.Status); Assert.Equal(2, s.ThreatsFound); Assert.NotNull(s.EndDate); Assert.Null(s.FilesScanned);
        Assert.Equal(1, _db.Store.CountScans(DateTime.Now.AddMinutes(-5)));
    }

    [Fact]
    public void AuditLog_StoresActionsAndTruncatesHugeDetails()
    {
        _db.Store.AddAudit("utilisateur", "Création de règle", new string('x', 5000));
        var a = _db.Store.GetAudit().Single();
        Assert.Equal("Création de règle", a.Action);
        Assert.True(a.Details.Length <= 2000);
    }

    [Fact]
    public void FirewallEvents_AreCountedAsBlocked()
    {
        _db.Store.AddFirewallEvents(new[]
        {
            new FirewallEventRecord { Application = "a.exe", Action = "Bloquée", Direction = "Sortante", Protocol = "TCP", RemoteAddress = "1.2.3.4", RemotePort = 80, Timestamp = DateTime.Now },
            new FirewallEventRecord { Application = "a.exe", Action = "Bloquée", Direction = "Sortante", Protocol = "TCP", RemoteAddress = "1.2.3.5", RemotePort = 80, Timestamp = DateTime.Now },
        });
        Assert.Equal(2, _db.Store.CountBlocked(DateTime.Now.AddHours(-1)));
        Assert.Equal(2, _db.Store.BlockedByApplication(DateTime.Now.AddHours(-1), 5)["a.exe"]);
    }

    [Fact]
    public void Settings_RoundTripAndAreSanitized()
    {
        var settings = new SettingsStore(_db.Store);
        Assert.Equal(4, settings.Current.Schedules.Count);          // planifications par défaut
        settings.Current.RefreshSeconds = 999;                      // hors bornes
        settings.Current.Theme = ThemeMode.Dark;
        settings.Save();

        var reloaded = new SettingsStore(_db.Store);
        Assert.Equal(60, reloaded.Current.RefreshSeconds);
        Assert.Equal(ThemeMode.Dark, reloaded.Current.Theme);

        Assert.False(reloaded.ImportJson("{ pas du json").Success);
        Assert.True(reloaded.ImportJson(reloaded.ExportJson()).Success);
    }

    [Fact]
    public void Purge_RemovesOldHistoryAndKeepsRecent()
    {
        _db.Store.AddEvent("Test", "récent");
        _db.Store.PurgeOlderThan(DateTime.Now.AddDays(1));          // limite dans le futur : tout est "ancien"
        Assert.Empty(_db.Store.GetEvents());
        _db.Store.AddEvent("Test", "récent");
        _db.Store.PurgeOlderThan(DateTime.Now.AddDays(-30));
        Assert.Single(_db.Store.GetEvents());
    }

    [Fact]
    public void ClearHistory_RemovesEverythingButSettings()
    {
        _db.Store.SetSetting("k", "v");
        _db.Store.AddEvent("T", "x"); _db.Store.AddAudit("u", "a", "d"); _db.Store.SeenDevice("d", "i");
        _db.Store.ClearHistory();
        Assert.Empty(_db.Store.GetEvents()); Assert.Empty(_db.Store.GetAudit()); Assert.Empty(_db.Store.GetDevices());
        Assert.Equal("v", _db.Store.GetSetting("k"));
    }

    [Fact]
    public void LargeVolumes_RemainFastWithIndexes()
    {
        var app = _db.Store.UpsertApplication("big.exe", @"C:\big.exe", "", "", out _);
        var rows = Enumerable.Range(0, 20000).Select(i => new ConnectionRecord
        {
            Protocol = "TCP", LocalAddress = "10.0.0.1", LocalPort = 1000 + i % 100, RemoteAddress = "9.9.9." + (i % 250), RemotePort = 443, State = "Établie",
            Timestamp = DateTime.Now.AddMinutes(-i % 600),
        }).ToList();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        _db.Store.AddConnections(app, rows);
        var insert = sw.ElapsedMilliseconds; sw.Restart();
        var top = _db.Store.TopDestinations(DateTime.Now.AddDays(-1), 10);
        var query = sw.ElapsedMilliseconds;
        Assert.Equal(10, top.Count);
        Assert.True(insert < 10000, $"insertion trop lente : {insert} ms");
        Assert.True(query < 2000, $"requête trop lente : {query} ms");
    }
}
