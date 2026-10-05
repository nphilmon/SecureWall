using SecureWall.Core.Enums;
using SecureWall.Core.Logic;
using SecureWall.Core.Models;
using SecureWall.Security.Antivirus;

namespace SecureWall.Tests;

public class DefenderServiceTests : IDisposable
{
    readonly TempDb _db = new();
    readonly FakeDefenderGateway _gw = new();
    readonly FakeNotifications _notify = new();
    readonly FakeAudit _audit = new();
    readonly DefenderService _svc;

    public DefenderServiceTests()
    {
        _svc = new DefenderService(_gw, _db.Store, new ThreatSync(_gw, _db.Store, _notify), _notify, _audit);
    }

    public void Dispose() => _db.Dispose();

    static DefenderThreat Threat(string id, int status = 1, bool active = true, DateTime? time = null, string name = "Virus:Test/Eicar") => new()
    {
        DetectionId = id, ThreatId = 1, Name = name, FilePath = @"C:\Test\x.exe", SeverityId = 5, StatusId = status, ActionId = status == 3 ? 2 : 9,
        IsActive = active, DetectionTime = time ?? DateTime.Now,
    };

    [Fact]
    public async Task Status_IsReadFromGateway()
    {
        var s = await _svc.GetStatusAsync();
        Assert.True(s.Available);
        Assert.Equal("1.0.0.0", s.SignatureVersion);
        Assert.Equal("1.0.0.0", (await _svc.GetSignatureVersionAsync()).Version);
    }

    [Fact]
    public async Task RealtimeProtection_ReflectsRealStateNeverSimulated()
    {
        _gw.Status = new DefenderStatus { Available = true, ServiceEnabled = true, AntivirusEnabled = true, RealTime = false, OnAccess = false, Downloads = true, Behavior = false };
        _gw.Prefs = new DefenderPreferences { Available = true, CloudReporting = 0, PuaProtection = 2 };

        var rt = await _svc.GetRealtimeProtectionStatusAsync();

        Assert.False(rt.RealTimeEnabled);
        Assert.Equal(FeatureState.Off, rt.Features.Single(f => f.Name == "Protection en temps réel").State);
        Assert.Equal(FeatureState.On, rt.Features.Single(f => f.Name == "Protection des téléchargements").State);
        Assert.Equal(FeatureState.Off, rt.Features.Single(f => f.Name == "Protection cloud").State);
        Assert.Equal(FeatureState.Off, rt.Features.Single(f => f.Name.StartsWith("Applications potentiellement")).State);   // audit = pas de blocage
        Assert.All(rt.Features, f => Assert.Equal("Microsoft Defender", f.ManagedBy));
    }

    [Fact]
    public async Task RealtimeProtection_WhenDefenderUnavailable_ReportsUnavailable()
    {
        _gw.Status = DefenderStatus.Unavailable("absent");
        _gw.Prefs = new DefenderPreferences();
        var rt = await _svc.GetRealtimeProtectionStatusAsync();
        Assert.All(rt.Features, f => Assert.Equal(FeatureState.Unavailable, f.State));
    }

    [Fact]
    public async Task QuickScan_UsesOfficialScanTypeAndReportsNewDetections()
    {
        _gw.OnScan = () => _gw.Detections.Add(Threat("d1", status: 3, active: false));

        var r = await _svc.StartQuickScanAsync();

        Assert.True(r.Completed);
        Assert.Equal(new[] { "-Scan", "-ScanType", "1" }, _gw.ScanCalls.Single());
        Assert.Equal(1, r.ThreatsFound);
        var rec = Assert.Single(_db.Store.GetScans());
        Assert.Equal("Terminée", rec.Status);
        Assert.Equal(1, rec.ThreatsFound);
        Assert.Contains(_notify.Sent, n => n.Kind == NotificationKind.ScanCompleted);
    }

    [Fact]
    public async Task FullScan_UsesScanType2()
    {
        await _svc.StartFullScanAsync();
        Assert.Equal("2", _gw.ScanCalls.Single()[2]);
    }

    [Fact]
    public async Task CustomScan_ScansEachPathAndReportsFileKind()
    {
        var file = Path.GetTempFileName();
        try
        {
            var r = await _svc.StartCustomScanAsync(new[] { file });
            Assert.Equal(ScanKind.File, r.Kind);
            var call = _gw.ScanCalls.Single();
            Assert.Equal(new[] { "-Scan", "-ScanType", "3", "-File", Path.GetFullPath(file) }, call);
            Assert.Equal(1, r.FilesScanned);
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public async Task OldDetections_AreNotAttributedToANewScan()
    {
        _gw.Detections.Add(Threat("old", time: DateTime.Now.AddDays(-3)));
        var r = await _svc.StartQuickScanAsync();
        Assert.Equal(0, r.ThreatsFound);
    }

    [Fact]
    public async Task Scan_WhenDefenderUnavailable_IsImpossibleAndNotAnError()
    {
        _gw.Status = DefenderStatus.Unavailable("Defender absent");
        var r = await _svc.StartQuickScanAsync();
        Assert.Equal("Impossible", r.Status);
        Assert.Empty(_gw.ScanCalls);
    }

    [Fact]
    public async Task Scan_CanBeCancelled()
    {
        _gw.ScanDuration = TimeSpan.FromSeconds(30);
        using var cts = new CancellationTokenSource();
        var task = _svc.StartQuickScanAsync(null, cts.Token);
        await Task.Delay(300);
        cts.Cancel();
        var r = await task;
        Assert.Equal("Annulée", r.Status);
        Assert.True(_gw.CancelCalled);
    }

    [Fact]
    public async Task Scan_FailureExitCode_IsReported()
    {
        _gw.ScanExitCode = 5;
        var r = await _svc.StartQuickScanAsync();
        Assert.Equal("Échec", r.Status);
    }

    [Fact]
    public async Task UpdateSignatures_ReportsFailureMessage()
    {
        _gw.UpdateExit = 1;
        var r = await _svc.UpdateSignaturesAsync();
        Assert.False(r.Success);
        Assert.Contains("échoué", r.Message);
        _gw.UpdateExit = 0;
        Assert.True((await _svc.UpdateSignaturesAsync()).Success);
    }

    [Fact]
    public async Task GetThreats_ReturnsOnlyUnresolved()
    {
        _gw.Detections.Add(Threat("a", status: 1, active: true));
        _gw.Detections.Add(Threat("b", status: 3, active: false));
        _gw.Detections.Add(Threat("c", status: 4, active: false));
        _gw.Detections.Add(Threat("d", status: 102, active: false));

        var threats = await _svc.GetThreatsAsync();
        var history = await _svc.GetProtectionHistoryAsync();

        Assert.Equal(new[] { "a", "d" }, threats.Select(t => t.DetectionId).OrderBy(x => x));
        Assert.Equal(4, history.Count);
    }

    [Fact]
    public async Task ThreatSync_FirstSyncIsSilent_ThenNotifiesNewDetectionsAndStatusChanges()
    {
        _gw.Detections.Add(Threat("existing", status: 4, active: false));
        await _svc.GetProtectionHistoryAsync();                     // référence silencieuse
        Assert.Empty(_notify.Sent);

        _gw.Detections.Add(Threat("new1"));
        await _svc.GetProtectionHistoryAsync();
        Assert.Contains(_notify.Sent, n => n.Kind == NotificationKind.ThreatDetected && n.Page == AppPage.Threats);

        _gw.Detections.RemoveAll(d => d.DetectionId == "new1");
        _gw.Detections.Add(Threat("new1", status: 3, active: false));   // passe en quarantaine
        await _svc.GetProtectionHistoryAsync();
        Assert.Contains(_notify.Sent, n => n.Kind == NotificationKind.Quarantined && n.Page == AppPage.Quarantine);
    }

    [Fact]
    public async Task GlobalState_ReflectsRealFacts()
    {
        var fine = new DefenderStatus { Available = true, AntivirusEnabled = true, RealTime = true, SignatureAgeDays = 0, LastQuickScan = DateTime.Now };
        Assert.Equal(GlobalState.Protected, GlobalStateEvaluator.Evaluate(fine, Array.Empty<DefenderThreat>(), true, 3, out _));
        Assert.Equal(GlobalState.ProtectionDisabled, GlobalStateEvaluator.Evaluate(fine, Array.Empty<DefenderThreat>(), false, 3, out _));
        Assert.Equal(GlobalState.ThreatDetected, GlobalStateEvaluator.Evaluate(fine, new[] { Threat("x") }, true, 3, out _));
        Assert.Equal(GlobalState.ProtectionDisabled, GlobalStateEvaluator.Evaluate(DefenderStatus.Unavailable("x"), Array.Empty<DefenderThreat>(), true, 3, out _));

        var stale = new DefenderStatus { Available = true, AntivirusEnabled = true, RealTime = true, SignatureAgeDays = 10, LastQuickScan = DateTime.Now };
        Assert.Equal(GlobalState.AttentionRequired, GlobalStateEvaluator.Evaluate(stale, Array.Empty<DefenderThreat>(), true, 3, out var reasons));
        Assert.NotEmpty(reasons);

        var passive = new DefenderStatus { Available = true, AntivirusEnabled = true, PassiveMode = true, RealTime = false, LastQuickScan = DateTime.Now, SignatureAgeDays = 0 };
        Assert.Equal(GlobalState.AttentionRequired, GlobalStateEvaluator.Evaluate(passive, Array.Empty<DefenderThreat>(), true, 3, out _));
        await Task.CompletedTask;
    }

    [Theory]
    [InlineData(@"file:_C:\Users\x\a.exe", @"C:\Users\x\a.exe")]
    [InlineData(@"containerfile:_C:\a.zip", @"C:\a.zip")]
    [InlineData(@"webfile:_C:\dl\b.exe|https://exemple.test/b.exe|pid:12", @"C:\dl\b.exe")]
    public void ResourceParsing(string resource, string expected) =>
        Assert.Equal(expected, typeof(DefenderGateway).GetMethod("ParseResource", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!.Invoke(null, new object[] { resource }));
}
