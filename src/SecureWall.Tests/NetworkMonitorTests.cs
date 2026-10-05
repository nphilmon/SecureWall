using System.Net;
using SecureWall.Core.Logic;
using SecureWall.Core.Models;
using SecureWall.Infrastructure.Configuration;
using SecureWall.Security.Network;

namespace SecureWall.Tests;

public class NetworkMonitorTests : IDisposable
{
    readonly TempDb _db = new();
    readonly FakeConnectionSource _source = new();
    readonly FakeSignatures _sigs = new();
    readonly SettingsStore _settings;

    public NetworkMonitorTests() => _settings = new SettingsStore(_db.Store);
    public void Dispose() => _db.Dispose();

    static NetConnection Conn(string path, string remote = "93.184.216.34", int rport = 443, int pid = 100, bool established = true, bool listening = false) => new()
    {
        Protocol = "TCP", LocalAddress = "192.168.1.5", LocalPort = 50000 + pid, RemoteAddress = remote, RemotePort = rport, State = established ? "Établie" : "À l'écoute",
        Pid = pid, IsEstablished = established, IsListening = listening, IsExternal = NetworkAddressClassifier.IsExternal(remote),
        ProcessName = Path.GetFileName(path), ProcessPath = path,
    };

    NetworkMonitor Monitor(TimeSpan? learning = null) => new(_source, _db.Store, _settings, _sigs, new ProcessIdentityCache(), null, null, learning ?? TimeSpan.Zero);

    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("93.184.216.34", true)]
    [InlineData("127.0.0.1", false)]
    [InlineData("10.1.2.3", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("172.32.0.1", true)]
    [InlineData("192.168.1.1", false)]
    [InlineData("169.254.1.1", false)]
    [InlineData("224.0.0.251", false)]
    [InlineData("0.0.0.0", false)]
    [InlineData("::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("fd00::1", false)]
    [InlineData("2606:4700:4700::1111", true)]
    [InlineData("::ffff:192.168.1.1", false)]
    [InlineData("n'importe quoi", false)]
    public void AddressClassification(string ip, bool external) => Assert.Equal(external, NetworkAddressClassifier.IsExternal(ip));

    [Fact]
    public void Analyzer_ComputesTopApplicationsPortsAndStates()
    {
        var conns = new[]
        {
            Conn(@"C:\a\a.exe", pid: 1), Conn(@"C:\a\a.exe", pid: 1, rport: 80), Conn(@"C:\b\b.exe", pid: 2),
            Conn(@"C:\b\b.exe", pid: 2, established: false, listening: true, remote: "0.0.0.0", rport: 0),
        };
        var apps = ConnectionAnalyzer.TopApplications(conns);
        Assert.Equal("a.exe", apps[0].App);
        Assert.Equal(2, apps[0].Count);
        var ports = ConnectionAnalyzer.TopRemotePorts(conns);
        Assert.Equal(443, ports[0].Port);
        Assert.Equal(2, ports[0].Count);
        var states = ConnectionAnalyzer.CountByState(conns);
        Assert.Equal(3, states["Établie"]);
    }

    [Fact]
    public async Task Observe_RecordsApplicationAndExternalConnections()
    {
        _source.Connections.Add(Conn(@"C:\Prog\client.exe"));
        _source.Connections.Add(Conn(@"C:\Prog\client.exe", remote: "192.168.1.9", rport: 445));    // local : non enregistrée
        var mon = Monitor();
        await mon.ObserveOnceAsync();

        var app = Assert.Single(_db.Store.GetApplications());
        Assert.Equal("client.exe", app.Name);
        Assert.Equal("Éditeur Test", app.Publisher);
        Assert.Equal(1, _db.Store.TopDestinations(DateTime.Now.AddHours(-1), 5).Values.Sum());
    }

    [Fact]
    public async Task Observe_DoesNotDuplicateTheSameConnectionEveryCycle()
    {
        _source.Connections.Add(Conn(@"C:\Prog\client.exe"));
        var mon = Monitor();
        await mon.ObserveOnceAsync(); await mon.ObserveOnceAsync(); await mon.ObserveOnceAsync();
        Assert.Equal(1, _db.Store.ConnectionsByHour(DateTime.Now.AddHours(-1)).Values.Sum());
    }

    [Fact]
    public async Task NewApplication_RaisesEventOnce_AfterLearningPeriod()
    {
        var raised = new List<NetworkAppInfo>();
        var mon = Monitor(TimeSpan.Zero);
        mon.NewApplicationDetected += (a, _) => raised.Add(a);

        _source.Connections.Add(Conn(@"C:\Users\x\AppData\inconnu.exe"));
        await Task.Delay(20);
        await mon.ObserveOnceAsync();
        await mon.ObserveOnceAsync();

        Assert.Single(raised);
        Assert.Equal("inconnu.exe", raised[0].Name);
    }

    [Fact]
    public async Task NewApplication_IsSilentDuringLearningPeriod()
    {
        var raised = 0;
        var mon = Monitor(TimeSpan.FromMinutes(5));
        mon.NewApplicationDetected += (_, _) => raised++;
        _source.Connections.Add(Conn(@"C:\Users\x\AppData\inconnu.exe"));
        await mon.ObserveOnceAsync();
        Assert.Equal(0, raised);
        Assert.Single(_db.Store.GetApplications());      // mais l'application est bien mémorisée
    }

    [Fact]
    public async Task WindowsComponents_AreNeverReportedAsNewApplications()
    {
        var raised = 0;
        var mon = Monitor(TimeSpan.Zero);
        mon.NewApplicationDetected += (_, _) => raised++;
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        _source.Connections.Add(Conn(Path.Combine(win, "System32", "svchost.exe")));
        await Task.Delay(20);
        await mon.ObserveOnceAsync();
        Assert.Equal(0, raised);
    }

    [Fact]
    public async Task ListeningSockets_DoNotCreateApplications()
    {
        _source.Connections.Add(Conn(@"C:\Prog\server.exe", remote: "0.0.0.0", rport: 0, established: false, listening: true));
        await Monitor().ObserveOnceAsync();
        Assert.Empty(_db.Store.GetApplications());
    }

    [Fact]
    public void CriticalProcessPolicy_RecognisesWindowsAndUnusualLocations()
    {
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        Assert.True(CriticalProcessPolicy.IsCriticalWindowsComponent(Path.Combine(win, "System32", "lsass.exe")));
        Assert.True(CriticalProcessPolicy.IsCriticalWindowsComponent(""));
        Assert.False(CriticalProcessPolicy.IsCriticalWindowsComponent(@"C:\Program Files\App\app.exe"));
        Assert.True(CriticalProcessPolicy.IsUnusualLocation(@"C:\Users\x\AppData\Local\Temp\a.exe"));
        Assert.True(CriticalProcessPolicy.IsUnusualLocation(@"C:\Users\x\Downloads\a.exe"));
        Assert.True(CriticalProcessPolicy.IsUnusualLocation(@"C:\a.exe"));
        Assert.False(CriticalProcessPolicy.IsUnusualLocation(@"C:\Program Files\App\a.exe"));
    }

    [Fact]
    public void IpHelper_ReadsRealConnectionsWithoutThrowing()
    {
        // Lecture seule des tables TCP/UDP de la machine : aucune modification.
        var all = IpHelper.ReadAll();
        Assert.NotEmpty(all);
        Assert.All(all, c => Assert.InRange(c.LocalPort, 0, 65535));
    }
}
