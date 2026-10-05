using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Logic;
using SecureWall.PrivilegedService;
using SecureWall.PrivilegedService.SystemOperations;
using SecureWall.Security.DnsConfig;
using Xunit;

namespace SecureWall.Tests;

public class DnsLogicTests
{
    [Theory]
    [InlineData("1.1.1.1", "1.1.1.1", true)]
    [InlineData("8.8.8.8, 8.8.4.4", "8.8.8.8|8.8.4.4", true)]
    [InlineData("8.8.8.8;9.9.9.9 1.1.1.1", "8.8.8.8|9.9.9.9|1.1.1.1", true)]
    [InlineData("192.168.001.001", "192.168.1.1", true)]
    [InlineData("127.0.0.1", "127.0.0.1", true)]                       // résolveur local (dnscrypt, Pi-hole sur ce PC…)
    [InlineData("", "", false)]
    [InlineData("   ", "", false)]
    [InlineData("1.1.1", "", false)]
    [InlineData("1.1", "", false)]
    [InlineData("999.1.1.1", "", false)]
    [InlineData("dns.google", "", false)]
    [InlineData("2606:4700:4700::1111", "", false)]                    // IPv6 non géré à l'écriture
    [InlineData("0.0.0.0", "", false)]
    [InlineData("224.0.0.1", "", false)]
    [InlineData("255.255.255.255", "", false)]
    [InlineData("1.1.1.1,1.1.1.1", "", false)]
    [InlineData("1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9", "", false)]
    public void TryParseServers(string input, string expected, bool ok)
    {
        Assert.Equal(ok, DnsLogic.TryParseServers(input, out var servers, out var error));
        if (ok) { Assert.Equal(expected, string.Join("|", servers)); Assert.Equal("", error); }
        else Assert.NotEqual("", error);
    }

    [Fact]
    public void TryParseServers_NullIsRefused() => Assert.False(DnsLogic.TryParseServers(null, out _, out _));

    [Theory]
    [InlineData("1.1.1.1", "Cloudflare")]
    [InlineData("1.0.0.1", "Cloudflare")]
    [InlineData("1.1.1.3", "Cloudflare")]
    [InlineData("8.8.4.4", "Google Public DNS")]
    [InlineData("9.9.9.9", "Quad9")]
    [InlineData("208.67.222.222", "OpenDNS")]
    [InlineData("94.140.14.14", "AdGuard DNS")]
    [InlineData("2001:4860:4860::8888", "Google Public DNS")]
    [InlineData("192.168.1.1", "Réseau local (routeur ou box)")]
    [InlineData("10.0.0.2", "Réseau local (routeur ou box)")]
    [InlineData("fe80::1", "Réseau local (routeur ou box)")]
    [InlineData("127.0.0.1", "Cet ordinateur (résolveur local)")]
    [InlineData("::1", "Cet ordinateur (résolveur local)")]
    [InlineData("203.0.113.9", "Serveur non reconnu")]
    [InlineData("n'importe quoi", "Adresse invalide")]
    public void Describe(string address, string expected) => Assert.Equal(expected, DnsLogic.Describe(address));

    [Fact]
    public void OnlyUnknownPublicServersAreUnusual()
    {
        Assert.True(DnsLogic.IsUnusual("203.0.113.9"));
        Assert.False(DnsLogic.IsUnusual("192.168.1.1"));
        Assert.False(DnsLogic.IsUnusual("1.1.1.1"));
        Assert.False(DnsLogic.IsUnusual("127.0.0.1"));
    }

    [Fact]
    public void PresetsAreValidDistinctAndWithinLimits()
    {
        Assert.Equal(DnsLogic.Presets.Length, DnsLogic.Presets.Select(p => p.Name).Distinct().Count());
        foreach (var p in DnsLogic.Presets)
        {
            Assert.True(DnsLogic.TryParseServers(string.Join(",", p.Servers), out var s, out var e), $"{p.Name} : {e}");
            Assert.Equal(p.Servers, s);
            Assert.All(p.Servers, a => Assert.NotEqual("", DnsLogic.Provider(a)));
        }
    }
}

public class DnsConfiguratorTests
{
    sealed class FakeDnsSystem : IDnsSystem
    {
        public List<DnsAdapterInfo> Adapters { get; } = new()
        {
            new() { Index = 7, Name = "Wi-Fi", Servers = { "192.168.1.1" } },
            new() { Index = 12, Name = "Ethernet", IsManual = true, Servers = { "1.1.1.1" } },
        };
        public int ReturnCode { get; set; }
        public bool FlushOk { get; set; } = true;
        public List<(int Index, string[]? Servers)> Calls { get; } = new();
        public IReadOnlyList<DnsAdapterInfo> GetAdapters() => Adapters;
        public int SetServers(int interfaceIndex, string[]? servers) { Calls.Add((interfaceIndex, servers)); return ReturnCode; }
        public Task<bool> FlushCacheAsync(CancellationToken ct) => Task.FromResult(FlushOk);
    }

    [Fact]
    public void Set_AppliesValidatedServersToAnExistingAdapter_AndMentionsThePreviousOnes()
    {
        var sys = new FakeDnsSystem(); var c = new DnsConfigurator(sys);
        var r = c.Set("7", "1.1.1.1, 1.0.0.1");
        Assert.True(r.Ok, r.Message);
        Assert.Equal(7, sys.Calls.Single().Index);
        Assert.Equal(new[] { "1.1.1.1", "1.0.0.1" }, sys.Calls.Single().Servers);
        Assert.Contains("192.168.1.1", r.Message);        // ancienne valeur conservée dans le message / l'audit
    }

    [Theory]
    [InlineData("999")]        // carte inexistante
    [InlineData("abc")]
    [InlineData("-7")]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("7; calc")]
    public void Set_RefusesUnknownOrMalformedAdapters(string? index)
    {
        var sys = new FakeDnsSystem();
        Assert.False(new DnsConfigurator(sys).Set(index, "1.1.1.1").Ok);
        Assert.Empty(sys.Calls);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0.0.0.0")]
    [InlineData("1.1.1.1 & calc")]
    [InlineData("dns.google")]
    public void Set_RefusesInvalidServersWithoutTouchingTheSystem(string servers)
    {
        var sys = new FakeDnsSystem();
        Assert.False(new DnsConfigurator(sys).Set("7", servers).Ok);
        Assert.Empty(sys.Calls);
    }

    [Fact]
    public void Reset_PassesNullToReturnToDhcp()
    {
        var sys = new FakeDnsSystem();
        var r = new DnsConfigurator(sys).Reset("12");
        Assert.True(r.Ok);
        Assert.Equal(12, sys.Calls.Single().Index);
        Assert.Null(sys.Calls.Single().Servers);
        Assert.Contains("1.1.1.1", r.Message);
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, true)]       // 1 = redémarrage conseillé : la modification est faite
    [InlineData(91, false)]
    [InlineData(70, false)]
    [InlineData(-2, false)]
    [InlineData(84, false)]
    public void WmiReturnCodesAreInterpreted(int code, bool ok)
    {
        var sys = new FakeDnsSystem { ReturnCode = code };
        var r = new DnsConfigurator(sys).Set("7", "1.1.1.1");
        Assert.Equal(ok, r.Ok);
        if (!ok) Assert.NotEqual("", r.Message);
    }

    [Fact]
    public async Task Flush_ReportsSuccessAndFailure()
    {
        Assert.True((await new DnsConfigurator(new FakeDnsSystem()).FlushAsync(default)).Ok);
        Assert.False((await new DnsConfigurator(new FakeDnsSystem { FlushOk = false }).FlushAsync(default)).Ok);
    }
}

public class DnsPrivilegedOperationTests
{
    static PipeRequest Req(PrivilegedOperation op, params (string, string)[] args)
        => new() { Operation = op, Args = args.ToDictionary(a => a.Item1, a => a.Item2) };

    [Fact]
    public void EnvelopeAcceptsOnlyTheExpectedArguments()
    {
        Assert.Null(RequestDispatcher.ValidateEnvelope(Req(PrivilegedOperation.DnsSetServers, ("index", "7"), ("servers", "1.1.1.1"))));
        Assert.Null(RequestDispatcher.ValidateEnvelope(Req(PrivilegedOperation.DnsResetServers, ("index", "7"))));
        Assert.Null(RequestDispatcher.ValidateEnvelope(Req(PrivilegedOperation.DnsFlushCache)));
        Assert.NotNull(RequestDispatcher.ValidateEnvelope(Req(PrivilegedOperation.DnsSetServers, ("index", "7"), ("servers", "1.1.1.1"), ("cmd", "calc"))));
        Assert.NotNull(RequestDispatcher.ValidateEnvelope(Req(PrivilegedOperation.DnsFlushCache, ("index", "7"))));
        Assert.NotNull(RequestDispatcher.ValidateEnvelope(Req(PrivilegedOperation.DnsResetServers, ("servers", "1.1.1.1"))));
    }

    [Fact]
    public async Task HandlerRoutesToTheConfigurator_AndTurnsRefusalsIntoFailures()
    {
        var h = new DnsHandler(new DnsConfigurator(new Fake()));
        var ok = await h.HandleAsync(Req(PrivilegedOperation.DnsSetServers, ("index", "7"), ("servers", "9.9.9.9")), default);
        Assert.True(ok.Success, ok.Message);
        var bad = await h.HandleAsync(Req(PrivilegedOperation.DnsSetServers, ("index", "7"), ("servers", "0.0.0.0")), default);
        Assert.False(bad.Success);
        Assert.False((await h.HandleAsync(Req(PrivilegedOperation.DnsResetServers, ("index", "55")), default)).Success);
        Assert.True((await h.HandleAsync(Req(PrivilegedOperation.DnsFlushCache), default)).Success);
        Assert.False((await h.HandleAsync(Req(PrivilegedOperation.Ping), default)).Success);
    }

    sealed class Fake : IDnsSystem
    {
        public IReadOnlyList<DnsAdapterInfo> GetAdapters() => new[] { new DnsAdapterInfo { Index = 7, Name = "Wi-Fi" } };
        public int SetServers(int interfaceIndex, string[]? servers) => 0;
        public Task<bool> FlushCacheAsync(CancellationToken ct) => Task.FromResult(true);
    }
}
