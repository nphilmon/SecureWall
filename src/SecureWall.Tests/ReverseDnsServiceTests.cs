using System.Net;
using System.Net.Sockets;
using SecureWall.Security.Network;
using Xunit;

namespace SecureWall.Tests;

public class ReverseDnsServiceTests
{
    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("192.168.1.1", true)]
    [InlineData("2606:4700::1111", true)]
    [InlineData("::ffff:8.8.8.8", true)]
    [InlineData("0.0.0.0", false)]
    [InlineData("::", false)]
    [InlineData("255.255.255.255", false)]
    [InlineData("224.0.0.251", false)]
    [InlineData("ff02::fb", false)]
    [InlineData("", false)]
    [InlineData("pas une ip", false)]
    [InlineData("dns.google", false)]
    public void IsResolvable(string address, bool expected) => Assert.Equal(expected, ReverseDnsService.IsResolvable(address, out _));

    [Fact]
    public async Task Resolves_AndTrimsTrailingDot_AndCaches()
    {
        var calls = 0;
        var svc = new ReverseDnsService((_, _) => { calls++; return Task.FromResult<string?>("dns.google."); });

        Assert.Null(svc.TryGetCached("8.8.8.8"));                       // rien en cache, aucune requête
        var r = await svc.ResolveAsync("8.8.8.8");
        Assert.True(r.HasName); Assert.Equal("dns.google", r.HostName);

        Assert.Equal("dns.google", (await svc.ResolveAsync("8.8.8.8")).HostName);
        Assert.Equal("dns.google", svc.TryGetCached("8.8.8.8")!.HostName);
        Assert.Equal(1, calls);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("8.8.8.8")]            // le résolveur renvoie l'adresse elle-même : pas de nom
    public async Task NoName_WhenResolverReturnsNothingUseful(string? name)
    {
        var svc = new ReverseDnsService((_, _) => Task.FromResult(name));
        var r = await svc.ResolveAsync("8.8.8.8");
        Assert.Equal(ReverseDnsStatus.NoName, r.Status);
        Assert.False(r.HasName);
    }

    [Fact]
    public async Task HostNotFound_IsNoNameAndCached_OtherSocketErrorsAreNot()
    {
        var calls = 0;
        var svc = new ReverseDnsService((_, _) => { calls++; throw new SocketException((int)SocketError.HostNotFound); });
        Assert.Equal(ReverseDnsStatus.NoName, (await svc.ResolveAsync("1.2.3.4")).Status);
        await svc.ResolveAsync("1.2.3.4");
        Assert.Equal(1, calls);

        var flaky = new ReverseDnsService((_, _) => { calls++; throw new SocketException((int)SocketError.TryAgain); });
        Assert.Equal(ReverseDnsStatus.Failed, (await flaky.ResolveAsync("1.2.3.4")).Status);
        Assert.Null(flaky.TryGetCached("1.2.3.4"));
    }

    [Fact]
    public async Task Skipped_WithoutAnyLookup_ForUnresolvableAddress()
    {
        var called = false;
        var svc = new ReverseDnsService((_, _) => { called = true; return Task.FromResult<string?>("x"); });
        Assert.Equal(ReverseDnsStatus.Skipped, (await svc.ResolveAsync("224.0.0.251")).Status);
        Assert.False(called);
    }

    [Fact]
    public async Task Timeout_IsReportedAsFailureAndNotCached()
    {
        var svc = new ReverseDnsService(async (_, ct) => { await Task.Delay(Timeout_Infinite, ct); return null; });
        using var cts = new CancellationTokenSource();
        var task = svc.ResolveAsync("1.2.3.4", cts.Token);
        // Pas d'attente réelle de 4 s : on vérifie seulement que l'annulation de l'appelant se propage, et qu'un échec n'est jamais mis en cache.
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        Assert.Null(svc.TryGetCached("1.2.3.4"));
    }

    const int Timeout_Infinite = -1;

    [Fact]
    public async Task UnexpectedErrors_AreReportedWithoutThrowing()
    {
        var svc = new ReverseDnsService((_, _) => throw new InvalidOperationException("boom"));
        var r = await svc.ResolveAsync("1.2.3.4");
        Assert.Equal(ReverseDnsStatus.Failed, r.Status);
        Assert.Contains("boom", r.Message);
    }
}
