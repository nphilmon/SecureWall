using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureWall.Core.Enums;
using SecureWall.Core.Models;
using SecureWall.Security.Firewall;

namespace SecureWall.Tests;

public class BaselineRulesTests : IDisposable
{
    readonly TempDb _db = new();
    readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    string Pub => Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo());
    public void Dispose() { _db.Dispose(); _key.Dispose(); }

    static string RulesJson(int version = 5, string name = "SecureWall Base - Test", string extra = "") =>
        "{\"Format\":\"SecureWall.Baseline\",\"Version\":" + version + ",\"Name\":\"Test\",\"Published\":\"2026-01-01\",\"Source\":\"s\",\"Rules\":[" +
        "{\"Name\":\"" + name + "\",\"Enabled\":true,\"Direction\":\"Outbound\",\"Action\":\"Block\",\"Protocol\":\"Tcp\",\"RemotePorts\":\"23\",\"Profiles\":\"All\"" + extra + "}]}";

    string Sign(string payload, ECDsa? with = null)
    {
        var sig = (with ?? _key).SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256);
        return JsonSerializer.Serialize(new { Payload = payload, Signature = Convert.ToBase64String(sig) });
    }

    BaselineRulesService Service(FakePrivilegedClient? client = null, Func<Uri, CancellationToken, Task<string>>? fetch = null)
    {
        var audit = new FakeAudit();
        var rules = new FirewallRuleService(new FakeFirewallPolicy(), client ?? new FakePrivilegedClient(), audit);
        return new BaselineRulesService(_db.Store, rules, audit, fetch, Pub);
    }

    [Fact]
    public void ValidSignature_IsAccepted()
    {
        var set = BaselineRulesService.Verify(Sign(RulesJson()), Pub, out var err);
        Assert.NotNull(set); Assert.Equal("", err);
        Assert.Equal(5, set!.Version);
    }

    [Fact]
    public void TamperedPayload_IsRejected()
    {
        var good = Sign(RulesJson());
        var tampered = good.Replace("\\u0022", "\\u0022").Replace("23", "22");     // modifie le port après signature
        Assert.Null(BaselineRulesService.Verify(tampered, Pub, out var err));
        Assert.Contains("Signature invalide", err);
    }

    [Fact]
    public void SignatureFromAnotherKey_IsRejected()
    {
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.Null(BaselineRulesService.Verify(Sign(RulesJson(), other), Pub, out var err));
        Assert.Contains("Signature invalide", err);
    }

    [Theory]
    [InlineData("n'importe quoi")]
    [InlineData("{}")]
    [InlineData("{\"Payload\":\"x\",\"Signature\":\"pas-base64!\"}")]
    public void GarbageIsRejectedWithoutException(string input) => Assert.Null(BaselineRulesService.Verify(input, Pub, out _));

    [Fact]
    public void SignedButUnsafeRules_AreStillRejected()
    {
        // Nom hors convention
        Assert.Null(BaselineRulesService.Verify(Sign(RulesJson(name: "Autre nom")), Pub, out _));
        // Règle invalide (port hors limites)
        Assert.Null(BaselineRulesService.Verify(Sign(RulesJson().Replace("\"23\"", "\"99999\"")), Pub, out _));
        // Règle qui ouvrirait un accès entrant
        var allowIn = RulesJson().Replace("\"Outbound\"", "\"Inbound\"").Replace("\"Block\"", "\"Allow\"");
        Assert.Null(BaselineRulesService.Verify(Sign(allowIn), Pub, out var err));
        Assert.Contains("entrant", err);
    }

    [Fact]
    public void ProgramTargets_AreStrippedFromBaselineRules()
    {
        var set = BaselineRulesService.Verify(Sign(RulesJson(extra: ",\"Program\":\"C:\\\\Windows\\\\notepad.exe\"")), Pub, out _);
        Assert.Equal("", set!.Rules[0].Program);
    }

    [Theory]
    [InlineData("https://raw.githubusercontent.com/user/repo/main/baseline.json", true)]
    [InlineData("http://raw.githubusercontent.com/user/repo/main/baseline.json", false)]
    [InlineData("https://exemple.com/baseline.json", false)]
    [InlineData("https://raw.githubusercontent.com.evil.test/x.json", false)]
    [InlineData("https://raw.githubusercontent.com:8443/x.json", false)]
    [InlineData("ftp://raw.githubusercontent.com/x", false)]
    [InlineData("pas une url", false)]
    public void OnlyTrustedHttpsHostsAreAllowed(string url, bool ok) => Assert.Equal(ok, BaselineRulesService.IsAllowedUrl(url, out _));

    [Fact]
    public void BundledRuleSet_HasValidSignatureUnderTheEmbeddedPublicKey()
    {
        var svc = new BaselineRulesService(_db.Store, new FirewallRuleService(new FakeFirewallPolicy(), new FakePrivilegedClient(), new FakeAudit()), new FakeAudit());
        var set = svc.LoadBundled();
        Assert.True(set.Rules.Count >= 5);
        Assert.All(set.Rules, r => Assert.StartsWith("SecureWall Base - ", r.Name));
        Assert.All(set.Rules, r => Assert.Equal(FirewallAction.Block, r.Action));
    }

    [Fact]
    public async Task Update_NewerVersionIsCachedAndPreferred_OlderIsIgnored()
    {
        var svc = Service(fetch: (_, _) => Task.FromResult(Sign(RulesJson(version: 5))));
        var bundled = svc.LoadBundled().Version;
        var url = "https://raw.githubusercontent.com/u/r/main/b.json";

        var (set, _) = await Service(fetch: (_, _) => Task.FromResult(Sign(RulesJson(version: bundled + 1)))).CheckForUpdateAsync(url);
        Assert.NotNull(set);

        var same = Service(fetch: (_, _) => Task.FromResult(Sign(RulesJson(version: bundled))));
        var (none, msg) = await same.CheckForUpdateAsync(url);
        Assert.Null(none);
        Assert.Contains("dernière version", msg);
    }

    [Fact]
    public async Task Update_RejectsUnsignedDownloadsAndBadHostsWithoutFetching()
    {
        var fetched = 0;
        var svc = Service(fetch: (_, _) => { fetched++; return Task.FromResult("{\"Payload\":\"{}\",\"Signature\":\"AAAA\"}"); });
        var (s1, m1) = await svc.CheckForUpdateAsync("https://evil.example/b.json");
        Assert.Null(s1); Assert.Equal(0, fetched);
        var (s2, m2) = await svc.CheckForUpdateAsync("https://raw.githubusercontent.com/u/r/main/b.json");
        Assert.Null(s2); Assert.Equal(1, fetched);
        Assert.Contains("Signature", m2);
        Assert.Contains("refusée", m1);
    }

    [Fact]
    public async Task Update_NetworkFailureIsReportedNotThrown()
    {
        var svc = Service(fetch: (_, _) => throw new HttpRequestException("hors ligne"));
        var (s, m) = await svc.CheckForUpdateAsync("https://raw.githubusercontent.com/u/r/main/b.json");
        Assert.Null(s); Assert.Contains("hors ligne", m);
    }

    [Fact]
    public void Preview_MarksExistingRulesAndDoesNotSelectThem()
    {
        var set = BaselineRulesService.Verify(Sign(RulesJson()), Pub, out _)!;
        var existing = new[] { new FirewallRule { Name = "secureWall base - test" } };
        var items = BaselineRulesService.Preview(set, existing);
        Assert.Equal(BaselineStatus.AlreadyPresent, items.Single().Status);
        Assert.False(items.Single().IsSelected);
        Assert.Equal(BaselineStatus.New, BaselineRulesService.Preview(set, Array.Empty<FirewallRule>()).Single().Status);
    }

    [Fact]
    public async Task Apply_CreatesOnlySelectedNewRulesThroughThePrivilegedService()
    {
        var client = new FakePrivilegedClient();
        var svc = Service(client);
        var set = BaselineRulesService.Verify(Sign(RulesJson()), Pub, out _)!;
        var items = BaselineRulesService.Preview(set, Array.Empty<FirewallRule>()).ToList();

        items[0].IsSelected = false;
        var none = await svc.ApplyAsync(set, items);
        Assert.False(none.Success);
        Assert.Empty(client.Requests);

        items[0].IsSelected = true;
        var r = await svc.ApplyAsync(set, items);
        Assert.True(r.Success);
        Assert.Equal(PrivilegedOperation.FirewallCreateRule, client.Requests.Single().Op);
        Assert.Equal(5, svc.AppliedVersion);
    }

    [Fact]
    public async Task Apply_WhenServiceUnavailable_ReportsFailureWithoutMarkingApplied()
    {
        var svc = Service(new FakePrivilegedClient { Available = false });
        var set = BaselineRulesService.Verify(Sign(RulesJson()), Pub, out _)!;
        var r = await svc.ApplyAsync(set, BaselineRulesService.Preview(set, Array.Empty<FirewallRule>()));
        Assert.False(r.Success);
        Assert.Null(svc.AppliedVersion);
    }
}
