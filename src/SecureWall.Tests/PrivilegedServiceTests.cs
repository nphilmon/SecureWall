using System.Text.Json;
using System.Text.Json.Serialization;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Models;
using SecureWall.Infrastructure.Windows;
using SecureWall.PrivilegedService;
using SecureWall.PrivilegedService.Firewall;
using SecureWall.Security.Firewall;

namespace SecureWall.Tests;

/// <summary>Sécurité du service privilégié : liste blanche, validation stricte, aucune commande arbitraire. Tout est simulé.</summary>
public class PrivilegedServiceTests
{
    static readonly JsonSerializerOptions Json = new() { Converters = { new JsonStringEnumConverter() } };

    static PipeRequest Req(PrivilegedOperation op, params (string, string)[] args) =>
        new() { Operation = op, Args = args.ToDictionary(a => a.Item1, a => a.Item2) };

    static string Spec(Action<FirewallRuleSpec>? tweak = null)
    {
        var s = new FirewallRuleSpec { Name = "SecureWall - Test", Action = FirewallAction.Block, Direction = FirewallDirection.Outbound };
        tweak?.Invoke(s);
        return JsonSerializer.Serialize(s, Json);
    }

    // ----- Enveloppe -----
    [Fact]
    public void UnknownOperation_IsRejected() =>
        Assert.NotNull(RequestDispatcher.ValidateEnvelope(new PipeRequest { Operation = (PrivilegedOperation)9999 }));

    [Fact]
    public void ExtraOrUnexpectedArguments_AreRejected()
    {
        Assert.NotNull(RequestDispatcher.ValidateEnvelope(Req(PrivilegedOperation.Ping, ("cmd", "calc.exe"))));
        Assert.NotNull(RequestDispatcher.ValidateEnvelope(Req(PrivilegedOperation.FirewallDeleteRule, ("name", "x"), ("path", @"C:\Windows\x"))));
        Assert.NotNull(RequestDispatcher.ValidateEnvelope(Req(PrivilegedOperation.FirewallDeleteRule, ("filename", "x"))));
    }

    [Fact]
    public void OversizedArgumentsAndWrongVersion_AreRejected()
    {
        Assert.NotNull(RequestDispatcher.ValidateEnvelope(Req(PrivilegedOperation.FirewallDeleteRule, ("name", new string('a', 9000)))));
        var r = Req(PrivilegedOperation.Ping); r.Version = 99;
        Assert.NotNull(RequestDispatcher.ValidateEnvelope(r));
        r = Req(PrivilegedOperation.Ping); r.Id = "";
        Assert.NotNull(RequestDispatcher.ValidateEnvelope(r));
    }

    [Fact]
    public void WellFormedRequests_AreAccepted()
    {
        Assert.Null(RequestDispatcher.ValidateEnvelope(Req(PrivilegedOperation.Ping)));
        Assert.Null(RequestDispatcher.ValidateEnvelope(Req(PrivilegedOperation.FirewallSetRuleEnabled, ("name", "R"), ("enabled", "1"))));
    }

    [Fact]
    public void EveryDefinedOperationIsWhitelistedExplicitly()
    {
        foreach (var op in Enum.GetValues<PrivilegedOperation>())
            Assert.True(RequestDispatcher.IsKnownOperation(op), $"{op} n'a pas de définition d'arguments dans la liste blanche");
    }

    [Fact]
    public void ThereIsNoOperationThatAcceptsACommandOrScript()
    {
        foreach (var op in Enum.GetValues<PrivilegedOperation>())
        {
            var name = op.ToString();
            Assert.DoesNotContain("Exec", name); Assert.DoesNotContain("Command", name); Assert.DoesNotContain("Script", name); Assert.DoesNotContain("Shell", name);
        }
    }

    // ----- Gestionnaire pare-feu -----
    (FirewallHandler h, FakeFirewallPolicy p, FakeFirewallBackup b) Handler()
    {
        var p = new FakeFirewallPolicy(); var b = new FakeFirewallBackup();
        return (new FirewallHandler(p, b, new EmergencyExecutor(p, b, Path.Combine(Path.GetTempPath(), "sw-h-" + Guid.NewGuid().ToString("N") + ".json"))), p, b);
    }

    [Theory]
    [InlineData("15", true)]
    [InlineData("abc", false)]
    [InlineData("-1", false)]
    [InlineData("0", false)]
    [InlineData("1441", false)]
    [InlineData("1,5", false)]
    public async Task EmergencyCutoff_ValidatesTheAutoRestoreDuration(string minutes, bool ok)
    {
        var (h, p, _) = Handler();
        var r = await h.HandleAsync(Req(PrivilegedOperation.EmergencyCutoff, ("minutes", minutes)), default);
        Assert.Equal(ok, r.Success);
        Assert.Equal(ok ? 2 : 0, p.Rules.Count);
    }

    [Fact]
    public void EmergencyCutoff_AcceptsOnlyTheMinutesArgument()
    {
        Assert.Null(RequestDispatcher.ValidateEnvelope(Req(PrivilegedOperation.EmergencyCutoff, ("minutes", "5"))));
        Assert.Null(RequestDispatcher.ValidateEnvelope(Req(PrivilegedOperation.EmergencyCutoff)));
        Assert.NotNull(RequestDispatcher.ValidateEnvelope(Req(PrivilegedOperation.EmergencyCutoff, ("program", "cmd.exe"))));
    }

    [Fact]
    public async Task Create_ValidatesSpec_BacksUpFirst_AndUsesSecureWallGroup()
    {
        var (h, p, b) = Handler();
        var r = await h.HandleAsync(Req(PrivilegedOperation.FirewallCreateRule, ("spec", Spec())), default);
        Assert.True(r.Success, r.Message);
        Assert.Equal(1, b.BackupCount);
        Assert.Equal(RuleGroups.SecureWall, p.Rules.Single().Group);
    }

    [Theory]
    [InlineData("pas du json")]
    [InlineData("")]
    public async Task Create_RejectsGarbageSpec(string spec)
    {
        var (h, p, b) = Handler();
        var r = await h.HandleAsync(Req(PrivilegedOperation.FirewallCreateRule, ("spec", spec)), default);
        Assert.False(r.Success);
        Assert.Empty(p.Calls); Assert.Equal(0, b.BackupCount);
    }

    [Fact]
    public async Task Create_RejectsInvalidPortsProgramAndMissingExecutable()
    {
        var (h, p, _) = Handler();
        Assert.False((await h.HandleAsync(Req(PrivilegedOperation.FirewallCreateRule, ("spec", Spec(s => { s.Protocol = FirewallProtocol.Tcp; s.RemotePorts = "99999"; }))), default)).Success);
        Assert.False((await h.HandleAsync(Req(PrivilegedOperation.FirewallCreateRule, ("spec", Spec(s => s.Program = "calc.exe"))), default)).Success);
        var r = await h.HandleAsync(Req(PrivilegedOperation.FirewallCreateRule, ("spec", Spec(s => s.Program = @"C:\n'existe\pas\x.exe"))), default);
        Assert.False(r.Success);
        Assert.Contains("n'existe pas", r.Message);
        Assert.Empty(p.Calls);
    }

    [Fact]
    public async Task Create_RefusesReservedEmergencyNamesAndDuplicates()
    {
        var (h, p, _) = Handler();
        Assert.False((await h.HandleAsync(Req(PrivilegedOperation.FirewallCreateRule, ("spec", Spec(s => s.Name = "SecureWall Emergency - piège"))), default)).Success);
        p.Rules.Add(new FirewallRule { Name = "SecureWall - Test" });
        Assert.False((await h.HandleAsync(Req(PrivilegedOperation.FirewallCreateRule, ("spec", Spec())), default)).Success);
    }

    [Fact]
    public async Task EmergencyRules_CannotBeModifiedDeletedOrDisabledThroughRuleOperations()
    {
        var (h, p, _) = Handler();
        p.Rules.Add(new FirewallRule { Name = "Règle urgence", Group = RuleGroups.Emergency });
        Assert.False((await h.HandleAsync(Req(PrivilegedOperation.FirewallDeleteRule, ("name", "Règle urgence")), default)).Success);
        Assert.False((await h.HandleAsync(Req(PrivilegedOperation.FirewallSetRuleEnabled, ("name", "Règle urgence"), ("enabled", "0")), default)).Success);
        Assert.False((await h.HandleAsync(Req(PrivilegedOperation.FirewallUpdateRule, ("name", "Règle urgence"), ("spec", Spec())), default)).Success);
        Assert.Single(p.Rules);
    }

    [Fact]
    public async Task DuplicateNamedRules_AreNeverTargeted()
    {
        var (h, p, _) = Handler();
        p.Rules.Add(new FirewallRule { Name = "Doublon" }); p.Rules.Add(new FirewallRule { Name = "Doublon" });
        var r = await h.HandleAsync(Req(PrivilegedOperation.FirewallDeleteRule, ("name", "Doublon")), default);
        Assert.False(r.Success);
        Assert.Equal(2, p.Rules.Count);
    }

    [Fact]
    public async Task Delete_BacksUpBeforeRemoving_AndMissingRuleIsReported()
    {
        var (h, p, b) = Handler();
        p.Rules.Add(new FirewallRule { Name = "A supprimer", Group = RuleGroups.SecureWall });
        Assert.True((await h.HandleAsync(Req(PrivilegedOperation.FirewallDeleteRule, ("name", "A supprimer")), default)).Success);
        Assert.Equal(1, b.BackupCount);
        Assert.Empty(p.Rules);
        Assert.False((await h.HandleAsync(Req(PrivilegedOperation.FirewallDeleteRule, ("name", "Absente")), default)).Success);
    }

    [Fact]
    public async Task BackupFailure_AbortsModification()
    {
        var (h, p, b) = Handler();
        b.Fail = true;
        var r = await h.HandleAsync(Req(PrivilegedOperation.FirewallCreateRule, ("spec", Spec())), default);
        Assert.False(r.Success);
        Assert.Empty(p.Rules);
    }

    [Theory]
    [InlineData("3")]
    [InlineData("8")]
    [InlineData("0")]
    [InlineData("abc")]
    public async Task ProfileOperation_RejectsInvalidProfiles(string profile)
    {
        var (h, p, _) = Handler();
        Assert.False((await h.HandleAsync(Req(PrivilegedOperation.FirewallSetProfileEnabled, ("profile", profile), ("enabled", "0")), default)).Success);
        Assert.Empty(p.Calls);
    }

    [Fact]
    public async Task ProfileOperation_RejectsInvalidBoolean()
    {
        var (h, p, _) = Handler();
        Assert.False((await h.HandleAsync(Req(PrivilegedOperation.FirewallSetProfileEnabled, ("profile", "4"), ("enabled", "peut-être")), default)).Success);
        Assert.True((await h.HandleAsync(Req(PrivilegedOperation.FirewallSetProfileEnabled, ("profile", "4"), ("enabled", "0")), default)).Success);
        Assert.Contains("profile:Public:False", p.Calls);
    }

    [Theory]
    [InlineData("../../Windows/system.wfw")]
    [InlineData(@"C:\Windows\x.wfw")]
    [InlineData("fw-20260101-000000.wfw; calc")]
    [InlineData("")]
    public void BackupNames_AreStrictlyValidated(string name) => Assert.False(FirewallBackupManager.IsValidBackupName(name));

    [Fact]
    public void LegitimateBackupNamesAreAccepted()
    {
        Assert.True(FirewallBackupManager.IsValidBackupName("fw-20260101-235959.wfw"));
        Assert.True(FirewallBackupManager.IsValidBackupName("fw-20260101-235959-urgence.wfw"));
    }

    [Fact]
    public async Task RestoreBackup_WithInvalidNameNeverReachesTheBackupManager()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sw-bk-" + Guid.NewGuid().ToString("N"));
        var mgr = new FirewallBackupManager(dir);
        var r = await mgr.RestoreAsync(@"..\..\evil.wfw");
        Assert.False(r.Ok);
        Assert.False(Directory.Exists(dir));
    }

    // ----- Trames -----
    [Fact]
    public async Task Framing_RoundTripsRequestsAndResponses()
    {
        using var ms = new MemoryStream();
        var req = Req(PrivilegedOperation.FirewallSetRuleEnabled, ("name", "Règle é"), ("enabled", "1"));
        await PipeFraming.WriteAsync(ms, req, default);
        ms.Position = 0;
        var back = await PipeFraming.ReadAsync<PipeRequest>(ms, default);
        Assert.Equal(req.Id, back!.Id);
        Assert.Equal(PrivilegedOperation.FirewallSetRuleEnabled, back.Operation);
        Assert.Equal("Règle é", back.Args["name"]);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(PipeFraming.MaxFrameBytes + 1)]
    public async Task Framing_RejectsInvalidLengths(int length)
    {
        using var ms = new MemoryStream(BitConverter.GetBytes(length));
        await Assert.ThrowsAsync<InvalidDataException>(() => PipeFraming.ReadAsync<PipeRequest>(ms, default));
    }

    [Fact]
    public async Task Framing_TruncatedPayloadFailsCleanly()
    {
        using var ms = new MemoryStream(BitConverter.GetBytes(100).Concat(new byte[] { 1, 2, 3 }).ToArray());
        await Assert.ThrowsAsync<EndOfStreamException>(() => PipeFraming.ReadAsync<PipeRequest>(ms, default));
    }

    [Fact]
    public async Task Framing_MalformedJsonThrowsJsonException()
    {
        var payload = System.Text.Encoding.UTF8.GetBytes("{ ceci n'est pas du json");
        using var ms = new MemoryStream(BitConverter.GetBytes(payload.Length).Concat(payload).ToArray());
        await Assert.ThrowsAnyAsync<JsonException>(() => PipeFraming.ReadAsync<PipeRequest>(ms, default));
    }
}
