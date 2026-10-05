using System.Text.Json;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Models;
using SecureWall.Security.Firewall;

namespace SecureWall.Tests;

public class FirewallServiceTests
{
    [Fact]
    public async Task ActiveProfileProtected_WhenCurrentProfileEnabled()
    {
        var policy = new FakeFirewallPolicy();
        var svc = new FirewallService(policy, new FakePrivilegedClient(), new FakeAudit());
        Assert.True(await svc.IsActiveProfileProtectedAsync());
    }

    [Fact]
    public async Task ActiveProfileNotProtected_WhenCurrentProfileDisabled()
    {
        var policy = new FakeFirewallPolicy();
        policy.SetProfileEnabled(FirewallProfiles.Public, false);
        var svc = new FirewallService(policy, new FakePrivilegedClient(), new FakeAudit());
        Assert.False(await svc.IsActiveProfileProtectedAsync());
    }

    [Fact]
    public async Task OtherProfileDisabled_DoesNotAffectActiveStatus()
    {
        var policy = new FakeFirewallPolicy();
        policy.SetProfileEnabled(FirewallProfiles.Domain, false);
        var svc = new FirewallService(policy, new FakePrivilegedClient(), new FakeAudit());
        Assert.True(await svc.IsActiveProfileProtectedAsync());
    }

    [Fact]
    public async Task SetProfileEnabled_SendsWhitelistedOperationAndAudits()
    {
        var client = new FakePrivilegedClient(); var audit = new FakeAudit();
        var svc = new FirewallService(new FakeFirewallPolicy(), client, audit);

        var r = await svc.SetProfileEnabledAsync(FirewallProfiles.Public, false);

        Assert.True(r.Success);
        var (op, args) = Assert.Single(client.Requests);
        Assert.Equal(PrivilegedOperation.FirewallSetProfileEnabled, op);
        Assert.Equal("4", args["profile"]);
        Assert.Equal("0", args["enabled"]);
        Assert.Contains(audit.Entries, e => e.Action.Contains("profil", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ServiceUnavailable_ReturnsReadableError()
    {
        var client = new FakePrivilegedClient { Available = false };
        var svc = new FirewallService(new FakeFirewallPolicy(), client, new FakeAudit());
        var r = await svc.SetProfileEnabledAsync(FirewallProfiles.Public, true);
        Assert.False(r.Success);
        Assert.Contains("service", r.Message, StringComparison.OrdinalIgnoreCase);
    }
}

public class FirewallRuleServiceTests
{
    static FirewallRuleService Make(FakeFirewallPolicy p, FakePrivilegedClient c, FakeAudit a) => new(p, c, a);

    [Fact]
    public async Task InvalidRule_IsRejectedBeforeAnyPrivilegedCall()
    {
        var client = new FakePrivilegedClient();
        var svc = Make(new FakeFirewallPolicy(), client, new FakeAudit());
        var r = await svc.CreateRuleAsync(new FirewallRuleSpec { Name = "", Protocol = FirewallProtocol.Tcp, RemotePorts = "99999" });
        Assert.False(r.Success);
        Assert.Empty(client.Requests);
    }

    [Fact]
    public async Task CreateRule_SendsSerializedSpecAndAudits()
    {
        var client = new FakePrivilegedClient(); var audit = new FakeAudit();
        var svc = Make(new FakeFirewallPolicy(), client, audit);
        var spec = new FirewallRuleSpec { Name = "Test 1", Action = FirewallAction.Block, Direction = FirewallDirection.Outbound };

        var r = await svc.CreateRuleAsync(spec);

        Assert.True(r.Success);
        var (op, args) = Assert.Single(client.Requests);
        Assert.Equal(PrivilegedOperation.FirewallCreateRule, op);
        Assert.Contains("Test 1", args["spec"]);
        Assert.Contains(audit.Entries, e => e.Action.Contains("Création"));
    }

    [Fact]
    public async Task DeleteAndToggle_UseDedicatedOperations()
    {
        var client = new FakePrivilegedClient();
        var svc = Make(new FakeFirewallPolicy(), client, new FakeAudit());
        await svc.DeleteRuleAsync("R1");
        await svc.SetRuleEnabledAsync("R1", true);
        Assert.Equal(PrivilegedOperation.FirewallDeleteRule, client.Requests[0].Op);
        Assert.Equal(PrivilegedOperation.FirewallSetRuleEnabled, client.Requests[1].Op);
        Assert.Equal("1", client.Requests[1].Args["enabled"]);
    }

    [Fact]
    public async Task Duplicate_AddsCopySuffixAndKeepsSettings()
    {
        var policy = new FakeFirewallPolicy();
        var rule = new FirewallRule { Name = "Ma règle", Action = FirewallAction.Allow, Direction = FirewallDirection.Inbound, ProtocolNumber = 6, RemotePorts = "443", ProfilesMask = 7 };
        policy.Rules.Add(rule);
        var client = new FakePrivilegedClient();
        var svc = Make(policy, client, new FakeAudit());
        await svc.GetRulesAsync();

        var r = await svc.DuplicateRuleAsync(rule);

        Assert.True(r.Success);
        var spec = JsonSerializer.Deserialize<FirewallRuleSpec>(client.Requests.Single().Args["spec"], new JsonSerializerOptions { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } })!;
        Assert.Equal("Ma règle (copie)", spec.Name);
        Assert.Equal(FirewallAction.Allow, spec.Action);
        Assert.Equal("443", spec.RemotePorts);
    }

    [Fact]
    public async Task ExportThenImport_RoundTripsAndSkipsExistingNames()
    {
        var policy = new FakeFirewallPolicy();
        policy.Rules.Add(new FirewallRule { Name = "SecureWall - A", Group = RuleGroups.SecureWall, Action = FirewallAction.Block, Direction = FirewallDirection.Outbound, ProfilesMask = 7 });
        policy.Rules.Add(new FirewallRule { Name = "Règle Windows", Group = "Autre", ProfilesMask = 7 });
        var client = new FakePrivilegedClient();
        var svc = Make(policy, client, new FakeAudit());

        var json = await svc.ExportRulesJsonAsync(onlySecureWall: true);
        Assert.Contains("SecureWall - A", json);
        Assert.DoesNotContain("Règle Windows", json);

        // Import dans une politique vide : la règle est créée.
        var emptyClient = new FakePrivilegedClient();
        var svc2 = Make(new FakeFirewallPolicy(), emptyClient, new FakeAudit());
        var r = await svc2.ImportRulesJsonAsync(json);
        Assert.True(r.Success);
        Assert.Equal(PrivilegedOperation.FirewallCreateRule, emptyClient.Requests.Single().Op);

        // Import dans la politique d'origine : nom déjà présent, rien n'est créé.
        var r2 = await svc.ImportRulesJsonAsync(json);
        Assert.Empty(client.Requests);
        Assert.Contains("ignorée", r2.Message);
    }

    [Fact]
    public async Task Import_RejectsGarbageAndInvalidRules()
    {
        var svc = Make(new FakeFirewallPolicy(), new FakePrivilegedClient(), new FakeAudit());
        Assert.False((await svc.ImportRulesJsonAsync("pas du json")).Success);
        Assert.False((await svc.ImportRulesJsonAsync("{\"Format\":\"x\"}")).Success);
        var bad = "{\"Rules\":[{\"Name\":\"X\",\"Program\":\"relatif.exe\"}]}";
        var r = await svc.ImportRulesJsonAsync(bad);
        Assert.False(r.Success);
    }

    [Fact]
    public void RulesForProgram_MatchesCaseInsensitively()
    {
        var rules = new[] { new FirewallRule { Name = "a", Program = @"C:\App\X.exe" }, new FirewallRule { Name = "b", Program = @"C:\Autre.exe" } };
        Assert.Single(FirewallRuleService.RulesForProgram(rules, @"c:\app\x.EXE"));
        Assert.Empty(FirewallRuleService.RulesForProgram(rules, ""));
    }
}

public class EmergencyModeTests
{
    [Fact]
    public async Task Cutoff_CreatesTwoBlockRulesAndRestoreRemovesThem()
    {
        var policy = new FakeFirewallPolicy(); var backup = new FakeFirewallBackup();
        var state = Path.Combine(Path.GetTempPath(), "sw-emergency-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var exec = new EmergencyExecutor(policy, backup, state);
            var r = await exec.CutoffAsync(CancellationToken.None);

            Assert.True(r.Ok);
            Assert.Equal(1, backup.BackupCount);                              // sauvegarde avant modification
            Assert.True(exec.GetState().Active);
            Assert.Equal(2, policy.Rules.Count(x => x.Group == RuleGroups.Emergency && x.Action == FirewallAction.Block));
            Assert.All(policy.Rules, x => Assert.Equal("Internet", x.RemoteAddresses));

            exec.Restore();
            Assert.False(exec.GetState().Active);
            Assert.Empty(policy.Rules);
            Assert.False(File.Exists(state));
        }
        finally { if (File.Exists(state)) File.Delete(state); }
    }

    [Fact]
    public async Task Cutoff_IsRefusedWhenActiveProfileHasFirewallDisabled()
    {
        var policy = new FakeFirewallPolicy();
        policy.SetProfileEnabled(FirewallProfiles.Public, false);
        var exec = new EmergencyExecutor(policy, new FakeFirewallBackup(), Path.Combine(Path.GetTempPath(), "sw-e2.json"));
        var r = await exec.CutoffAsync(CancellationToken.None);
        Assert.False(r.Ok);
        Assert.Empty(policy.Rules);
    }

    [Fact]
    public async Task Cutoff_AbortsWhenBackupFails()
    {
        var policy = new FakeFirewallPolicy();
        var exec = new EmergencyExecutor(policy, new FakeFirewallBackup { Fail = true }, Path.Combine(Path.GetTempPath(), "sw-e3.json"));
        var r = await exec.CutoffAsync(CancellationToken.None);
        Assert.False(r.Ok);
        Assert.Empty(policy.Rules);
    }

    static EmergencyExecutor Exec(FakeFirewallPolicy policy, out string state, FakeFirewallBackup? backup = null)
    {
        state = Path.Combine(Path.GetTempPath(), "sw-emergency-" + Guid.NewGuid().ToString("N") + ".json");
        return new EmergencyExecutor(policy, backup ?? new FakeFirewallBackup(), state);
    }

    [Fact]
    public async Task Cutoff_RollsBackFirstRuleWhenSecondOneFails()
    {
        var policy = new FakeFirewallPolicy { FailAddFor = EmergencyExecutor.InName };
        var exec = Exec(policy, out var state);
        var r = await exec.CutoffAsync(CancellationToken.None);

        Assert.False(r.Ok);
        Assert.Contains("aucune modification", r.Message);
        Assert.Empty(policy.Rules);                       // jamais une seule règle laissée en place
        Assert.False(File.Exists(state));
        Assert.False(exec.GetState().Active);
    }

    [Fact]
    public async Task Cutoff_CleansLeftoverRuleFromInterruptedAttempt()
    {
        var policy = new FakeFirewallPolicy();
        policy.Rules.Add(new FirewallRule { Name = EmergencyExecutor.OutName, Group = RuleGroups.Emergency });
        var exec = Exec(policy, out var state);
        try
        {
            var r = await exec.CutoffAsync(CancellationToken.None);
            Assert.True(r.Ok);
            Assert.Equal(2, policy.Rules.Count);
        }
        finally { if (File.Exists(state)) File.Delete(state); }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(EmergencyExecutor.MaxAutoRestoreMinutes + 1)]
    public async Task Cutoff_RejectsInvalidAutoRestoreDuration(int minutes)
    {
        var policy = new FakeFirewallPolicy();
        var exec = Exec(policy, out _);
        var r = await exec.CutoffAsync(CancellationToken.None, minutes);
        Assert.False(r.Ok);
        Assert.Empty(policy.Rules);
    }

    [Fact]
    public async Task AutoRestore_RestoresOnlyOnceTheDelayHasElapsed()
    {
        var policy = new FakeFirewallPolicy();
        var exec = Exec(policy, out var state);
        try
        {
            var r = await exec.CutoffAsync(CancellationToken.None, 15);
            Assert.True(r.Ok);
            var s = exec.GetState();
            Assert.True(s.Active);
            Assert.NotNull(s.AutoRestoreAt);
            Assert.InRange((s.AutoRestoreAt!.Value - s.Since!.Value).TotalMinutes, 14.99, 15.01);

            Assert.False(exec.RestoreIfExpired(DateTime.Now.AddMinutes(14)));   // trop tôt
            Assert.True(exec.GetState().Active);

            Assert.True(exec.RestoreIfExpired(DateTime.Now.AddMinutes(16)));    // délai écoulé
            Assert.False(exec.GetState().Active);
            Assert.Empty(policy.Rules);
            Assert.False(File.Exists(state));
        }
        finally { if (File.Exists(state)) File.Delete(state); }
    }

    [Fact]
    public async Task ManualCutoff_NeverAutoRestores()
    {
        var policy = new FakeFirewallPolicy();
        var exec = Exec(policy, out var state);
        try
        {
            await exec.CutoffAsync(CancellationToken.None);
            Assert.Null(exec.GetState().AutoRestoreAt);
            Assert.False(exec.RestoreIfExpired(DateTime.Now.AddYears(1)));
            Assert.True(exec.GetState().Active);
        }
        finally { if (File.Exists(state)) File.Delete(state); }
    }

    [Fact]
    public void RestoreIfExpired_DoesNothingWhenInactive()
    {
        var exec = Exec(new FakeFirewallPolicy(), out _);
        Assert.False(exec.RestoreIfExpired());
    }

    [Fact]
    public async Task Restore_NeverRemovesForeignRules()
    {
        var policy = new FakeFirewallPolicy();
        policy.Rules.Add(new FirewallRule { Name = EmergencyExecutor.OutName, Group = "Autre groupe" });
        var exec = new EmergencyExecutor(policy, new FakeFirewallBackup(), Path.Combine(Path.GetTempPath(), "sw-e4.json"));
        exec.Restore();
        Assert.Single(policy.Rules);
        await Task.CompletedTask;
    }
}
