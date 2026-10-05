using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Validation;

namespace SecureWall.Tests;

public class RuleValidationTests
{
    static FirewallRuleSpec Valid() => new()
    {
        Name = "SecureWall - Test", Program = @"C:\Windows\System32\notepad.exe", Protocol = FirewallProtocol.Tcp,
        RemotePorts = "80,443", RemoteAddresses = "10.0.0.0/8", Profiles = FirewallProfiles.All,
    };

    [Fact]
    public void ValidRulePasses() => Assert.Empty(RuleValidator.Validate(Valid()));

    [Theory]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("Règle normale", true)]
    [InlineData("a|b", false)]
    [InlineData("tab\there", false)]
    public void NameValidation(string name, bool ok) => Assert.Equal(ok, RuleValidator.IsSafeName(name));

    [Fact]
    public void NameTooLongIsRejected() => Assert.False(RuleValidator.IsSafeName(new string('a', 201)));

    [Theory]
    [InlineData("", true)]
    [InlineData("*", true)]
    [InlineData("80", true)]
    [InlineData("80, 443", true)]
    [InlineData("8000-8100", true)]
    [InlineData("1-65535", true)]
    [InlineData("0", false)]
    [InlineData("65536", false)]
    [InlineData("abc", false)]
    [InlineData("100-50", false)]
    [InlineData("80;443", false)]
    [InlineData("80,", false)]
    public void PortList(string ports, bool ok) => Assert.Equal(ok, RuleValidator.IsValidPortList(ports));

    [Theory]
    [InlineData("", true)]
    [InlineData("192.168.1.10", true)]
    [InlineData("10.0.0.0/8", true)]
    [InlineData("10.0.0.0/33", false)]
    [InlineData("10.0.0.0/255.0.0.0", true)]
    [InlineData("1.2.3.4-1.2.3.9", true)]
    [InlineData("1.2.3.4-::1", false)]
    [InlineData("::1", true)]
    [InlineData("fe80::/10", true)]
    [InlineData("Internet", true)]
    [InlineData("Any", false)]
    [InlineData("Intranet", false)]
    [InlineData("*", true)]
    [InlineData("LocalSubnet,DNS", true)]
    [InlineData("999.1.1.1", false)]
    [InlineData("1.2", false)]
    [InlineData("pas une ip", false)]
    public void AddressList(string addresses, bool ok) => Assert.Equal(ok, RuleValidator.IsValidAddressList(addresses));

    [Theory]
    [InlineData(@"C:\Windows\notepad.exe", true)]
    [InlineData(@"notepad.exe", false)]
    [InlineData(@"C:\a*.exe", false)]
    [InlineData(@"\\serveur\partage\x.exe", false)]
    [InlineData(@"C:\a|b.exe", false)]
    public void ProgramPath(string path, bool ok) => Assert.Equal(ok, RuleValidator.IsValidProgramPath(path));

    [Fact]
    public void PortsRefusedForNonTcpUdpProtocols()
    {
        var s = Valid(); s.Protocol = FirewallProtocol.Any;
        Assert.Contains(RuleValidator.Validate(s), e => e.Contains("ports", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ProfilesCannotBeEmpty()
    {
        var s = Valid(); s.Profiles = FirewallProfiles.None;
        Assert.NotEmpty(RuleValidator.Validate(s));
    }

    [Fact]
    public void UndefinedEnumValuesAreRejected()
    {
        var s = Valid(); s.Action = (FirewallAction)42;
        Assert.NotEmpty(RuleValidator.Validate(s));
    }

    [Fact]
    public void TooManyListItemsRejected()
    {
        var ports = string.Join(",", Enumerable.Range(1, 101));
        Assert.False(RuleValidator.IsValidPortList(ports));
    }
}
