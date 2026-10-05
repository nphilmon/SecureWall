using SecureWall.Core.Models;
using Xunit;

namespace SecureWall.Tests;

public class BlockedConnectionInsightsTests
{
    [Theory]
    [InlineData(443, "443 · HTTPS")]
    [InlineData(445, "445 · SMB (partages Windows)")]
    [InlineData(54321, "54321")]
    [InlineData(0, "—")]
    public void PortText(int port, string expected) => Assert.Equal(expected, BlockedConnectionInsights.PortText(port));

    [Theory]
    [InlineData("8.8.8.8", "Internet")]
    [InlineData("192.168.1.20", "Réseau local (privée)")]
    [InlineData("10.1.2.3", "Réseau local (privée)")]
    [InlineData("172.20.0.1", "Réseau local (privée)")]
    [InlineData("172.32.0.1", "Internet")]
    [InlineData("100.64.0.1", "Réseau d'opérateur (CGNAT)")]
    [InlineData("169.254.10.10", "Liaison locale (sans DHCP)")]
    [InlineData("224.0.0.251", "Multicast (diffusion groupée)")]
    [InlineData("255.255.255.255", "Diffusion locale")]
    [InlineData("127.0.0.1", "Cet ordinateur (boucle locale)")]
    [InlineData("::1", "Cet ordinateur (boucle locale)")]
    [InlineData("fe80::1", "Liaison locale")]
    [InlineData("ff02::fb", "Multicast (diffusion groupée)")]
    [InlineData("fd12:3456::1", "Réseau local (privée)")]
    [InlineData("2606:4700::1111", "Internet")]
    [InlineData("n'importe quoi", "Inconnue")]
    [InlineData("", "Inconnue")]
    public void AddressKind(string address, string expected) => Assert.Equal(expected, BlockedConnectionInsights.AddressKind(address));

    [Fact]
    public void Explain_DescribesDirection()
    {
        var o = BlockedConnectionInsights.Explain("chrome.exe", "Sortante", "TCP", "1.2.3.4", 443);
        Assert.Contains("sortante", o);
        Assert.Contains("chrome.exe", o);
        Assert.Contains("HTTPS", o);
        var i = BlockedConnectionInsights.Explain("", "Entrante", "TCP", "9.9.9.9", 3389);
        Assert.Contains("entrante", i);
        Assert.Contains("Un programme ou service système", i);
    }
}
