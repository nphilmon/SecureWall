using SecureWall.Core.Logic;
using Xunit;

namespace SecureWall.Tests;

public class EmergencyTextTests
{
    [Theory]
    [InlineData(-5, "quelques secondes")]
    [InlineData(30, "moins d'une minute")]
    [InlineData(60, "1 min")]
    [InlineData(61, "2 min")]
    [InlineData(14 * 60 + 10, "15 min")]
    [InlineData(3600, "1 h")]
    [InlineData(3600 + 600, "1 h 10")]
    [InlineData(4 * 3600, "4 h")]
    public void Duration(int seconds, string expected) => Assert.Equal(expected, EmergencyText.Duration(TimeSpan.FromSeconds(seconds)));

    [Fact]
    public void Badge_ReflectsStateAndCountdown()
    {
        var now = new DateTime(2026, 10, 5, 12, 0, 0);
        Assert.Equal("", EmergencyText.Badge(false, now.AddMinutes(5), now));
        Assert.Equal("Mode urgence : Internet coupé", EmergencyText.Badge(true, null, now));
        Assert.Equal("Mode urgence : Internet coupé · rétabli dans 5 min", EmergencyText.Badge(true, now.AddMinutes(5), now));
    }

    [Fact]
    public void Options_StartWithManualAndAreIncreasing()
    {
        var o = EmergencyText.AutoRestoreOptions;
        Assert.Equal(0, o[0].Minutes);
        Assert.True(o.Skip(1).Select(x => x.Minutes).SequenceEqual(o.Skip(1).Select(x => x.Minutes).OrderBy(m => m)));
        Assert.All(o, x => Assert.InRange(x.Minutes, 0, 24 * 60));
    }
}
