using SecureWall.Core.Enums;
using SecureWall.Core.Models;
using Xunit;

namespace SecureWall.Tests;

public class ReleaseNotesTests
{
    static readonly string[] Categories = { ReleaseNotes.New, ReleaseNotes.Improved, ReleaseNotes.Fixed, ReleaseNotes.Security };

    [Fact]
    public void TheShippedVersionHasNotes()
    {
        // La version publiée (src\Directory.Build.props) doit toujours avoir ses nouveautés : sinon la page Nouveautés resterait vide.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "src", "Directory.Build.props"))) dir = dir.Parent;
        Assert.NotNull(dir);
        var props = File.ReadAllText(Path.Combine(dir!.FullName, "src", "Directory.Build.props"));
        var version = System.Text.RegularExpressions.Regex.Match(props, @"<Version>(\d+\.\d+\.\d+)</Version>").Groups[1].Value;
        Assert.NotEqual("", version);
        Assert.NotNull(ReleaseNotes.For(version));
        Assert.Equal(version, ReleaseNotes.All[0].Version);          // la plus récente est en premier
    }

    [Fact]
    public void VersionsAreUniqueAndSortedFromNewestToOldest()
    {
        var versions = ReleaseNotes.All.Select(e => Version.Parse(e.Version)).ToList();
        Assert.Equal(versions.Count, versions.Distinct().Count());
        Assert.True(versions.SequenceEqual(versions.OrderByDescending(v => v)));
    }

    [Fact]
    public void EveryEntryAndFeatureIsFilledIn()
    {
        foreach (var e in ReleaseNotes.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(e.Date)); Assert.False(string.IsNullOrWhiteSpace(e.Title));
            Assert.NotEmpty(e.Features);
            foreach (var f in e.Features)
            {
                Assert.Contains(f.Category, Categories);
                Assert.False(string.IsNullOrWhiteSpace(f.Title));
                Assert.True(f.Description.Length >= 30, $"Description trop courte : {f.Title}");
                if (f.Page != null) Assert.False(string.IsNullOrWhiteSpace(f.PageLabel), $"Bouton sans libellé : {f.Title}");
                else Assert.Null(f.PageLabel);
            }
        }
    }

    [Fact]
    public void LinkedPagesExist_AndTheNewPagesAreAdvertised()
    {
        foreach (var f in ReleaseNotes.All.SelectMany(e => e.Features).Where(f => f.Page != null))
            Assert.True(Enum.IsDefined(f.Page!.Value));
        var current = ReleaseNotes.All[0].Features.Where(f => f.Page != null).Select(f => f.Page!.Value).ToList();
        Assert.Contains(AppPage.Map, current);
        Assert.Contains(AppPage.Dns, current);
    }

    [Theory]
    [InlineData("", "2.0.1", true)]
    [InlineData(null, "2.0.1", true)]
    [InlineData("1.0.0", "2.0.1", true)]
    [InlineData("2.0.1", "2.0.1", false)]
    [InlineData("", "9.9.9", false)]          // version sans notes : on n'ouvre pas une page vide
    [InlineData("2.0.1", "1.0.0", true)]      // retour à une version plus ancienne : changement de version quand même
    public void ShouldShow(string? lastSeen, string current, bool expected) => Assert.Equal(expected, ReleaseNotes.ShouldShow(lastSeen, current));
}
