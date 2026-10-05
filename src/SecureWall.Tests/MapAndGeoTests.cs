using SecureWall.Core.Logic;
using SecureWall.Core.Models;
using SecureWall.Infrastructure.Configuration;
using SecureWall.Security.Network;
using Xunit;

namespace SecureWall.Tests;

public class CountryTrafficTests
{
    static RemoteTraffic T(string ip, int port, string app, int n) => new(ip, port, app, n, DateTime.Now);
    static readonly Dictionary<string, string> Geo = new(StringComparer.OrdinalIgnoreCase)
    {
        ["8.8.8.8"] = "US", ["1.2.3.4"] = "US", ["5.6.7.8"] = "FR", ["9.9.9.9"] = "",
    };

    [Fact]
    public void GroupsByCountry_SeparatesLocalAndUnknown_AndSortsByConnections()
    {
        var rows = new[]
        {
            T("8.8.8.8", 443, "chrome.exe", 10), T("1.2.3.4", 443, "chrome.exe", 5), T("1.2.3.4", 80, "edge.exe", 2),
            T("5.6.7.8", 443, "chrome.exe", 20),
            T("192.168.1.10", 445, "system", 3), T("127.0.0.1", 5000, "dev.exe", 1), T("224.0.0.251", 5353, "svc", 1),
            T("9.9.9.9", 443, "a.exe", 4), T("203.0.113.5", 443, "a.exe", 1),   // pays vide / adresse jamais localisée
        };
        var stats = CountryTraffic.Build(rows, Geo, c => c);

        Assert.Equal(new[] { "FR", "US", "??", "LOCAL" }, stats.Select(s => s.Code).ToArray());
        var us = stats.Single(s => s.Code == "US");
        Assert.Equal(17, us.Connections);
        Assert.Equal(2, us.Addresses);                 // 2 adresses distinctes
        Assert.Equal("chrome.exe", us.Apps[0].Application);
        Assert.Equal(15, us.Apps[0].Connections);
        Assert.Equal("1.2.3.4", us.TopAddresses.Single(a => a.Address == "1.2.3.4").Address);
        Assert.Equal("443, 80", us.TopAddresses.Single(a => a.Address == "1.2.3.4").Ports);
        Assert.Equal(5, stats.Single(s => s.Code == "LOCAL").Connections);
        Assert.Equal(5, stats.Single(s => s.Code == "??").Connections);
        Assert.False(stats.Single(s => s.Code == "LOCAL").IsReal);
        Assert.True(us.IsReal);
    }

    [Fact]
    public void LookupIsCaseAndFormatInsensitive_IncludingMappedIPv4()
    {
        var geo = new Dictionary<string, string> { ["8.8.8.8"] = "us", ["2606:4700:4700::1111"] = "AU" };
        var stats = CountryTraffic.Build(new[] { T("::ffff:8.8.8.8", 443, "a", 1), T("2606:4700:4700:0:0:0:0:1111", 443, "a", 1) }, geo, c => c);
        Assert.Equal(new[] { "AU", "US" }, stats.Select(s => s.Code).OrderBy(c => c).ToArray());
    }

    [Fact]
    public void EmptyApplicationNamesAreLabelledUnknown_AndEmptyInputIsFine()
    {
        var s = CountryTraffic.Build(new[] { T("8.8.8.8", 0, "", 1) }, Geo, c => c).Single();
        Assert.Equal("(inconnu)", s.Apps.Single().Application);
        Assert.Equal("", s.TopAddresses.Single().Ports);
        Assert.Empty(CountryTraffic.Build(Array.Empty<RemoteTraffic>(), Geo));
    }

    [Theory]
    [InlineData("LOCAL", "Réseau local")]
    [InlineData("??", "Pays inconnu")]
    [InlineData("", "Pays inconnu")]
    [InlineData("XK", "Kosovo")]
    [InlineData("ZZZZ", "ZZZZ")]
    public void NameOfSpecialCodes(string code, string expected) => Assert.Equal(expected, CountryTraffic.NameOf(code));

    [Fact]
    public void NameOfKnownCountriesIsNotTheRawCode()
    {
        foreach (var code in new[] { "FR", "US", "DE", "JP", "BR" }) Assert.NotEqual(code, CountryTraffic.NameOf(code));
    }

    [Theory]
    [InlineData(0, 10, 0)]
    [InlineData(5, 0, 0)]
    [InlineData(1, 1, 1)]
    [InlineData(10, 10, 1)]
    public void IntensityBounds(int n, int max, double expected) => Assert.Equal(expected, CountryTraffic.Intensity(n, max), 3);

    [Fact]
    public void IntensityIsMonotonicAndNeverInvisible()
    {
        var values = new[] { 1, 2, 5, 20, 100, 1000 }.Select(n => CountryTraffic.Intensity(n, 1000)).ToArray();
        Assert.True(values.SequenceEqual(values.OrderBy(v => v)));
        Assert.All(values, v => Assert.InRange(v, 0.08, 1));
    }
}

public class WorldMapDataTests
{
    static string FindMap()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var p = Path.Combine(dir.FullName, "src", "SecureWall.App", "Resources", "world-map.txt");
            if (File.Exists(p)) return p;
            dir = dir.Parent;
        }
        throw new FileNotFoundException("world-map.txt introuvable");
    }

    [Fact]
    public void ParsesTheBundledMap()
    {
        var map = WorldMapData.Parse(File.ReadAllText(FindMap()));
        Assert.Equal(1000, map.Width);
        Assert.InRange(map.Height, 380, 410);
        Assert.InRange(map.Shapes.Count, 150, 200);
        foreach (var code in new[] { "FR", "US", "DE", "CN", "BR", "AU", "RU", "NO", "XK" })
            Assert.Contains(map.Shapes, s => s.Code == code);
        Assert.Equal(map.Shapes.Count, map.Shapes.Select(s => s.Code).Distinct().Count());   // un seul tracé par code
        Assert.DoesNotContain(map.Shapes, s => s.Code is "AQ" or "-9");
    }

    [Fact]
    public void EveryPathStaysInsideTheViewBoxAndIsWellFormed()
    {
        var map = WorldMapData.Parse(File.ReadAllText(FindMap()));
        foreach (var s in map.Shapes)
        {
            Assert.StartsWith("M", s.PathData);
            Assert.EndsWith("Z", s.PathData);
            foreach (var pair in System.Text.RegularExpressions.Regex.Matches(s.PathData, @"(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)").Cast<System.Text.RegularExpressions.Match>())
            {
                var x = double.Parse(pair.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
                var y = double.Parse(pair.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture);
                Assert.InRange(x, 0, map.Width); Assert.InRange(y, 0, map.Height);
            }
        }
    }

    [Fact]
    public void SkipsCommentsAndMalformedLines()
    {
        var map = WorldMapData.Parse("# VIEWBOX 0 0 500 200\r\nFR\tFrance\tM0,0L1,1L2,0Z\r\nbad line\r\nXXX\tToo long code\tM0,0Z\r\nUS\tUSA\tnot a path\r\n");
        Assert.Equal(500, map.Width); Assert.Equal(200, map.Height);
        Assert.Equal("FR", map.Shapes.Single().Code);
    }
}

public class GeoLocationServiceTests : IDisposable
{
    readonly TempDb _db = new();
    readonly SettingsStore _settings;
    readonly List<string> _bodies = new();
    DateTime _now = new(2026, 10, 5, 12, 0, 0);
    Func<string, Task<string>> _reply = _ => Task.FromResult("[]");

    public GeoLocationServiceTests() { _settings = new SettingsStore(_db.Store); }
    public void Dispose() => _db.Dispose();

    GeoLocationService Svc() => new(_db.Store, _settings, (body, _) => { _bodies.Add(body); return _reply(body); }, () => _now);
    void Enable(bool on = true) { _settings.Current.GeoLookupEnabled = on; _settings.Save(); }

    static string Answer(params (string ip, string country)[] items) =>
        "[" + string.Join(",", items.Select(i => $"{{\"ip\":\"{i.ip}\",\"country\":\"{i.country}\"}}")) + "]";

    [Fact]
    public async Task DisabledByDefault_NothingIsSentToTheNetwork()
    {
        Assert.False(Svc().Enabled);
        var r = await Svc().LocateAsync(new[] { "8.8.8.8", "1.1.1.1" });
        Assert.Empty(_bodies);
        Assert.Empty(r.Countries);
    }

    [Fact]
    public async Task OnlyPublicAddressesAreEverSent()
    {
        Enable();
        _reply = _ => Task.FromResult(Answer(("8.8.8.8", "US")));
        var r = await Svc().LocateAsync(new[] { "192.168.1.1", "10.0.0.5", "127.0.0.1", "169.254.1.1", "224.0.0.251", "100.64.0.1", "fe80::1", "::1", "0.0.0.0", "n'importe quoi", "", "8.8.8.8" });
        var sent = System.Text.Json.JsonSerializer.Deserialize<string[]>(_bodies.Single())!;
        Assert.Equal(new[] { "8.8.8.8" }, sent);
        Assert.Equal("US", r.Countries["8.8.8.8"]);
    }

    [Fact]
    public async Task RequestBodyContainsAddressesOnly()
    {
        Enable();
        await Svc().LocateAsync(new[] { "8.8.8.8" });
        Assert.Equal("[\"8.8.8.8\"]", _bodies.Single());
    }

    [Fact]
    public async Task ResultsAreCached_SoTheSameAddressIsNeverAskedTwice()
    {
        Enable();
        _reply = _ => Task.FromResult(Answer(("8.8.8.8", "US")));
        await Svc().LocateAsync(new[] { "8.8.8.8" });
        var again = await Svc().LocateAsync(new[] { "8.8.8.8" });
        Assert.Single(_bodies);
        Assert.Equal("US", again.Countries["8.8.8.8"]);
        Assert.Equal(0, again.QueriedOnline);
    }

    [Fact]
    public async Task CachedCountriesStillAppearAfterDisabling_ButNothingNewIsSent()
    {
        Enable();
        _reply = _ => Task.FromResult(Answer(("8.8.8.8", "US")));
        await Svc().LocateAsync(new[] { "8.8.8.8" });
        Enable(false);
        var r = await Svc().LocateAsync(new[] { "8.8.8.8", "5.6.7.8" });
        Assert.Single(_bodies);
        Assert.Equal("US", r.Countries["8.8.8.8"]);
        Assert.False(r.Countries.ContainsKey("5.6.7.8"));
    }

    [Fact]
    public async Task AddressesMissingFromTheAnswerBecomeUnknown_WithAShorterRetryDelay()
    {
        Enable();
        _reply = _ => Task.FromResult(Answer(("8.8.8.8", "US")));   // 1.1.1.1 absent (anycast)
        var r = await Svc().LocateAsync(new[] { "8.8.8.8", "1.1.1.1" });
        Assert.Equal("", r.Countries["1.1.1.1"]);

        _now = _now.AddDays(2);  await Svc().LocateAsync(new[] { "1.1.1.1" });
        Assert.Single(_bodies);                                      // < 3 jours : pas de nouvelle requête
        _now = _now.AddDays(2);  await Svc().LocateAsync(new[] { "1.1.1.1" });
        Assert.Equal(2, _bodies.Count);                              // > 3 jours : on retente
    }

    [Fact]
    public async Task KnownCountriesAreRefreshedAfterThirtyDays()
    {
        Enable();
        _reply = _ => Task.FromResult(Answer(("8.8.8.8", "US")));
        await Svc().LocateAsync(new[] { "8.8.8.8" });
        _now = _now.AddDays(29); await Svc().LocateAsync(new[] { "8.8.8.8" });
        Assert.Single(_bodies);
        _now = _now.AddDays(2);  await Svc().LocateAsync(new[] { "8.8.8.8" });
        Assert.Equal(2, _bodies.Count);
    }

    [Fact]
    public async Task LargeListsAreSplitInBatchesOf100_AndCappedPerRun()
    {
        Enable();
        var ips = Enumerable.Range(0, 1000).Select(i => $"8.{i / 250}.{i % 250}.{i % 7 + 1}").Distinct().ToList();
        _reply = _ => Task.FromResult("[]");
        var r = await Svc().LocateAsync(ips);
        Assert.Equal(GeoLocationService.MaxNewPerRun / GeoLocationService.BatchSize, _bodies.Count);
        Assert.All(_bodies, b => Assert.True(System.Text.Json.JsonSerializer.Deserialize<string[]>(b)!.Length <= GeoLocationService.BatchSize));
        Assert.Equal(GeoLocationService.MaxNewPerRun, r.QueriedOnline);
        Assert.Equal(ips.Count - GeoLocationService.MaxNewPerRun, r.Remaining);
        Assert.False(r.Complete);
    }

    [Fact]
    public async Task NetworkFailureIsReportedNotCached_AndEarlierBatchesAreKept()
    {
        Enable();
        var ips = Enumerable.Range(1, 150).Select(i => $"8.8.{i}.1").ToList();
        var calls = 0;
        _reply = _ => ++calls == 1 ? Task.FromResult("[]") : throw new HttpRequestException("503");
        var r = await Svc().LocateAsync(ips);
        Assert.NotEqual("", r.Warning);
        Assert.Equal(100, r.QueriedOnline);
        Assert.Equal(50, r.Remaining);
        Assert.Equal(100, _db.Store.GetGeoCache(ips).Count);        // le lot qui a échoué n'est pas mis en cache
    }

    [Theory]
    [InlineData("pas du json")]
    [InlineData("")]
    public async Task GarbageAnswerIsAFailureWithoutException(string answer)
    {
        Enable();
        _reply = _ => Task.FromResult(answer);
        var r = await Svc().LocateAsync(new[] { "8.8.8.8" });
        Assert.NotEqual("", r.Warning);
        Assert.Empty(_db.Store.GetGeoCache(new[] { "8.8.8.8" }));
    }

    [Fact]
    public void ParseKeepsOnlyWellFormedEntries()
    {
        var d = GeoLocationService.Parse("[{\"ip\":\"8.8.8.8\",\"country\":\"us\"},{\"ip\":\"1.1.1.1\",\"country\":\"USA\"},{\"ip\":5,\"country\":\"FR\"},{\"country\":\"FR\"},42,{\"ip\":\"::ffff:9.9.9.9\",\"country\":\"CH\"}]");
        Assert.Equal(2, d.Count);
        Assert.Equal("US", d["8.8.8.8"]);
        Assert.Equal("CH", d["9.9.9.9"]);
        Assert.Single(GeoLocationService.Parse("{\"ip\":\"8.8.8.8\",\"country\":\"US\"}"));   // réponse à une seule adresse
    }

    [Fact]
    public async Task CountryCodesFromTheServerAreSanitised()
    {
        Enable();
        _reply = _ => Task.FromResult(Answer(("8.8.8.8", "<script>")));
        var r = await Svc().LocateAsync(new[] { "8.8.8.8" });
        Assert.Equal("", r.Countries["8.8.8.8"]);
    }

    [Fact]
    public async Task ClearCacheForgetsEverything()
    {
        Enable();
        _reply = _ => Task.FromResult(Answer(("8.8.8.8", "US")));
        var svc = Svc();
        await svc.LocateAsync(new[] { "8.8.8.8" });
        Assert.Equal(1, svc.ClearCache());
        Assert.Empty(_db.Store.GetGeoCache(new[] { "8.8.8.8" }));
    }

    [Fact]
    public async Task ClearingTheHistoryAlsoClearsLocatedAddresses()
    {
        Enable();
        _reply = _ => Task.FromResult(Answer(("8.8.8.8", "US")));
        await Svc().LocateAsync(new[] { "8.8.8.8" });
        _db.Store.ClearHistory();
        Assert.Empty(_db.Store.GetGeoCache(new[] { "8.8.8.8" }));
    }

    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("2606:4700:4700::1111", true)]
    [InlineData("192.168.0.1", false)]
    [InlineData("fd00::1", false)]
    [InlineData("224.0.0.1", false)]
    [InlineData("", false)]
    public void IsLocatable(string address, bool expected) => Assert.Equal(expected, GeoLocationService.IsLocatable(address));
}

public class RemoteTrafficStoreTests : IDisposable
{
    readonly TempDb _db = new();
    public void Dispose() => _db.Dispose();

    [Fact]
    public void RemoteTraffic_GroupsByAddressPortAndApplication_WithinThePeriod()
    {
        var a = _db.Store.UpsertApplication("a.exe", @"C:\a.exe", "", "", out _);
        var b = _db.Store.UpsertApplication("b.exe", @"C:\b.exe", "", "", out _);
        var now = DateTime.Now;
        ConnectionRecord Row(string ip, int port, DateTime t) => new() { Protocol = "TCP", LocalAddress = "192.168.1.2", LocalPort = 50000, RemoteAddress = ip, RemotePort = port, State = "Établie", Timestamp = t };
        _db.Store.AddConnections(a, new[] { Row("1.1.1.1", 443, now), Row("1.1.1.1", 443, now), Row("1.1.1.1", 80, now), Row("8.8.8.8", 53, now.AddDays(-10)) });
        _db.Store.AddConnections(b, new[] { Row("1.1.1.1", 443, now), Row("", 0, now) });

        var rows = _db.Store.GetRemoteTraffic(now.AddDays(-1));
        Assert.Equal(3, rows.Count);                                          // 8.8.8.8 trop ancien, adresse vide ignorée
        Assert.Equal(2, rows.Single(r => r.Application == "a.exe" && r.Port == 443).Connections);
        Assert.Equal(1, rows.Single(r => r.Application == "b.exe").Connections);
        Assert.Equal(rows.OrderByDescending(r => r.Connections).First(), rows[0]);
        Assert.Equal(4, _db.Store.GetRemoteTraffic(now.AddDays(-30)).Count);
        Assert.Single(_db.Store.GetRemoteTraffic(now.AddDays(-1), 1));
    }

    [Fact]
    public void GeoCache_RoundTripsUpsertsAndHandlesManyAddresses()
    {
        var t = DateTime.Now;
        _db.Store.SetGeoCache(new[] { new GeoCacheEntry("8.8.8.8", "US", t), new GeoCacheEntry("1.1.1.1", "", t) });
        _db.Store.SetGeoCache(new[] { new GeoCacheEntry("8.8.8.8", "CA", t.AddMinutes(1)) });   // mise à jour, pas de doublon
        var got = _db.Store.GetGeoCache(new[] { "8.8.8.8", "1.1.1.1", "9.9.9.9" });
        Assert.Equal(2, got.Count);
        Assert.Equal("CA", got["8.8.8.8"].Country);
        Assert.Equal("", got["1.1.1.1"].Country);

        var many = Enumerable.Range(0, 1500).Select(i => $"10.{i / 250}.{i % 250}.1").ToList();   // dépasse la limite de paramètres SQLite
        _db.Store.SetGeoCache(many.Select(a => new GeoCacheEntry(a, "FR", t)));
        Assert.Equal(1500, _db.Store.GetGeoCache(many).Count);
    }

    [Fact]
    public void GeoCache_IsPurgedWithOldHistory()
    {
        _db.Store.SetGeoCache(new[] { new GeoCacheEntry("8.8.8.8", "US", DateTime.Now.AddDays(-100)), new GeoCacheEntry("1.1.1.1", "AU", DateTime.Now) });
        _db.Store.PurgeOlderThan(DateTime.Now.AddDays(-90));
        Assert.Equal(new[] { "1.1.1.1" }, _db.Store.GetGeoCache(new[] { "8.8.8.8", "1.1.1.1" }).Keys.ToArray());
    }
}
