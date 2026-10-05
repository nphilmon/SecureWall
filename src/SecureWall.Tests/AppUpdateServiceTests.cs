using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureWall.Security.Updates;
using Xunit;

namespace SecureWall.Tests;

public class AppUpdateServiceTests : IDisposable
{
    readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    readonly string _pub;
    readonly string _dir = Path.Combine(Path.GetTempPath(), "sw-upd-" + Guid.NewGuid().ToString("N"));
    static readonly byte[] Installer = Encoding.UTF8.GetBytes(new string('x', 5000));
    static string Hash(byte[] b) => Convert.ToHexString(SHA256.HashData(b));

    public AppUpdateServiceTests() { _pub = Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo()); }
    public void Dispose() { _key.Dispose(); try { Directory.Delete(_dir, true); } catch { } }

    string Payload(string version = "2.1.0", string? sha = null, long? size = null, string url = "https://github.com/o/r/releases/download/v2.1.0/SecureWall-Setup-2.1.0.exe", string format = "SecureWall.Update", string notes = "Nouveautés")
        => JsonSerializer.Serialize(new { Format = format, Version = version, Published = "2026-10-05", Notes = notes, InstallerUrl = url, Sha256 = sha ?? Hash(Installer), Size = size ?? Installer.Length });

    string Sign(string payload, ECDsa? key = null)
    {
        var sig = (key ?? _key).SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256);
        return JsonSerializer.Serialize(new { Payload = payload, Signature = Convert.ToBase64String(sig) });
    }

    AppUpdateService Svc(Func<Uri, CancellationToken, Task<HttpResponseMessage>> get, string current = "2.0.1")
        => new(new FakeAudit(), Version.Parse(current), get, _pub);

    static HttpResponseMessage Ok(byte[] body) => new(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
    static HttpResponseMessage Ok(string body) => Ok(Encoding.UTF8.GetBytes(body));
    static HttpResponseMessage Redirect(string to) => new(HttpStatusCode.Found) { Headers = { Location = new Uri(to) } };

    // ----- Manifeste -----
    [Fact]
    public void ValidManifestIsAccepted()
    {
        var m = AppUpdateService.Verify(Sign(Payload()), _pub, out var err);
        Assert.NotNull(m); Assert.Equal("", err);
        Assert.Equal("2.1.0", m!.Version);
    }

    [Fact]
    public void TamperedPayloadIsRejected()
    {
        var env = Sign(Payload());
        var tampered = env.Replace("2.1.0", "9.9.9");
        Assert.Null(AppUpdateService.Verify(tampered, _pub, out var err));
        Assert.Contains("Signature invalide", err);
    }

    [Fact]
    public void ManifestSignedWithAnotherKeyIsRejected()
    {
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.Null(AppUpdateService.Verify(Sign(Payload(), other), _pub, out var err));
        Assert.Contains("Signature invalide", err);
    }

    [Theory]
    [InlineData("pas du json")]
    [InlineData("{}")]
    [InlineData("{\"Payload\":\"x\",\"Signature\":\"!!\"}")]
    [InlineData("")]
    public void GarbageIsRejectedWithoutException(string input) => Assert.Null(AppUpdateService.Verify(input, _pub, out _));

    [Fact]
    public void InvalidFieldsAreRejectedEvenWhenSigned()
    {
        Assert.Null(AppUpdateService.Verify(Sign(Payload(format: "Autre")), _pub, out _));
        Assert.Null(AppUpdateService.Verify(Sign(Payload(version: "abc")), _pub, out _));
        Assert.Null(AppUpdateService.Verify(Sign(Payload(version: "2")), _pub, out _));
        Assert.Null(AppUpdateService.Verify(Sign(Payload(sha: "1234")), _pub, out _));
        Assert.Null(AppUpdateService.Verify(Sign(Payload(size: 0)), _pub, out _));
        Assert.Null(AppUpdateService.Verify(Sign(Payload(size: AppUpdateService.MaxInstallerBytes + 1)), _pub, out _));
        Assert.Null(AppUpdateService.Verify(Sign(Payload(notes: new string('n', 5000))), _pub, out _));
    }

    [Theory]
    [InlineData("https://github.com/o/r/releases/download/v1/x.exe", true)]
    [InlineData("https://objects.githubusercontent.com/abc/x.exe", true)]
    [InlineData("https://release-assets.githubusercontent.com/abc", true)]
    [InlineData("http://github.com/o/r/x.exe", false)]
    [InlineData("https://evil.com/x.exe", false)]
    [InlineData("https://github.com.evil.com/x.exe", false)]
    [InlineData("https://evilgithubusercontent.com/x.exe", false)]
    [InlineData("https://user:pw@github.com/x.exe", false)]
    [InlineData("https://github.com:8443/x.exe", false)]
    public void InstallerHostsAreRestrictedToGitHub(string url, bool ok)
    {
        Assert.Equal(ok, AppUpdateService.IsAllowedInstallerUrl(new Uri(url)));
        Assert.Equal(ok, AppUpdateService.Verify(Sign(Payload(url: url)), _pub, out _) != null);
    }

    [Theory]
    [InlineData("https://raw.githubusercontent.com/o/r/main/update.signed.json", true)]
    [InlineData("https://github.com/o/r/update.json", false)]
    [InlineData("http://raw.githubusercontent.com/o/r/main/u.json", false)]
    [InlineData("https://evil.com/u.json", false)]
    [InlineData("n'importe quoi", false)]
    public void ManifestUrlIsRestrictedToRawGithub(string url, bool ok) => Assert.Equal(ok, AppUpdateService.IsAllowedManifestUrl(url, out _));

    // ----- Recherche -----
    [Fact]
    public async Task Check_ReportsNewerVersion()
    {
        var svc = Svc((_, _) => Task.FromResult(Ok(Sign(Payload("2.1.0")))));
        var r = await svc.CheckAsync("https://raw.githubusercontent.com/o/r/main/u.json");
        Assert.True(r.Available); Assert.False(r.UpToDate);
    }

    [Theory]
    [InlineData("2.0.1")]
    [InlineData("1.9.9")]
    public async Task Check_SaysUpToDateForSameOrOlderVersion(string published)
    {
        var svc = Svc((_, _) => Task.FromResult(Ok(Sign(Payload(published)))));
        var r = await svc.CheckAsync("https://raw.githubusercontent.com/o/r/main/u.json");
        Assert.False(r.Available); Assert.True(r.UpToDate);
    }

    [Fact]
    public async Task Check_NeverCallsTheNetworkForARefusedUrl()
    {
        var called = false;
        var svc = Svc((_, _) => { called = true; return Task.FromResult(Ok("")); });
        var r = await svc.CheckAsync("https://evil.com/u.json");
        Assert.False(called); Assert.False(r.Available); Assert.Contains("refusée", r.Message);
    }

    [Fact]
    public async Task Check_ReportsNetworkErrorsWithoutThrowing()
    {
        var svc = Svc((_, _) => throw new HttpRequestException("pas de réseau"));
        var r = await svc.CheckAsync("https://raw.githubusercontent.com/o/r/main/u.json");
        Assert.False(r.Available); Assert.Contains("pas de réseau", r.Message);
    }

    [Fact]
    public async Task Check_RejectsOversizedManifest()
    {
        var svc = Svc((_, _) => Task.FromResult(Ok(new string(' ', AppUpdateService.MaxManifestBytes + 10))));
        var r = await svc.CheckAsync("https://raw.githubusercontent.com/o/r/main/u.json");
        Assert.False(r.Available);
    }

    // ----- Téléchargement -----
    UpdateManifest Manifest(string? sha = null, long? size = null, string? url = null)
        => AppUpdateService.Verify(Sign(Payload(sha: sha, size: size, url: url ?? "https://github.com/o/r/releases/download/v2.1.0/s.exe")), _pub, out _)!;

    [Fact]
    public async Task Download_VerifiesHashAndKeepsFile()
    {
        var svc = Svc((_, _) => Task.FromResult(Ok(Installer)));
        var reports = new List<double>();
        var (path, msg) = await svc.DownloadAsync(Manifest(), _dir, new Progress<double>(reports.Add));
        Assert.NotNull(path); Assert.True(File.Exists(path));
        Assert.Equal(Installer, await File.ReadAllBytesAsync(path!));
        Assert.False(File.Exists(path + ".part"));
        Assert.EndsWith("SecureWall-Setup-2.1.0.exe", path);
    }

    [Fact]
    public async Task Download_DeletesFileWhenHashDiffers()
    {
        var tampered = (byte[])Installer.Clone(); tampered[10] ^= 0xFF;
        var svc = Svc((_, _) => Task.FromResult(Ok(tampered)));
        var (path, msg) = await svc.DownloadAsync(Manifest(), _dir);
        Assert.Null(path); Assert.Contains("SHA-256", msg);
        Assert.Empty(Directory.GetFiles(_dir));
    }

    [Fact]
    public async Task Download_RefusesFilesLargerThanAnnounced()
    {
        var bigger = Installer.Concat(new byte[100]).ToArray();
        var svc = Svc((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new MemoryStream(bigger)) }));
        var (path, _) = await svc.DownloadAsync(Manifest(), _dir);
        Assert.Null(path);
        Assert.Empty(Directory.GetFiles(_dir));
    }

    [Fact]
    public async Task Download_RefusesTruncatedFiles()
    {
        var svc = Svc((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new MemoryStream(Installer[..1000])) }));
        var (path, _) = await svc.DownloadAsync(Manifest(), _dir);
        Assert.Null(path);
        Assert.Empty(Directory.GetFiles(_dir));
    }

    [Fact]
    public async Task Download_FollowsRedirectsToGithubHostsOnly()
    {
        var hops = new List<string>();
        var svc = Svc((u, _) =>
        {
            hops.Add(u.Host);
            return Task.FromResult(u.Host == "github.com" ? Redirect("https://objects.githubusercontent.com/abc/s.exe") : Ok(Installer));
        });
        var (path, _) = await svc.DownloadAsync(Manifest(), _dir);
        Assert.NotNull(path);
        Assert.Equal(new[] { "github.com", "objects.githubusercontent.com" }, hops);
    }

    [Fact]
    public async Task Download_RefusesRedirectToAnotherHost()
    {
        var svc = Svc((u, _) => Task.FromResult(u.Host == "github.com" ? Redirect("https://evil.example/s.exe") : Ok(Installer)));
        var (path, msg) = await svc.DownloadAsync(Manifest(), _dir);
        Assert.Null(path); Assert.Contains("refusée", msg);
    }

    [Fact]
    public async Task Download_StopsRedirectLoops()
    {
        var svc = Svc((u, _) => Task.FromResult(Redirect("https://github.com/loop")));
        var (path, msg) = await svc.DownloadAsync(Manifest(), _dir);
        Assert.Null(path); Assert.Contains("redirections", msg);
    }

    [Fact]
    public async Task Download_ReportsHttpErrors()
    {
        var svc = Svc((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)));
        var (path, msg) = await svc.DownloadAsync(Manifest(), _dir);
        Assert.Null(path); Assert.Contains("impossible", msg);
    }

    [Fact]
    public async Task Download_RefusesWhenServerAnnouncesAnotherSize()
    {
        var svc = Svc((_, _) =>
        {
            var r = Ok(Installer); r.Content.Headers.ContentLength = Installer.Length + 7;
            return Task.FromResult(r);
        });
        var (path, msg) = await svc.DownloadAsync(Manifest(), _dir);
        Assert.Null(path); Assert.Contains("taille", msg);
    }
}
