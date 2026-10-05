using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.PrivilegedService;
using SecureWall.PrivilegedService.Antivirus;
using SecureWall.PrivilegedService.Firewall;
using SecureWall.PrivilegedService.SystemOperations;
using SecureWall.Security.DnsConfig;
using SecureWall.Security.Firewall;
using SecureWall.Security.Hardening;
using SecureWall.Security.Updates;
using Xunit;

namespace SecureWall.Tests;

public class FolderTrustTests
{
    const string System_ = "S-1-5-18", Admins = "S-1-5-32-544", Users = "S-1-5-32-545", AuthUsers = "S-1-5-11", Everyone = "S-1-1-0";
    const string TrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    const string StandardUser = "S-1-5-21-1111111111-2222222222-3333333333-1001";

    static AceEntry Allow(string sid, FileSystemRights r, bool here = true) => new(sid, true, r, here);
    static AceEntry Deny(string sid, FileSystemRights r) => new(sid, false, r, true);
    static readonly FileSystemRights Rx = FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize;

    static (string, string?, IReadOnlyList<AceEntry>) Folder(string path, string? owner, params AceEntry[] aces) => (path, owner, aces);

    static List<AceEntry> ProgramFilesLike() => new()
    {
        Allow(System_, FileSystemRights.Modify), Allow(Admins, FileSystemRights.Modify), Allow(Users, Rx),
        Allow(TrustedInstaller, FileSystemRights.FullControl), Allow("S-1-3-0", FileSystemRights.FullControl, here: false),
    };

    [Fact]
    public void AStandardProgramFilesFolderIsTrusted()
    {
        var chain = new[] { Folder(@"C:\Program Files\SecureWall", Admins, ProgramFilesLike().ToArray()), Folder(@"C:\Program Files", TrustedInstaller, ProgramFilesLike().ToArray()),
            Folder(@"C:\", System_, Allow(AuthUsers, FileSystemRights.AppendData), Allow(Users, Rx), Allow(Admins, FileSystemRights.FullControl)) };
        Assert.True(FolderTrust.EvaluateChain(chain).Trusted);
    }

    [Theory]
    [InlineData(FileSystemRights.Modify)]
    [InlineData(FileSystemRights.FullControl)]
    [InlineData(FileSystemRights.WriteData)]
    [InlineData(FileSystemRights.AppendData)]
    [InlineData(FileSystemRights.CreateFiles)]
    [InlineData(FileSystemRights.Delete)]
    [InlineData(FileSystemRights.DeleteSubdirectoriesAndFiles)]
    [InlineData(FileSystemRights.ChangePermissions)]
    [InlineData(FileSystemRights.TakeOwnership)]
    public void WriteRightsGrantedToStandardUsersMakeTheInstallFolderUntrusted(FileSystemRights rights)
    {
        foreach (var sid in new[] { Users, AuthUsers, Everyone })
        {
            var r = FolderTrust.EvaluateChain(new[] { Folder(@"C:\SecureWall", Admins, Allow(sid, rights), Allow(System_, FileSystemRights.FullControl)) });
            Assert.False(r.Trusted, $"{sid} / {rights}");
            Assert.Contains("modifiable", r.Reason);
        }
    }

    [Fact]
    public void ReadOnlyAndInheritOnlyEntriesAreHarmless()
    {
        Assert.True(FolderTrust.EvaluateChain(new[] { Folder(@"C:\App", Admins, Allow(Users, Rx), Allow(Users, FileSystemRights.FullControl, here: false)) }).Trusted);
        Assert.True(FolderTrust.EvaluateChain(new[] { Folder(@"C:\App", Admins, Allow(Users, FileSystemRights.ReadData | FileSystemRights.ReadAttributes | FileSystemRights.ListDirectory)) }).Trusted);
    }

    [Fact]
    public void ADenyForTheSameAccountCancelsTheGrant()
    {
        var r = FolderTrust.EvaluateChain(new[] { Folder(@"C:\App", Admins, Allow(Users, FileSystemRights.Modify), Deny(Users, FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership)) });
        Assert.True(r.Trusted);
        var partial = FolderTrust.EvaluateChain(new[] { Folder(@"C:\App", Admins, Allow(Users, FileSystemRights.Modify), Deny(Users, FileSystemRights.WriteData)) });
        Assert.False(partial.Trusted);   // AppendData, Delete… restent accordés
    }

    [Theory]
    [InlineData(StandardUser, false)]
    [InlineData(Users, false)]
    [InlineData(Everyone, false)]
    [InlineData(null, false)]
    [InlineData(System_, true)]
    [InlineData(Admins, true)]
    [InlineData(TrustedInstaller, true)]
    [InlineData("S-1-5-19", false)]      // LOCAL SERVICE : pas SYSTEM
    public void OwnerTrust(string? sid, bool expected)
    {
        Assert.Equal(expected, FolderTrust.IsTrustedOwner(sid));
        Assert.Equal(expected, FolderTrust.EvaluateChain(new[] { Folder(@"C:\App", sid, Allow(Admins, FileSystemRights.FullControl)) }).Trusted);
    }

    [Fact]
    public void ParentFoldersMustNotLetStandardUsersReplaceTheInstallFolder()
    {
        var install = Folder(@"C:\Tools\SecureWall", Admins, Allow(Admins, FileSystemRights.FullControl), Allow(Users, Rx));
        // Créer des dossiers dans le parent est sans danger (comme sur C:\) ; supprimer/renommer/redéfinir les droits ne l'est pas.
        Assert.True(FolderTrust.EvaluateChain(new[] { install, Folder(@"C:\Tools", Admins, Allow(Admins, FileSystemRights.FullControl), Allow(Users, FileSystemRights.AppendData | FileSystemRights.WriteData | Rx)) }).Trusted);
        foreach (var rights in new[] { FileSystemRights.DeleteSubdirectoriesAndFiles, FileSystemRights.ChangePermissions, FileSystemRights.TakeOwnership, FileSystemRights.FullControl })
        {
            var r = FolderTrust.EvaluateChain(new[] { install, Folder(@"C:\Tools", Admins, Allow(Admins, FileSystemRights.FullControl), Allow(Users, rights)) });
            Assert.False(r.Trusted, rights.ToString());
            Assert.Contains(@"C:\Tools", r.Reason);
        }
    }

    [Fact]
    public void ModifyOnAParentAloneCannotReplaceAProtectedInstallFolder_ButIsCaughtWhenInherited()
    {
        var parent = Folder(@"C:\Tools", Admins, Allow(Admins, FileSystemRights.FullControl), Allow(Users, FileSystemRights.Modify));
        var protectedChild = Folder(@"C:\Tools\SecureWall", Admins, Allow(Admins, FileSystemRights.FullControl), Allow(Users, Rx));
        Assert.True(FolderTrust.EvaluateChain(new[] { protectedChild, parent }).Trusted);          // droits non hérités : le dossier reste hors d'atteinte
        var inheritingChild = Folder(@"C:\Tools\SecureWall", Admins, Allow(Admins, FileSystemRights.FullControl), Allow(Users, FileSystemRights.Modify));
        Assert.False(FolderTrust.EvaluateChain(new[] { inheritingChild, parent }).Trusted);        // hérités : refusé
    }

    [Fact]
    public void AParentOwnedByAStandardUserIsUntrusted()
    {
        var r = FolderTrust.EvaluateChain(new[] { Folder(@"C:\A\B", Admins, Allow(Admins, FileSystemRights.FullControl)), Folder(@"C:\A", StandardUser, Allow(Admins, FileSystemRights.FullControl)) });
        Assert.False(r.Trusted);
        Assert.Contains("non fiable", r.Reason);
    }

    // ----- Système de fichiers réel (lecture seule) -----
    [Fact]
    public void RealSystemFolderIsTrusted()
    {
        var r = FolderTrust.CheckDirectory(Environment.SystemDirectory);
        Assert.True(r.Trusted, r.Reason);
    }

    [Fact]
    public void RealFolderCreatedByTheCurrentUserIsNotTrusted()
    {
        var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "sw-trust-" + Guid.NewGuid().ToString("N")));
        try { Assert.False(FolderTrust.CheckDirectory(dir.FullName).Trusted); }
        finally { dir.Delete(true); }
    }

    [Fact]
    public void UnreadableOrMissingFolderIsRefusedNotAccepted()
    {
        Assert.False(FolderTrust.CheckDirectory(Path.Combine(Path.GetTempPath(), "sw-absent-" + Guid.NewGuid().ToString("N"), "x")).Trusted);
    }
}

public class DataDirectoryGuardTests
{
    static IEnumerable<FileSystemAccessRule> Rules(DirectorySecurity s) => s.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>();
    static SecurityIdentifier Sid(WellKnownSidType t) => new(t, null);

    [Fact]
    public void PrivateSecurity_GivesAccessOnlyToSystemAndAdministrators()
    {
        var s = DataDirectoryGuard.BuildPrivateSecurity();
        Assert.True(s.AreAccessRulesProtected);
        var rules = Rules(s).ToList();
        Assert.Equal(2, rules.Count);
        Assert.All(rules, r => { Assert.Equal(AccessControlType.Allow, r.AccessControlType); Assert.Equal(FileSystemRights.FullControl, r.FileSystemRights); });
        Assert.Contains(rules, r => r.IdentityReference.Equals(Sid(WellKnownSidType.LocalSystemSid)));
        Assert.Contains(rules, r => r.IdentityReference.Equals(Sid(WellKnownSidType.BuiltinAdministratorsSid)));
        Assert.DoesNotContain(rules, r => r.IdentityReference.Equals(Sid(WellKnownSidType.BuiltinUsersSid)));
    }

    [Fact]
    public void SharedSecurity_LetsUsersReadButNeverWrite()
    {
        var s = DataDirectoryGuard.BuildSharedReadSecurity();
        Assert.True(s.AreAccessRulesProtected);
        var users = Rules(s).Single(r => r.IdentityReference.Equals(Sid(WellKnownSidType.BuiltinUsersSid)));
        Assert.Equal(FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize, users.FileSystemRights & (FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize));
        Assert.Equal((FileSystemRights)0, users.FileSystemRights & FolderTrust.ContentWrite);
        Assert.Equal(3, Rules(s).Count());
    }

    [Fact]
    public void AFolderOwnedByTheCurrentUserIsMovedAsideNeverReused()
    {
        var root = Path.Combine(Path.GetTempPath(), "sw-guard-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "planted.txt"), "x");
        var warnings = new List<string>();
        string? aside = null;
        try
        {
            Assert.True(DataDirectoryGuard.QuarantineIfUntrusted(root, warnings));
            Assert.False(Directory.Exists(root));
            aside = Directory.GetDirectories(Path.GetTempPath(), Path.GetFileName(root) + ".untrusted-*").Single();
            Assert.True(File.Exists(Path.Combine(aside, "planted.txt")));       // rien n'est perdu : déplacé, pas supprimé
            Assert.Contains("non fiable", warnings.Single());
        }
        finally { if (aside != null) Directory.Delete(aside, true); if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Fact]
    public void MissingFolderIsLeftAlone()
    {
        var warnings = new List<string>();
        Assert.False(DataDirectoryGuard.QuarantineIfUntrusted(Path.Combine(Path.GetTempPath(), "sw-none-" + Guid.NewGuid().ToString("N")), warnings));
        Assert.Empty(warnings);
    }

    [Fact]
    public void FilesOwnedByAnUntrustedAccountAreDeleted_AndEachOneIsReported()
    {
        var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "sw-purge-" + Guid.NewGuid().ToString("N")));
        try
        {
            File.WriteAllText(Path.Combine(dir.FullName, "fw-20991231-235959.wfw"), "piégé");
            File.WriteAllText(Path.Combine(dir.FullName, "emergency.json"), "{}");
            var warnings = new List<string>();
            Assert.Equal(2, DataDirectoryGuard.PurgeUntrustedFiles(dir.FullName, warnings, recursive: false));
            Assert.Empty(dir.GetFiles());
            Assert.Equal(2, warnings.Count);
            Assert.Contains(warnings, w => w.Contains("fw-20991231-235959.wfw"));
        }
        finally { dir.Delete(true); }
        Assert.Equal(0, DataDirectoryGuard.PurgeUntrustedFiles(Path.Combine(Path.GetTempPath(), "sw-none-" + Guid.NewGuid().ToString("N")), new List<string>(), false));
    }
}

public class PipeHardeningTests
{
    static IEnumerable<PipeAccessRule> Rules(PipeSecurity s) => s.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<PipeAccessRule>();

    [Fact]
    public void PipeAcl_StandardUsersCanConnectButCannotCreateInstances_AndNetworkIsDenied()
    {
        var rules = Rules(PipeServerWorker.BuildSecurity()).ToList();
        var auth = rules.Single(r => r.IdentityReference.Equals(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null)));
        Assert.Equal(AccessControlType.Allow, auth.AccessControlType);
        Assert.True(auth.PipeAccessRights.HasFlag(PipeAccessRights.ReadWrite));
        Assert.False(auth.PipeAccessRights.HasFlag(PipeAccessRights.CreateNewInstance));    // pas de faux serveur sous le même nom
        Assert.False(auth.PipeAccessRights.HasFlag(PipeAccessRights.ChangePermissions));
        Assert.False(auth.PipeAccessRights.HasFlag(PipeAccessRights.TakeOwnership));

        var net = rules.Single(r => r.IdentityReference.Equals(new SecurityIdentifier(WellKnownSidType.NetworkSid, null)));
        Assert.Equal(AccessControlType.Deny, net.AccessControlType);
        Assert.Equal(PipeAccessRights.FullControl, net.PipeAccessRights);
        Assert.Contains(rules, r => r.IdentityReference.Equals(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)) && r.PipeAccessRights == PipeAccessRights.FullControl);
        Assert.Equal(4, rules.Count);
    }

    [Fact]
    public async Task RealPipe_AClientThatIsNotSecureWallExeIsRefused()
    {
        var name = "sw-test-" + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var wait = server.WaitForConnectionAsync();
        await client.ConnectAsync(3000);
        await wait;

        var auth = new ClientAuthenticator(NullLogger<ClientAuthenticator>.Instance, () => FolderTrustResult.Ok).Authenticate(server);
        Assert.False(auth.Allowed);
        Assert.Contains("binaire client inattendu", auth.Reason);   // le client est l'hôte de test, pas SecureWall.exe du dossier d'installation
    }

    [Fact]
    public async Task RealPipe_EverythingIsRefusedWhenTheInstallFolderIsUntrusted_EvenWithAnyClient()
    {
        var name = "sw-test-" + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var wait = server.WaitForConnectionAsync();
        await client.ConnectAsync(3000);
        await wait;

        var guard = new ClientAuthenticator(NullLogger<ClientAuthenticator>.Instance, () => new FolderTrustResult(false, "dossier modifiable par les utilisateurs"));
        Assert.False(guard.InstallTrust.Trusted);
        var auth = guard.Authenticate(server);
        Assert.False(auth.Allowed);
        Assert.Contains("dossier d'installation non fiable", auth.Reason);
    }

    [Fact]
    public async Task FirstPipeInstance_RefusesToTakeOverAnExistingPipeName()
    {
        var name = "sw-test-" + Guid.NewGuid().ToString("N");
        await using var squatter = new NamedPipeServerStream(name, PipeDirection.InOut, 4, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        // Le service intercepte exactement ces deux types (UnauthorizedAccessException ou IOException) et réessaie en le journalisant.
        var ex = Assert.ThrowsAny<Exception>(() => new NamedPipeServerStream(name, PipeDirection.InOut, 4, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance));
        Assert.True(ex is UnauthorizedAccessException or IOException, ex.GetType().Name);
        await Task.CompletedTask;
    }

    // ----- Répartiteur : « Restaurer Internet » n'est jamais limité -----
    sealed class NoDns : IDnsSystem
    {
        public IReadOnlyList<DnsAdapterInfo> GetAdapters() => Array.Empty<DnsAdapterInfo>();
        public int SetServers(int interfaceIndex, string[]? servers) => 0;
        public Task<bool> FlushCacheAsync(CancellationToken ct) => Task.FromResult(true);
    }

    static RequestDispatcher Dispatcher(out FakeFirewallPolicy policy)
    {
        policy = new FakeFirewallPolicy();
        var backup = new FakeFirewallBackup();
        var emergency = new EmergencyExecutor(policy, backup, Path.Combine(Path.GetTempPath(), "sw-rl-" + Guid.NewGuid().ToString("N") + ".json"));
        return new RequestDispatcher(new FirewallHandler(policy, backup, emergency), new DefenderHandler(), new SystemHandler(), new DnsHandler(new DnsConfigurator(new NoDns())), NullLogger<RequestDispatcher>.Instance);
    }

    static PipeRequest Req(PrivilegedOperation op) => new() { Operation = op, Args = new() };

    [Fact]
    public async Task RateLimit_Blocks61stModificationButNeverTheEmergencyRestore()
    {
        var d = Dispatcher(out var policy);
        for (var i = 0; i < 60; i++) Assert.True((await d.DispatchAsync(Req(PrivilegedOperation.FirewallBackup), "u", default)).Success);

        var blocked = await d.DispatchAsync(Req(PrivilegedOperation.EmergencyCutoff), "u", default);
        Assert.False(blocked.Success);
        Assert.Equal("rate-limit", blocked.ErrorCode);
        Assert.Empty(policy.Rules);

        var restore = await d.DispatchAsync(Req(PrivilegedOperation.EmergencyRestore), "u", default);
        Assert.True(restore.Success, restore.Message);                 // la sortie de secours reste toujours disponible
    }

    [Fact]
    public async Task EmergencyRestore_DoesNotConsumeTheBudgetOfOtherOperations()
    {
        var d = Dispatcher(out _);
        for (var i = 0; i < 200; i++) Assert.True((await d.DispatchAsync(Req(PrivilegedOperation.EmergencyRestore), "u", default)).Success);
        Assert.True((await d.DispatchAsync(Req(PrivilegedOperation.FirewallBackup), "u", default)).Success);
    }
}

public class InstallerLockTests : IDisposable
{
    readonly string _dir = Path.Combine(Path.GetTempPath(), "sw-lock-" + Guid.NewGuid().ToString("N"));
    static readonly byte[] Content = Encoding.UTF8.GetBytes(new string('i', 4096));

    public InstallerLockTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    static UpdateManifest Manifest(byte[] content) => new() { Version = "2.1.0", Sha256 = Convert.ToHexString(SHA256.HashData(content)), Size = content.Length };
    AppUpdateService Svc() => new(new FakeAudit(), new Version(2, 0, 1));
    string Write(byte[] c) { var p = Path.Combine(_dir, "setup.exe"); File.WriteAllBytes(p, c); return p; }

    [Fact]
    public void VerifiedInstallerCannotBeReplacedRenamedOrDeletedWhileLocked()
    {
        var path = Write(Content);
        var (fs, msg) = Svc().OpenVerified(path, Manifest(Content));
        Assert.NotNull(fs); Assert.Equal("", msg);
        using (fs)
        {
            Assert.Throws<IOException>(() => File.WriteAllBytes(path, new byte[] { 1, 2, 3 }));        // remplacement
            Assert.Throws<IOException>(() => File.Delete(path));                                      // suppression
            Assert.Throws<IOException>(() => File.Move(path, path + ".old"));                         // renommage
            using var reader = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);  // lecture/exécution : autorisées
            Assert.Equal(Content.Length, reader.Length);
            Assert.Equal(0, fs!.Position);                                                             // flux prêt à être conservé
        }
        File.WriteAllBytes(path, Content);                                                             // verrou libéré à la fermeture
    }

    [Fact]
    public void AFileSwappedAfterDownloadIsRefused_SameSizeOrNot()
    {
        var path = Write(Content);
        var m = Manifest(Content);
        var swapped = (byte[])Content.Clone(); swapped[2000] ^= 0xFF;
        File.WriteAllBytes(path, swapped);
        var (fs, msg) = Svc().OpenVerified(path, m);
        Assert.Null(fs); Assert.Contains("empreinte", msg);

        File.WriteAllBytes(path, Content.Concat(new byte[] { 0 }).ToArray());
        var (fs2, msg2) = Svc().OpenVerified(path, m);
        Assert.Null(fs2); Assert.Contains("taille", msg2);
        File.WriteAllBytes(path, Content);          // aucun verrou ne subsiste après un refus
    }

    [Fact]
    public void MissingOrAlreadyOpenFilesAreReportedWithoutException()
    {
        Assert.Null(Svc().OpenVerified(Path.Combine(_dir, "absent.exe"), Manifest(Content)).Lock);
        var path = Write(Content);
        using var writer = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);   // un autre programme tient le fichier
        var (fs, msg) = Svc().OpenVerified(path, Manifest(Content));
        Assert.Null(fs); Assert.Contains("inaccessible", msg);
    }
}
