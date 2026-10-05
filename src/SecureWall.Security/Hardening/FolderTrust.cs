using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SecureWall.Security.Hardening;

/// <summary>Une entrée d'ACL simplifiée (testable sans système de fichiers).</summary>
public sealed record AceEntry(string Sid, bool Allow, FileSystemRights Rights, bool AppliesToThisFolder);

public sealed record FolderTrustResult(bool Trusted, string Reason)
{
    public static readonly FolderTrustResult Ok = new(true, "");
}

/// <summary>
/// Évalue si un dossier (et ses parents) ne peut être modifié, remplacé ou repris que par SYSTEM / les administrateurs.
/// Sert à deux choses : (1) le service refuse tout client si son propre dossier d'installation est modifiable par un utilisateur standard
/// (sinon la vérification « le client est SecureWall.exe de ce dossier » ne prouve plus rien) ; (2) le dossier de données du service
/// ne doit jamais appartenir à un utilisateur standard (il pourrait redéfinir les droits à volonté et rediriger les écritures de SYSTEM).
/// </summary>
public static class FolderTrust
{
    /// <summary>Comptes de confiance : SYSTEM, Administrateurs, TrustedInstaller, créateur-propriétaire (marqueur d'héritage). LOCAL SERVICE / NETWORK SERVICE ne le sont volontairement pas.</summary>
    static readonly HashSet<string> TrustedSids = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-18",                                                         // SYSTEM
        "S-1-5-32-544",                                                     // Administrateurs
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",   // TrustedInstaller
        "S-1-3-0",                                                          // CREATOR OWNER (héritage seulement)
    };

    /// <summary>Comptes non privilégiés : tout accès en écriture accordé à l'un d'eux rend le dossier non fiable.</summary>
    static readonly HashSet<string> LowPrivilegeSids = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-1-0",        // Tout le monde
        "S-1-5-11",       // Utilisateurs authentifiés
        "S-1-5-32-545",   // Utilisateurs
        "S-1-5-4",        // Interactif
        "S-1-2-1",        // Console
        "S-1-5-7",        // Anonyme
        "S-1-5-32-546",   // Invités
    };

    /// <summary>Droits qui permettent de modifier le contenu du dossier lui-même.</summary>
    public const FileSystemRights ContentWrite =
        FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    /// <summary>Droits qui permettent de remplacer ou renommer un dossier enfant depuis son parent.</summary>
    public const FileSystemRights ParentReplace =
        FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    public static bool IsTrustedOwner(string? ownerSid) => ownerSid != null && TrustedSids.Contains(ownerSid);

    /// <param name="ownerSid">Propriétaire du dossier.</param>
    /// <param name="aces">Entrées de l'ACL.</param>
    /// <param name="dangerous">Droits dont l'octroi à un compte non privilégié est refusé.</param>
    public static FolderTrustResult EvaluateFolder(string path, string? ownerSid, IEnumerable<AceEntry> aces, FileSystemRights dangerous)
    {
        if (!IsTrustedOwner(ownerSid))
            return new(false, $"« {path} » appartient à un compte non fiable ({ownerSid ?? "inconnu"}) : il pourrait en modifier les droits.");

        var list = aces.Where(a => a.AppliesToThisFolder).ToList();
        foreach (var sid in list.Where(a => a.Allow && LowPrivilegeSids.Contains(a.Sid)).Select(a => a.Sid).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var granted = list.Where(a => a.Allow && a.Sid.Equals(sid, StringComparison.OrdinalIgnoreCase)).Aggregate((FileSystemRights)0, (acc, a) => acc | a.Rights);
            var denied = list.Where(a => !a.Allow && a.Sid.Equals(sid, StringComparison.OrdinalIgnoreCase)).Aggregate((FileSystemRights)0, (acc, a) => acc | a.Rights);
            var effective = granted & ~denied & dangerous;
            if (effective != 0)
                return new(false, $"« {path} » est modifiable par des utilisateurs standard (compte {Describe(sid)} : {effective}).");
        }
        return FolderTrustResult.Ok;
    }

    /// <summary>
    /// Évalue un dossier d'installation : le dossier lui-même (écriture interdite aux comptes non privilégiés), puis chaque dossier parent
    /// (aucun droit de suppression, de changement de droits ou de prise de possession pour eux, car cela permettrait de remplacer le dossier).
    /// </summary>
    public static FolderTrustResult EvaluateChain(IReadOnlyList<(string Path, string? OwnerSid, IReadOnlyList<AceEntry> Aces)> chain)
    {
        for (var i = 0; i < chain.Count; i++)
        {
            var (path, owner, aces) = chain[i];
            var r = EvaluateFolder(path, owner, aces, i == 0 ? ContentWrite : ParentReplace);
            if (!r.Trusted) return r;
        }
        return FolderTrustResult.Ok;
    }

    static string Describe(string sid) => sid switch
    {
        "S-1-1-0" => "Tout le monde", "S-1-5-11" => "Utilisateurs authentifiés", "S-1-5-32-545" => "Utilisateurs", _ => sid,
    };

    // ---------- Lecture réelle du système de fichiers ----------
    [SupportedOSPlatform("windows")]
    public static FolderTrustResult CheckDirectory(string directory)
    {
        try
        {
            var chain = new List<(string, string?, IReadOnlyList<AceEntry>)>();
            for (var d = new DirectoryInfo(Path.GetFullPath(directory)); d != null; d = d.Parent)
                chain.Add((d.FullName, null, Array.Empty<AceEntry>()));
            var resolved = new List<(string, string?, IReadOnlyList<AceEntry>)>();
            foreach (var (path, _, _) in chain) resolved.Add(ReadDirectory(path));
            return EvaluateChain(resolved);
        }
        catch (Exception ex)
        {
            return new(false, "Impossible de vérifier les droits du dossier d'installation : " + ex.Message);   // dans le doute, on refuse
        }
    }

    [SupportedOSPlatform("windows")]
    static (string, string?, IReadOnlyList<AceEntry>) ReadDirectory(string path)
    {
        var sec = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        var owner = (sec.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value;
        var aces = sec.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
            .Select(r => new AceEntry(r.IdentityReference.Value, r.AccessControlType == AccessControlType.Allow, r.FileSystemRights,
                (r.PropagationFlags & PropagationFlags.InheritOnly) == 0))
            .ToList();
        return (path, owner, aces);
    }

    [SupportedOSPlatform("windows")]
    public static string? OwnerSid(string directory)
    {
        var sec = new DirectoryInfo(directory).GetAccessControl(AccessControlSections.Owner);
        return (sec.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value;
    }
}
