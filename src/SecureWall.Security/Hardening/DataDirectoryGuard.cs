using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SecureWall.Security.Hardening;

/// <summary>
/// Protège le dossier de données du service (ProgramData\SecureWall : journaux, sauvegardes du pare-feu, état du mode urgence).
/// SYSTEM écrit dans ce dossier : si un utilisateur standard en était propriétaire (dossier créé avant l'installation) ou pouvait y déposer des
/// fichiers, il pourrait rediriger ces écritures ou imposer une « sauvegarde » du pare-feu piégée. Le garde (1) écarte un dossier dont le
/// propriétaire n'est pas fiable, (2) applique des droits stricts, (3) supprime les fichiers appartenant à un compte non fiable, (4) renvoie
/// chaque anomalie pour qu'elle soit journalisée (rien n'est avalé en silence). Il s'exécute avant l'ouverture du moindre journal.
/// </summary>
[SupportedOSPlatform("windows")]
public static class DataDirectoryGuard
{
    static SecurityIdentifier Sid(WellKnownSidType t) => new(t, null);

    static DirectorySecurity Base()
    {
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(Sid(WellKnownSidType.LocalSystemSid), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(Sid(WellKnownSidType.BuiltinAdministratorsSid), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        return sec;
    }

    /// <summary>Racine et journaux : SYSTEM et administrateurs ont tous les droits, les utilisateurs peuvent seulement lire (diagnostic).</summary>
    public static DirectorySecurity BuildSharedReadSecurity()
    {
        var sec = Base();
        sec.AddAccessRule(new FileSystemAccessRule(Sid(WellKnownSidType.BuiltinUsersSid), FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        return sec;
    }

    /// <summary>Sauvegardes du pare-feu : réservées à SYSTEM et aux administrateurs (l'interface passe par le service).</summary>
    public static DirectorySecurity BuildPrivateSecurity() => Base();

    /// <summary>
    /// Prépare le dossier de données. Retourne la liste des anomalies rencontrées (corrigées ou non) pour le journal.
    /// </summary>
    public static IReadOnlyList<string> Secure(string root, string backupsDir, string logsDir)
    {
        var warnings = new List<string>();
        try { QuarantineIfUntrusted(root, warnings); }
        catch (Exception ex) { warnings.Add($"Dossier de données : vérification du propriétaire impossible ({ex.Message})."); }

        foreach (var d in new[] { root, backupsDir, logsDir })
        {
            try { Directory.CreateDirectory(d); }
            catch (Exception ex) { warnings.Add($"Création du dossier « {d} » impossible : {ex.Message}"); }
        }

        Apply(root, BuildSharedReadSecurity(), warnings);
        Apply(logsDir, BuildSharedReadSecurity(), warnings);
        Apply(backupsDir, BuildPrivateSecurity(), warnings);

        PurgeUntrustedFiles(root, warnings, recursive: false);
        PurgeUntrustedFiles(backupsDir, warnings, recursive: false);
        return warnings;
    }

    /// <summary>Si le dossier existe et n'appartient pas à un compte fiable, il est déplacé de côté (jamais réutilisé) et un dossier neuf est créé ensuite.</summary>
    public static bool QuarantineIfUntrusted(string root, List<string> warnings)
    {
        if (!Directory.Exists(root)) return false;
        var owner = FolderTrust.OwnerSid(root);
        if (FolderTrust.IsTrustedOwner(owner)) return false;
        var aside = $"{root}.untrusted-{DateTime.Now:yyyyMMddHHmmss}";
        Directory.Move(root, aside);
        warnings.Add($"Le dossier de données appartenait à un compte non fiable ({owner ?? "inconnu"}) : déplacé vers « {aside} » et recréé. Examinez-le puis supprimez-le.");
        return true;
    }

    static void Apply(string dir, DirectorySecurity sec, List<string> warnings)
    {
        try { new DirectoryInfo(dir).SetAccessControl(sec); }
        catch (Exception ex) { warnings.Add($"Droits du dossier « {dir} » non appliqués : {ex.Message}"); }
    }

    /// <summary>Supprime les fichiers dont le propriétaire n'est pas fiable (déposés par un utilisateur standard) ; retourne leur nombre.</summary>
    public static int PurgeUntrustedFiles(string dir, List<string> warnings, bool recursive)
    {
        if (!Directory.Exists(dir)) return 0;
        var removed = 0;
        foreach (var file in Directory.EnumerateFiles(dir, "*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly))
        {
            try
            {
                var owner = (new FileInfo(file).GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value;
                if (FolderTrust.IsTrustedOwner(owner)) continue;
                File.Delete(file);
                removed++;
                warnings.Add($"Fichier supprimé car déposé par un compte non fiable ({owner ?? "inconnu"}) : {Path.GetFileName(file)}");
            }
            catch (Exception ex) { warnings.Add($"Vérification de « {Path.GetFileName(file)} » impossible : {ex.Message}"); }
        }
        return removed;
    }
}
