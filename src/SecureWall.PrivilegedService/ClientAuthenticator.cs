using System.IO.Pipes;
using SecureWall.Infrastructure.Configuration;
using SecureWall.Infrastructure.Windows;
using SecureWall.Security.Hardening;

namespace SecureWall.PrivilegedService;

public sealed record AuthResult(bool Allowed, string UserName, string Reason);

/// <summary>
/// Authentifie le client d'un tube : (1) le propriétaire du processus client (jeton Windows) doit être un compte réel, jamais anonyme ;
/// (2) le processus client doit être SecureWall.exe installé dans le même dossier que le service (dossier protégé en écriture par Windows).
/// Les connexions réseau sont déjà refusées par l'ACL du tube. Aucun emprunt d'identité n'est utilisé.
/// </summary>
public sealed class ClientAuthenticator
{
    readonly string _expectedClient = Path.Combine(AppContext.BaseDirectory, AppPaths.AppExeName);
    readonly ILogger<ClientAuthenticator> _log;
    readonly bool _devMode = false;   // vrai uniquement dans les builds Debug avec SECUREWALL_DEV=1
    readonly FolderTrustResult _installTrust = FolderTrustResult.Ok;

    /// <param name="installCheck">Vérification du dossier d'installation (remplaçable dans les tests). Par défaut : droits réels du dossier du service.</param>
    public ClientAuthenticator(ILogger<ClientAuthenticator> log, Func<FolderTrustResult>? installCheck = null)
    {
        _log = log;
#if DEBUG
        _devMode = Environment.GetEnvironmentVariable("SECUREWALL_DEV") == "1";
        if (_devMode) log.LogWarning("MODE DÉVELOPPEMENT : le chemin du client n'est pas vérifié.");
#endif
        if (!_devMode)
        {
            // Le chemin du client n'a de valeur que si personne d'autre qu'un administrateur ne peut remplacer SecureWall.exe.
            _installTrust = (installCheck ?? (() => FolderTrust.CheckDirectory(AppContext.BaseDirectory)))();
            if (!_installTrust.Trusted)
                log.LogCritical("Dossier d'installation non fiable : toutes les requêtes seront refusées. {Reason} Réinstallez SecureWall dans « Program Files ».", _installTrust.Reason);
        }
    }

    /// <summary>État de la vérification du dossier d'installation (affiché par GetServiceInfo).</summary>
    public FolderTrustResult InstallTrust => _installTrust;

    public AuthResult Authenticate(NamedPipeServerStream pipe)
    {
        try
        {
            if (!_installTrust.Trusted) return new AuthResult(false, "?", "dossier d'installation non fiable : " + _installTrust.Reason);
            var pid = NativeProcess.GetPipeClientPid(pipe.SafePipeHandle);
            if (pid <= 0) return new AuthResult(false, "?", "PID client introuvable");

            var user = NativeProcess.GetOwner(pid);
            if (string.IsNullOrEmpty(user) || user == "—" || user.StartsWith("NT AUTHORITY\\ANONYMOUS", StringComparison.OrdinalIgnoreCase))
                return new AuthResult(false, user ?? "?", "propriétaire du processus client indéterminé");

            if (_devMode) return new AuthResult(true, user, "dev");

            var path = NativeProcess.GetImagePath(pid);
            if (!string.Equals(path, _expectedClient, StringComparison.OrdinalIgnoreCase))
                return new AuthResult(false, user, $"binaire client inattendu ({(string.IsNullOrEmpty(path) ? "illisible" : path)})");
            return new AuthResult(true, user, "ok");
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Authentification impossible");
            return new AuthResult(false, "?", "erreur d'authentification");
        }
    }
}
