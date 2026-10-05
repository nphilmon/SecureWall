using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using SecureWall.Core.DTOs;
using SecureWall.Infrastructure.Configuration;
using SecureWall.Infrastructure.Windows;

namespace SecureWall.PrivilegedService;

/// <summary>Serveur de tube nommé local. Chaque connexion : authentification du client → lecture bornée → validation → exécution → réponse.</summary>
public sealed class PipeServerWorker : BackgroundService
{
    /// <summary>Connexions traitées en même temps. Au-delà, la connexion est coupée aussitôt : un client malveillant ne peut pas saturer le service.</summary>
    public const int MaxConcurrentConnections = 16;
    static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(10);
    static readonly TimeSpan DeniedReadTimeout = TimeSpan.FromSeconds(2);

    readonly ILogger<PipeServerWorker> _log;
    readonly RequestDispatcher _dispatcher;
    readonly ClientAuthenticator _auth;
    readonly SemaphoreSlim _slots = new(MaxConcurrentConnections, MaxConcurrentConnections);
    DateTime _lastSaturationLog = DateTime.MinValue;

    public PipeServerWorker(ILogger<PipeServerWorker> log, RequestDispatcher dispatcher, ClientAuthenticator auth)
    {
        _log = log; _dispatcher = dispatcher; _auth = auth;
    }

    /// <summary>
    /// ACL du tube : SYSTEM et administrateurs ont le contrôle total ; les utilisateurs authentifiés peuvent seulement se connecter et
    /// lire/écrire (PAS de création d'instance : un utilisateur ne peut pas ouvrir un faux serveur sous le même nom) ; aucun accès réseau.
    /// </summary>
    public static PipeSecurity BuildSecurity()
    {
        var sec = new PipeSecurity();
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        return sec;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation("Service privilégié démarré (v{Version}), tube « {Pipe} ».", typeof(PipeServerWorker).Assembly.GetName().Version, AppPaths.PipeName);

        var security = BuildSecurity();
        var first = true;   // la toute première instance doit créer le tube : s'il existe déjà, quelqu'un d'autre l'occupe
        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                var options = PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None);
                pipe = NamedPipeServerStreamAcl.Create(AppPaths.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte,
                    options, 64 * 1024, 64 * 1024, security);
                first = false;
                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);

                if (!_slots.Wait(0))
                {
                    if (DateTime.UtcNow - _lastSaturationLog > TimeSpan.FromSeconds(30))
                    {
                        _lastSaturationLog = DateTime.UtcNow;
                        _log.LogWarning("Trop de connexions simultanées ({Max}) : connexion refusée.", MaxConcurrentConnections);
                    }
                    continue;   // `finally` ferme la connexion
                }
                var p = pipe;
                pipe = null;
                _ = Task.Run(async () =>
                {
                    try { await HandleAsync(p, stoppingToken).ConfigureAwait(false); }
                    finally { _slots.Release(); }
                }, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) when (first && ex is UnauthorizedAccessException or IOException)
            {
                // Le nom du tube est déjà pris : un autre processus occupe la place du service (ou une instance précédente n'est pas fermée).
                _log.LogCritical(ex, "Le tube « {Pipe} » existe déjà : un autre processus l'occupe. Nouvel essai dans 5 s.", AppPaths.PipeName);
                await Task.Delay(5000, stoppingToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Erreur du serveur de tube");
                await Task.Delay(1000, stoppingToken).ConfigureAwait(false);
            }
            finally { pipe?.Dispose(); }
        }
    }

    async Task HandleAsync(NamedPipeServerStream pipe, CancellationToken stop)
    {
        await using (pipe)
        {
            string requestId = "";
            try
            {
                var auth = _auth.Authenticate(pipe);
                // Un client refusé n'a droit qu'à une courte attente : il ne peut pas monopoliser un emplacement.
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(stop);
                cts.CancelAfter(auth.Allowed ? ReadTimeout : DeniedReadTimeout);
                var req = await PipeFraming.ReadAsync<PipeRequest>(pipe, cts.Token).ConfigureAwait(false);
                if (req == null) return;
                requestId = req.Id ?? "";
                _log.LogDebug("Requête {Op} de {User} (authentification : {Reason})", req.Operation, auth.UserName, auth.Reason);

                PipeResponse resp;
                if (!auth.Allowed)
                {
                    _log.LogWarning("Client refusé ({Reason}) pour l'opération {Op}.", auth.Reason, req.Operation);
                    resp = PipeResponse.Fail(requestId, "denied", "Accès refusé : client non autorisé.");
                }
                else
                {
                    using var work = CancellationTokenSource.CreateLinkedTokenSource(stop);
                    work.CancelAfter(TimeSpan.FromMinutes(3));
                    resp = await _dispatcher.DispatchAsync(req, auth.UserName, work.Token).ConfigureAwait(false);
                }
                await PipeFraming.WriteAsync(pipe, resp, stop).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { /* arrêt ou délai */ }
            catch (Exception ex) when (ex is IOException or InvalidDataException or System.Text.Json.JsonException)
            {
                _log.LogWarning("Requête malformée ou connexion interrompue : {Message}", ex.Message);
                try { await PipeFraming.WriteAsync(pipe, PipeResponse.Fail(requestId, "bad-request", "Requête invalide."), stop).ConfigureAwait(false); } catch { /* client parti */ }
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Erreur de traitement");
            }
        }
    }
}
