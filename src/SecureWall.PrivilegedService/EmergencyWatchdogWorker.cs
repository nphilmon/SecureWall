using SecureWall.Security.Firewall;

namespace SecureWall.PrivilegedService;

/// <summary>
/// Rétablit Internet à l'heure choisie par l'utilisateur lors de la coupure. L'échéance est dans le fichier d'état :
/// elle survit à un redémarrage du service ou de l'ordinateur (vérifiée dès le démarrage).
/// </summary>
public sealed class EmergencyWatchdogWorker : BackgroundService
{
    static readonly TimeSpan Interval = TimeSpan.FromSeconds(15);
    readonly EmergencyExecutor _emergency;
    readonly ILogger<EmergencyWatchdogWorker> _log;

    public EmergencyWatchdogWorker(EmergencyExecutor emergency, ILogger<EmergencyWatchdogWorker> log)
    {
        _emergency = emergency; _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (_emergency.RestoreIfExpired())
                    _log.LogInformation("Mode urgence : délai écoulé, connexions Internet rétablies automatiquement.");
            }
            catch (Exception ex) { _log.LogError(ex, "Rétablissement automatique d'Internet : échec (nouvel essai dans {Seconds} s).", Interval.TotalSeconds); }
            try { await Task.Delay(Interval, stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }
}
