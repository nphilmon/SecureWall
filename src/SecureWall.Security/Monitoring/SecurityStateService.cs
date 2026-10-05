using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Logic;
using SecureWall.Core.Models;
using SecureWall.Security.Firewall;

namespace SecureWall.Security.Monitoring;


    /// <summary>Met en cache et diffuse l'état global (rafraîchi périodiquement) pour le tableau de bord, la barre d'état et le centre de sécurité.</summary>
    public sealed class SecurityStateService : IDisposable
    {
        readonly IDefenderService _defender;
        readonly IFirewallService _firewall;
        readonly IFirewallRuleService _rules;
        readonly INetworkProfileService _networks;
        readonly ISecurityStore _store;
        readonly IPrivilegedClient _client;
        readonly ISettingsStore _settings;
        readonly SemaphoreSlim _gate = new(1, 1);
        CancellationTokenSource? _cts;

        public SecuritySummary Current { get; private set; } = new();
        public event Action<SecuritySummary>? Changed;

        public SecurityStateService(IDefenderService defender, IFirewallService firewall, IFirewallRuleService rules, INetworkProfileService networks,
            ISecurityStore store, IPrivilegedClient client, ISettingsStore settings)
        {
            _defender = defender; _firewall = firewall; _rules = rules; _networks = networks; _store = store; _client = client; _settings = settings;
        }

        public void Start()
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
            _ = Task.Run(async () =>
            {
                using var timer = new PeriodicTimer(TimeSpan.FromSeconds(20));
                try
                {
                    await RefreshAsync(ct).ConfigureAwait(false);
                    while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false)) await RefreshAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { /* arrêt */ }
            }, ct);
        }

        public void Dispose() { _cts?.Cancel(); _cts = null; }

        public async Task<SecuritySummary> RefreshAsync(CancellationToken ct = default)
        {
            await _gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var statusT = _defender.GetStatusAsync(ct);
                var historyT = _defender.GetProtectionHistoryAsync(ct);
                var profilesT = _firewall.GetProfilesAsync(ct);
                var rulesT = SafeAsync(() => _rules.GetRulesAsync(ct), (IReadOnlyList<FirewallRule>)Array.Empty<FirewallRule>());
                var netT = _networks.GetNetworkProfilesAsync(ct);
                var svcT = _client.IsAvailableAsync(ct);
                await Task.WhenAll(statusT, historyT, profilesT, rulesT, netT, svcT).ConfigureAwait(false);

                var status = statusT.Result;
                var history = historyT.Result;
                var profiles = profilesT.Result;
                var current = profiles.Where(p => p.IsCurrent).ToList();
                var fwOk = current.Count > 0 ? current.All(p => p.Enabled) : profiles.All(p => p.Enabled);
                var state = GlobalStateEvaluator.Evaluate(status, history, fwOk, _settings.Current.SignatureMaxAgeDays, out var reasons);

                var emergency = false;
                DateTime? autoRestoreAt = null;
                if (svcT.Result)
                {
                    var r = await _client.SendAsync(PrivilegedOperation.EmergencyStatus, null, ct).ConfigureAwait(false);
                    if (r.Success && !string.IsNullOrEmpty(r.Data))
                    {
                        try
                        {
                            var es = System.Text.Json.JsonSerializer.Deserialize<SecureWall.Core.DTOs.EmergencyState>(r.Data);
                            emergency = es?.Active == true;
                            autoRestoreAt = emergency ? es!.AutoRestoreAt : null;
                        }
                        catch (System.Text.Json.JsonException) { emergency = r.Data.Contains("\"Active\":true"); }
                    }
                }
                else emergency = rulesT.Result.Any(x => x.Group == RuleGroups.Emergency && x.Enabled);

                Current = new SecuritySummary
                {
                    Defender = status, State = state, Reasons = reasons,
                    TotalDetections = history.Count,
                    ActiveThreats = history.Count(t => t.IsActive || t.StatusId == 1),
                    QuarantineCount = history.Count(t => t.IsQuarantined),
                    Profiles = profiles, FirewallProtected = fwOk,
                    TotalRules = rulesT.Result.Count, ActiveRules = rulesT.Result.Count(r => r.Enabled),
                    BlockedLast24h = _store.CountBlocked(DateTime.Now.AddHours(-24)),
                    ServiceAvailable = svcT.Result, EmergencyActive = emergency, EmergencyAutoRestoreAt = autoRestoreAt,
                    Networks = netT.Result, Updated = DateTime.Now,
                };
                Changed?.Invoke(Current);
                return Current;
            }
            finally { _gate.Release(); }
        }

        static async Task<T> SafeAsync<T>(Func<Task<T>> f, T fallback)
        {
            try { return await f().ConfigureAwait(false); } catch (OperationCanceledException) { throw; } catch { return fallback; }
        }
    }
