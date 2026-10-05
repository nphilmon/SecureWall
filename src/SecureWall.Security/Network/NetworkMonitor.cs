using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Logic;
using SecureWall.Core.Models;
using SecureWall.Infrastructure.Windows;

namespace SecureWall.Security.Network;

/// <summary>Résout un PID en (nom, chemin) avec un cache court.</summary>
public sealed class ProcessIdentityCache
{
    readonly ConcurrentDictionary<int, (string Name, string Path, DateTime At)> _cache = new();

    public (string Name, string Path) Resolve(int pid)
    {
        if (_cache.TryGetValue(pid, out var c) && (DateTime.Now - c.At).TotalSeconds < 20) return (c.Name, c.Path);
        string name, path;
        if (pid == 0) { name = "Connexion en fermeture"; path = ""; }
        else if (pid == 4) { name = "System"; path = ""; }
        else
        {
            path = NativeProcess.GetImagePath(pid);
            name = !string.IsNullOrEmpty(path) ? System.IO.Path.GetFileName(path) : SafeName(pid);
        }
        _cache[pid] = (name, path, DateTime.Now);
        if (_cache.Count > 4000) foreach (var k in _cache.Where(kv => (DateTime.Now - kv.Value.At).TotalMinutes > 2).Select(kv => kv.Key).ToList()) _cache.TryRemove(k, out _);
        return (name, path);
    }

    static string SafeName(int pid)
    {
        try { using var p = Process.GetProcessById(pid); return p.ProcessName + ".exe"; } catch { return $"PID {pid}"; }
    }
}

/// <summary>
/// Moniteur réseau : connexions TCP/UDP par processus (IP Helper), débit global (statistiques des interfaces),
/// enregistrement des applications ayant utilisé le réseau et détection d'une première connexion externe.
/// Il observe : il ne bloque rien et n'intercepte aucun contenu.
/// </summary>
public sealed class NetworkMonitor : INetworkMonitor, IDisposable
{
    readonly IConnectionSource _source;
    readonly ISecurityStore _store;
    readonly ISettingsStore _settings;
    readonly ISignatureService _signatures;
    readonly ProcessIdentityCache _procs;
    readonly ILogger<NetworkMonitor>? _log;
    readonly IPrivilegedClient? _client;

    readonly object _lock = new();
    readonly List<NetworkSample> _history = new();
    readonly Dictionary<string, DateTime> _recorded = new();      // dédoublonnage des enregistrements de connexions
    readonly Dictionary<string, DateTime> _appTouched = new(StringComparer.OrdinalIgnoreCase);
    readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);

    IReadOnlyList<NetConnection> _snapshot = Array.Empty<NetConnection>();
    DateTime _snapshotTime = DateTime.MinValue;
    long _lastRx, _lastTx;
    DateTime _lastSampleTime;
    DateTime _learningUntil;
    readonly TimeSpan _learning;
    CancellationTokenSource? _cts;

    public NetworkSample? LastSample { get; private set; }
    public IReadOnlyList<NetworkSample> History { get { lock (_lock) return _history.ToList(); } }
    public event Action<NetworkAppInfo, NetConnection>? NewApplicationDetected;

    public NetworkMonitor(IConnectionSource source, ISecurityStore store, ISettingsStore settings, ISignatureService signatures,
        ProcessIdentityCache procs, IPrivilegedClient? client = null, ILogger<NetworkMonitor>? log = null, TimeSpan? learningPeriod = null)
    {
        _learning = learningPeriod ?? TimeSpan.FromSeconds(90);
        _learningUntil = DateTime.Now + _learning;
        _source = source; _store = store; _settings = settings; _signatures = signatures; _procs = procs; _client = client; _log = log;
    }

    public void Start()
    {
        if (_cts != null) return;
        _cts = new CancellationTokenSource();
        _learningUntil = DateTime.Now + _learning;   // phase d'apprentissage : pas d'alerte "nouvelle application" immédiate
        var ct = _cts.Token;
        _ = Task.Run(async () =>
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
            var cycle = 0;
            try
            {
                while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
                {
                    SampleThroughput();
                    cycle++;
                    var every = Math.Max(2, _settings.Current.RefreshSeconds);
                    if (cycle % every == 0)
                    {
                        try { await RefreshAsync(record: true, ct).ConfigureAwait(false); }
                        catch (Exception ex) when (ex is not OperationCanceledException) { _log?.LogWarning(ex, "Actualisation réseau"); }
                    }
                }
            }
            catch (OperationCanceledException) { /* arrêt */ }
        }, ct);
    }

    public void Stop()
    {
        _cts?.Cancel();
        _cts = null;
    }

    public void Dispose() => Stop();

    // ---------- Débit ----------
    void SampleThroughput()
    {
        long rx = 0, tx = 0;
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                var s = nic.GetIPv4Statistics();
                rx += s.BytesReceived; tx += s.BytesSent;
            }
        }
        catch { return; }

        var now = DateTime.Now;
        if (_lastSampleTime != default && rx >= _lastRx && tx >= _lastTx)
        {
            var dt = Math.Max(0.2, (now - _lastSampleTime).TotalSeconds);
            var sample = new NetworkSample { Time = now, DownBytesPerSec = (rx - _lastRx) / dt, UpBytesPerSec = (tx - _lastTx) / dt };
            lock (_lock)
            {
                _history.Add(sample);
                if (_history.Count > 180) _history.RemoveAt(0);
            }
            LastSample = sample;
        }
        _lastRx = rx; _lastTx = tx; _lastSampleTime = now;
    }

    // ---------- Connexions ----------
    public async Task<IReadOnlyList<NetConnection>> GetConnectionsAsync(CancellationToken ct = default)
    {
        if ((DateTime.Now - _snapshotTime).TotalMilliseconds < 1200) return _snapshot;
        return await RefreshAsync(record: false, ct).ConfigureAwait(false);
    }

    /// <summary>Une observation complète (lecture + enregistrement). Utilisée par la boucle de surveillance et par les tests.</summary>
    public Task<IReadOnlyList<NetConnection>> ObserveOnceAsync(CancellationToken ct = default) => RefreshAsync(record: true, ct);

    async Task<IReadOnlyList<NetConnection>> RefreshAsync(bool record, CancellationToken ct)
    {
        var conns = await Task.Run(() =>
        {
            var list = _source.Read().ToList();
            foreach (var c in list)
            {
                if (!string.IsNullOrEmpty(c.ProcessPath)) continue;   // déjà renseigné par la source
                var (name, path) = _procs.Resolve(c.Pid);
                c.ProcessName = name; c.ProcessPath = path;
            }
            return list;
        }, ct).ConfigureAwait(false);

        // Trafic par connexion (TCP IPv4) fourni par le service privilégié, si disponible.
        if (record && _client != null && conns.Any(c => c.IsEstablished && !c.RemoteAddress.Contains(':')))
        {
            try { await AttachTrafficAsync(conns, ct).ConfigureAwait(false); } catch (OperationCanceledException) { throw; } catch { /* optionnel */ }
        }

        _snapshot = conns;
        _snapshotTime = DateTime.Now;
        if (record && _settings.Current.RecordConnections) RecordApplications(conns);
        return conns;
    }

    DateTime _lastTraffic;
    Dictionary<string, TcpTraffic> _traffic = new();
    sealed record TcpTraffic(long Sent, long Received);

    async Task AttachTrafficAsync(List<NetConnection> conns, CancellationToken ct)
    {
        if ((DateTime.Now - _lastTraffic).TotalSeconds >= 5)
        {
            _lastTraffic = DateTime.Now;
            var r = await _client!.SendAsync(PrivilegedOperation.NetworkGetTcpTraffic, null, ct).ConfigureAwait(false);
            if (r.Success && !string.IsNullOrEmpty(r.Data))
            {
                var entries = System.Text.Json.JsonSerializer.Deserialize<List<SecureWall.Core.DTOs.TcpTrafficEntry>>(r.Data) ?? new();
                _traffic = entries.GroupBy(e => $"{e.LocalAddress}:{e.LocalPort}>{e.RemoteAddress}:{e.RemotePort}")
                    .ToDictionary(g => g.Key, g => new TcpTraffic(g.Max(x => x.BytesSent), g.Max(x => x.BytesReceived)));
            }
        }
        foreach (var c in conns.Where(c => c.IsEstablished))
            if (_traffic.TryGetValue($"{c.LocalAddress}:{c.LocalPort}>{c.RemoteAddress}:{c.RemotePort}", out var t))
            { c.BytesSent = t.Sent; c.BytesReceived = t.Received; }
    }

    void RecordApplications(IReadOnlyList<NetConnection> conns)
    {
        var now = DateTime.Now;
        var byApp = conns.Where(c => !c.IsListening && !string.IsNullOrEmpty(c.ProcessPath) && (c.IsEstablished || c.IsExternal || c.Protocol == "UDP"))
            .GroupBy(c => c.ProcessPath, StringComparer.OrdinalIgnoreCase);

        foreach (var g in byApp)
        {
            var path = g.Key;
            var first = g.First();
            var sig = _signatures.GetOrQueue(path);

            long appId;
            bool isNew = false;
            var needTouch = !_appTouched.TryGetValue(path, out var last) || (now - last).TotalSeconds > 30;
            if (needTouch)
            {
                appId = _store.UpsertApplication(first.ProcessName, path, sig.Publisher, sig.Status == SignatureStatus.Pending ? "" : sig.Status.ToString(), out isNew);
                _appTouched[path] = now;
            }
            else
            {
                var rec = _store.GetApplication(path);
                if (rec == null) continue;
                appId = rec.Id;
            }

            var rows = new List<ConnectionRecord>();
            foreach (var c in g.Where(c => c.IsEstablished && c.IsExternal))
            {
                var key = $"{path}|{c.Protocol}|{c.RemoteAddress}|{c.RemotePort}";
                if (_recorded.TryGetValue(key, out var t) && (now - t).TotalMinutes < 10) continue;
                _recorded[key] = now;
                rows.Add(new ConnectionRecord
                {
                    Protocol = c.Protocol, LocalAddress = c.LocalAddress, LocalPort = c.LocalPort,
                    RemoteAddress = c.RemoteAddress, RemotePort = c.RemotePort, State = c.State, Timestamp = now,
                });
            }
            if (rows.Count > 0) _store.AddConnections(appId, rows);

            if (isNew && now > _learningUntil && g.Any(c => c.IsExternal && c.IsEstablished)
                && !CriticalProcessPolicy.IsCriticalWindowsComponent(path) && _alerted.Add(path))
            {
                var info = new NetworkAppInfo
                {
                    ApplicationId = appId, Name = first.ProcessName, Path = path, Publisher = sig.Publisher, Signature = sig,
                    FirstSeen = now, LastSeen = now,
                };
                NewApplicationDetected?.Invoke(info, g.First(c => c.IsExternal && c.IsEstablished));
            }
        }

        if (_recorded.Count > 20000)
            foreach (var k in _recorded.Where(kv => (now - kv.Value).TotalMinutes > 30).Select(kv => kv.Key).ToList()) _recorded.Remove(k);
    }
}
