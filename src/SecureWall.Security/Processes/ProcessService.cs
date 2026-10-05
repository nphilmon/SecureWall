using System.Diagnostics;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Logic;
using SecureWall.Core.Models;
using SecureWall.Infrastructure.Windows;

namespace SecureWall.Security.Processes;

/// <summary>Liste des processus avec chemin, utilisateur, CPU, mémoire, signature et connexions réseau.</summary>
public sealed class ProcessService : IProcessService
{
    readonly ISignatureService _signatures;
    readonly INetworkMonitor _network;
    readonly Dictionary<int, (TimeSpan Cpu, DateTime At)> _previous = new();
    readonly Dictionary<int, string> _owners = new();

    public ProcessService(ISignatureService signatures, INetworkMonitor network)
    {
        _signatures = signatures; _network = network;
    }

    public async Task<IReadOnlyList<ProcessEntry>> GetProcessesAsync(CancellationToken ct = default)
    {
        var conns = await _network.GetConnectionsAsync(ct).ConfigureAwait(false);
        var perPid = conns.Where(c => !c.IsListening).GroupBy(c => c.Pid).ToDictionary(g => g.Key, g => g.Count());
        return await Task.Run(() => Build(perPid, ct), ct).ConfigureAwait(false);
    }

    List<ProcessEntry> Build(Dictionary<int, int> connections, CancellationToken ct)
    {
        var now = DateTime.Now;
        var cores = Environment.ProcessorCount;
        var list = new List<ProcessEntry>(300);
        var alive = new HashSet<int>();

        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                ct.ThrowIfCancellationRequested();
                var pid = p.Id;
                alive.Add(pid);
                var path = NativeProcess.GetImagePath(pid);

                double cpu = 0;
                try
                {
                    var total = p.TotalProcessorTime;
                    if (_previous.TryGetValue(pid, out var prev) && now > prev.At)
                        cpu = Math.Clamp((total - prev.Cpu).TotalMilliseconds / ((now - prev.At).TotalMilliseconds * cores) * 100, 0, 100);
                    _previous[pid] = (total, now);
                }
                catch { /* accès refusé (processus protégé) */ }

                DateTime? start = null;
                try { start = p.StartTime; } catch { }

                if (!_owners.TryGetValue(pid, out var owner)) { owner = NativeProcess.GetOwner(pid); _owners[pid] = owner; }

                double mem = 0;
                try { mem = p.WorkingSet64 / 1048576.0; } catch { }

                list.Add(new ProcessEntry
                {
                    Name = pid == 0 ? "Inactif système" : string.IsNullOrEmpty(path) ? p.ProcessName : Path.GetFileName(path),
                    Pid = pid, User = owner, Path = path, Cpu = cpu, MemoryMb = mem, StartTime = start,
                    Connections = connections.TryGetValue(pid, out var n) ? n : 0,
                    UnusualLocation = CriticalProcessPolicy.IsUnusualLocation(path),
                    Signature = string.IsNullOrEmpty(path) ? new SignatureInfo { Status = Core.Enums.SignatureStatus.Unknown, Detail = "Processus système sans fichier accessible" } : _signatures.GetOrQueue(path),
                });
            }
        }
        foreach (var k in _previous.Keys.Where(k => !alive.Contains(k)).ToList()) { _previous.Remove(k); _owners.Remove(k); }
        return list;
    }
}
