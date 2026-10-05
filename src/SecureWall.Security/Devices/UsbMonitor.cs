using Microsoft.Extensions.Logging;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Models;
using SecureWall.Infrastructure.Windows;

namespace SecureWall.Security.Devices;

/// <summary>
/// Détecte l'insertion de supports amovibles (clés et disques USB). Ne bloque jamais un périphérique :
/// il informe, mémorise les périphériques connus et propose (ou lance, selon le réglage) une analyse Microsoft Defender.
/// </summary>
public sealed class UsbMonitor : IUsbMonitor, IDisposable
{
    readonly ISecurityStore _store;
    readonly ILogger<UsbMonitor>? _log;
    readonly object _lock = new();
    readonly Dictionary<string, UsbDevice> _connected = new(StringComparer.OrdinalIgnoreCase);
    HashSet<string> _letters = new(StringComparer.OrdinalIgnoreCase);
    CancellationTokenSource? _cts;
    bool _first = true;

    public IReadOnlyList<UsbDevice> Connected { get { lock (_lock) return _connected.Values.ToList(); } }
    public event Action<UsbDevice>? DeviceConnected;
    public event Action<string>? DeviceRemoved;

    public UsbMonitor(ISecurityStore store, ILogger<UsbMonitor>? log = null)
    {
        _store = store; _log = log;
    }

    public void Start()
    {
        if (_cts != null) return;
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        _ = Task.Run(async () =>
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(3));
            try
            {
                Poll();
                while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false)) Poll();
            }
            catch (OperationCanceledException) { /* arrêt */ }
        }, ct);
    }

    public void Stop() { _cts?.Cancel(); _cts = null; }
    public void Dispose() => Stop();

    void Poll()
    {
        try
        {
            var now = DriveInfo.GetDrives()
                .Where(d => d.DriveType is DriveType.Removable or DriveType.Fixed)
                .Select(d => d.Name.TrimEnd('\\'))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var added = now.Except(_letters).ToList();
            var removed = _letters.Except(now).ToList();
            _letters = now;

            foreach (var letter in removed)
            {
                bool had;
                lock (_lock) had = _connected.Remove(letter);
                if (had) DeviceRemoved?.Invoke(letter);
            }

            foreach (var letter in added)
            {
                var dev = Classify(letter);
                if (dev == null) continue;
                var existing = _store.GetDevice(dev.Identifier);
                dev.IsNew = existing == null;
                dev.LastScan = existing?.LastScanDate;
                _store.SeenDevice(dev.DisplayName, dev.Identifier);
                lock (_lock) _connected[letter] = dev;
                if (!_first) DeviceConnected?.Invoke(dev);
            }
            _first = false;
        }
        catch (Exception ex) { _log?.LogDebug(ex, "Interrogation des lecteurs"); }
    }

    /// <summary>Retourne le périphérique si le volume est porté par un disque USB / amovible, sinon null.</summary>
    static UsbDevice? Classify(string letter)
    {
        try
        {
            var disk = Wmi.Query(@"root\cimv2", $"SELECT * FROM Win32_LogicalDisk WHERE DeviceID='{letter}'").FirstOrDefault();
            if (disk == null) return null;
            var driveType = disk.Long("DriveType");

            string model = "", pnp = "", iface = "", media = "";
            foreach (var part in Wmi.Query(@"root\cimv2", $"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{letter}'}} WHERE AssocClass=Win32_LogicalDiskToPartition"))
            {
                var pid = part.Str("DeviceID").Replace("'", "''");
                foreach (var dd in Wmi.Query(@"root\cimv2", $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{pid}'}} WHERE AssocClass=Win32_DiskDriveToDiskPartition"))
                {
                    model = dd.Str("Model"); pnp = dd.Str("PNPDeviceID"); iface = dd.Str("InterfaceType"); media = dd.Str("MediaType");
                }
            }

            var isUsb = iface.Equals("USB", StringComparison.OrdinalIgnoreCase) || pnp.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase);
            var removable = driveType == 2 || media.Contains("Removable", StringComparison.OrdinalIgnoreCase);
            if (!isUsb && !removable) return null;

            return new UsbDevice
            {
                DriveLetter = letter, Label = disk.Str("VolumeName"), Model = model,
                Identifier = $"{(pnp.Length > 0 ? pnp : model)}|{disk.Str("VolumeSerialNumber")}",
                SizeBytes = disk.Long("Size"),
                Type = isUsb ? (driveType == 2 ? "Clé USB / stockage amovible" : "Disque USB externe") : "Stockage amovible",
                InsertedAt = DateTime.Now,
            };
        }
        catch { return null; }
    }
}
