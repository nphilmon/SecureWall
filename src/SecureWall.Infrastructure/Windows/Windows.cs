using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace SecureWall.Infrastructure.Windows;

public static class Elevation
{
    public static bool IsAdmin
    {
        get
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}

public sealed record RunResult(int ExitCode, string Output, string Error, bool TimedOut = false, bool Cancelled = false)
{
    public bool Ok => ExitCode == 0 && !TimedOut && !Cancelled;
}

public static class ProcessRunner
{
    /// <summary>Lance un exécutable avec une liste d'arguments (jamais de chaîne interprétée par un shell).</summary>
    public static async Task<RunResult> RunAsync(string file, IEnumerable<string> args, CancellationToken ct = default,
        TimeSpan? timeout = null, Action<Process>? onStart = null)
    {
        var psi = new ProcessStartInfo(file)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var p = new Process { StartInfo = psi };
        var sbOut = new StringBuilder();
        var sbErr = new StringBuilder();
        p.OutputDataReceived += (_, e) => { if (e.Data != null) lock (sbOut) sbOut.AppendLine(e.Data); };
        p.ErrorDataReceived += (_, e) => { if (e.Data != null) lock (sbErr) sbErr.AppendLine(e.Data); };

        try { p.Start(); }
        catch (Exception ex) { return new RunResult(-1, "", ex.Message); }
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        onStart?.Invoke(p);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (timeout is { } t) cts.CancelAfter(t);
        try
        {
            await p.WaitForExitAsync(cts.Token).ConfigureAwait(false);
            p.WaitForExit();
        }
        catch (OperationCanceledException)
        {
            try { p.Kill(entireProcessTree: true); } catch { /* déjà terminé */ }
            return new RunResult(-1, sbOut.ToString(), sbErr.ToString(), TimedOut: !ct.IsCancellationRequested, Cancelled: ct.IsCancellationRequested);
        }
        return new RunResult(p.ExitCode, sbOut.ToString(), sbErr.ToString());
    }
}

/// <summary>Exécute des cmdlets officielles (Defender, NetAdapter…). Les valeurs variables passent TOUJOURS par <see cref="Quote"/>.</summary>
public static class PowerShell
{
    public static string Quote(string s) => "'" + s.Replace("'", "''") + "'";

    public static Task<RunResult> RunAsync(string script, CancellationToken ct = default, TimeSpan? timeout = null)
    {
        var full = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + script;
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(full));
        return ProcessRunner.RunAsync("powershell.exe",
            new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded }, ct, timeout ?? TimeSpan.FromMinutes(2));
    }
}

public static class Wmi
{
    public const string DefenderScope = @"root\Microsoft\Windows\Defender";

    public static List<Dictionary<string, object?>> Query(string scope, string wql)
    {
        var rows = new List<Dictionary<string, object?>>();
        using var searcher = new ManagementObjectSearcher(scope, wql);
        using var coll = searcher.Get();
        foreach (ManagementBaseObject o in coll)
        {
            using (o)
            {
                var d = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                foreach (PropertyData p in o.Properties) d[p.Name] = p.Value;
                rows.Add(d);
            }
        }
        return rows;
    }

    public static bool Bool(this Dictionary<string, object?> d, string key) => d.TryGetValue(key, out var v) && v is bool b && b;

    public static string Str(this Dictionary<string, object?> d, string key) =>
        d.TryGetValue(key, out var v) && v != null ? v.ToString() ?? "" : "";

    public static long Long(this Dictionary<string, object?> d, string key)
    {
        if (!d.TryGetValue(key, out var v) || v == null) return 0;
        try { return Convert.ToInt64(v); } catch { return 0; }
    }

    public static string[] Arr(this Dictionary<string, object?> d, string key) =>
        d.TryGetValue(key, out var v) && v is string[] a ? a : Array.Empty<string>();

    public static DateTime? Date(this Dictionary<string, object?> d, string key)
    {
        if (!d.TryGetValue(key, out var v) || v == null) return null;
        try
        {
            var dt = v is DateTime x ? x : ManagementDateTimeConverter.ToDateTime(v.ToString()!);
            return dt.Year < 2000 ? null : dt;
        }
        catch { return null; }
    }
}

public static class NativeProcess
{
    const uint ProcessQueryLimitedInformation = 0x1000;
    const uint TokenQuery = 0x0008;

    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint pid);

    public static string GetImagePath(int pid)
    {
        if (pid <= 4) return "";
        var h = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (h == IntPtr.Zero) return "";
        try
        {
            var sb = new StringBuilder(1024);
            var size = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : "";
        }
        finally { CloseHandle(h); }
    }

    public static string GetOwner(int pid)
    {
        if (pid <= 4) return "SYSTEM";
        var h = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (h == IntPtr.Zero) return "—";
        try
        {
            if (!OpenProcessToken(h, TokenQuery, out var token)) return "—";
            try { using var id = new WindowsIdentity(token); return id.Name; }
            finally { CloseHandle(token); }
        }
        catch { return "—"; }
        finally { CloseHandle(h); }
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr OpenSCManager(string? machine, string? db, uint access);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr OpenService(IntPtr scm, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool QueryServiceStatusEx(IntPtr svc, int level, IntPtr buf, int size, out int needed);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool QueryServiceConfig(IntPtr svc, IntPtr buf, int size, out int needed);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool CloseServiceHandle(IntPtr h);

    /// <summary>
    /// PID et exécutable d'un service d'après le gestionnaire de services : un utilisateur standard ne peut pas
    /// ouvrir le processus d'un service SYSTEM (GetImagePath échoue), mais il peut interroger le SCM.
    /// </summary>
    public static (int Pid, string ImagePath) GetServiceInfo(string serviceName)
    {
        const uint ScManagerConnect = 0x0001, ServiceQueryConfig = 0x0001, ServiceQueryStatus = 0x0004;
        var scm = OpenSCManager(null, null, ScManagerConnect);
        if (scm == IntPtr.Zero) return (-1, "");
        try
        {
            var svc = OpenService(scm, serviceName, ServiceQueryConfig | ServiceQueryStatus);
            if (svc == IntPtr.Zero) return (-1, "");
            try
            {
                var pid = -1;
                var buf = Marshal.AllocHGlobal(256);
                try
                {
                    // SERVICE_STATUS_PROCESS : dwProcessId est le 8e DWORD.
                    if (QueryServiceStatusEx(svc, 0, buf, 256, out _)) pid = Marshal.ReadInt32(buf, 7 * 4);
                }
                finally { Marshal.FreeHGlobal(buf); }

                QueryServiceConfig(svc, IntPtr.Zero, 0, out var needed);
                if (needed <= 0) return (pid, "");
                var cfg = Marshal.AllocHGlobal(needed);
                try
                {
                    if (!QueryServiceConfig(svc, cfg, needed, out _)) return (pid, "");
                    // QUERY_SERVICE_CONFIG : 3 DWORD (+ remplissage 64 bits) puis lpBinaryPathName.
                    var ptr = Marshal.ReadIntPtr(cfg, IntPtr.Size == 8 ? 16 : 12);
                    var raw = Marshal.PtrToStringUni(ptr) ?? "";
                    return (pid, ExtractExePath(raw));
                }
                finally { Marshal.FreeHGlobal(cfg); }
            }
            finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }

    static string ExtractExePath(string commandLine)
    {
        var s = commandLine.Trim();
        if (s.StartsWith('"')) { var end = s.IndexOf('"', 1); return end > 0 ? s[1..end] : s.Trim('"'); }
        var exe = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exe > 0 ? s[..(exe + 4)] : s;
    }

    public static int GetPipeClientPid(Microsoft.Win32.SafeHandles.SafePipeHandle h) =>
        GetNamedPipeClientProcessId(h.DangerousGetHandle(), out var pid) ? (int)pid : -1;

    public static int GetPipeServerPid(Microsoft.Win32.SafeHandles.SafePipeHandle h) =>
        GetNamedPipeServerProcessId(h.DangerousGetHandle(), out var pid) ? (int)pid : -1;
}

public static class ShellActions
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    struct SHELLEXECUTEINFO
    {
        public int cbSize;
        public uint fMask;
        public IntPtr hwnd;
        [MarshalAs(UnmanagedType.LPTStr)] public string lpVerb;
        [MarshalAs(UnmanagedType.LPTStr)] public string lpFile;
        [MarshalAs(UnmanagedType.LPTStr)] public string? lpParameters;
        [MarshalAs(UnmanagedType.LPTStr)] public string? lpDirectory;
        public int nShow;
        public IntPtr hInstApp;
        public IntPtr lpIDList;
        [MarshalAs(UnmanagedType.LPTStr)] public string? lpClass;
        public IntPtr hkeyClass;
        public uint dwHotKey;
        public IntPtr hIconOrMonitor;
        public IntPtr hProcess;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    static extern bool ShellExecuteEx(ref SHELLEXECUTEINFO info);

    /// <summary>Boîte de dialogue "Propriétés" de l'Explorateur Windows.</summary>
    public static void ShowProperties(string path)
    {
        var info = new SHELLEXECUTEINFO
        {
            cbSize = Marshal.SizeOf<SHELLEXECUTEINFO>(),
            fMask = 0x0000000C,   // SEE_MASK_INVOKEIDLIST | SEE_MASK_NOASYNC-like flags
            lpVerb = "properties", lpFile = path, nShow = 5,
        };
        ShellExecuteEx(ref info);
    }

    public static void ShowInExplorer(string path)
    {
        if (string.IsNullOrEmpty(path)) return;
        if (File.Exists(path))
            Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { "/select," + path }, UseShellExecute = false });
        else if (Directory.Exists(path))
            Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { path }, UseShellExecute = false });
    }
}
