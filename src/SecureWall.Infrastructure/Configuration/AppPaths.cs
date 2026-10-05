namespace SecureWall.Infrastructure.Configuration;

public static class AppPaths
{
    public const string PipeName = "SecureWall.Privileged.v1";
    public const string ServiceName = "SecureWallPrivilegedService";
    public const string ServiceExeName = "SecureWall.PrivilegedService.exe";
    public const string AppExeName = "SecureWall.exe";

    /// <summary>Données de l'utilisateur : base SQLite, journaux, réglages.</summary>
    public static string UserDataDir { get; } = EnsureDir(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecureWall"));

    public static string LogDir => EnsureDir(Path.Combine(UserDataDir, "logs"));
    public static string DbFile => Path.Combine(UserDataDir, "securewall.db");
    public static string BaselineFile => Path.Combine(UserDataDir, "baseline.json");

    /// <summary>Données du service (sauvegardes du pare-feu, état du mode urgence).</summary>
    public static string ServiceDataDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SecureWall");

    public static string FirewallBackupDir => Path.Combine(ServiceDataDir, "FirewallBackups");
    public static string EmergencyStateFile => Path.Combine(ServiceDataDir, "emergency.json");
    public static string ExePath => Environment.ProcessPath ?? "";

    public static string EnsureDir(string path)
    {
        Directory.CreateDirectory(path);
        return path;
    }
}
