using System.Globalization;
using Microsoft.Data.Sqlite;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Models;

namespace SecureWall.Infrastructure.Database;

/// <summary>
/// Base SQLite locale. Ne contient que des métadonnées (noms de menaces, chemins, adresses, dates) :
/// jamais le contenu des fichiers de l'utilisateur, ni mots de passe.
/// </summary>
public sealed class SqliteSecurityStore : ISecurityStore, IAuditLog
{
    const string TimeFormat = "yyyy-MM-dd HH:mm:ss";
    readonly string _cs;
    readonly object _lock = new();

    public SqliteSecurityStore(string dbFile)
    {
        _cs = new SqliteConnectionStringBuilder { DataSource = dbFile, Pooling = false }.ToString();
        Migrate();
    }

    // ---------- Utilitaires ----------
    static string Ts(DateTime d) => d.ToUniversalTime().ToString(TimeFormat, CultureInfo.InvariantCulture);
    static DateTime FromTs(string s) =>
        DateTime.SpecifyKind(DateTime.ParseExact(s, TimeFormat, CultureInfo.InvariantCulture), DateTimeKind.Utc).ToLocalTime();
    static DateTime? FromTsN(SqliteDataReader r, int i) => r.IsDBNull(i) ? null : FromTs(r.GetString(i));

    SqliteConnection Open()
    {
        var c = new SqliteConnection(_cs);
        c.Open();
        return c;
    }

    static void AddParams(SqliteCommand cmd, (string, object?)[] p)
    {
        foreach (var (n, v) in p) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
    }

    int Exec(string sql, params (string, object?)[] p)
    {
        lock (_lock)
        {
            using var c = Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = sql;
            AddParams(cmd, p);
            return cmd.ExecuteNonQuery();
        }
    }

    List<T> Query<T>(string sql, Func<SqliteDataReader, T> map, params (string, object?)[] p)
    {
        lock (_lock)
        {
            using var c = Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = sql;
            AddParams(cmd, p);
            using var r = cmd.ExecuteReader();
            var list = new List<T>();
            while (r.Read()) list.Add(map(r));
            return list;
        }
    }

    Dictionary<string, int> Group(string sql, params (string, object?)[] p)
    {
        var d = new Dictionary<string, int>();
        foreach (var (k, v) in Query(sql, r => (r.IsDBNull(0) ? "—" : r.GetValue(0).ToString() ?? "—", r.GetInt32(1)), p)) d[k] = v;
        return d;
    }

    void Migrate()
    {
        lock (_lock)
        {
            using var c = Open();
            using var pragma = c.CreateCommand();
            pragma.CommandText = "PRAGMA journal_mode=WAL;";
            pragma.ExecuteNonQuery();
            using var cmd = c.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS Applications (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT, Name TEXT NOT NULL, Path TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    Publisher TEXT NOT NULL DEFAULT '', SignatureStatus TEXT NOT NULL DEFAULT '',
                    FirstSeen TEXT NOT NULL, LastSeen TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS Connections (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT, ApplicationId INTEGER NOT NULL, Protocol TEXT NOT NULL,
                    LocalAddress TEXT NOT NULL, LocalPort INTEGER NOT NULL, RemoteAddress TEXT NOT NULL,
                    RemotePort INTEGER NOT NULL, State TEXT NOT NULL, Timestamp TEXT NOT NULL,
                    FOREIGN KEY (ApplicationId) REFERENCES Applications(Id) ON DELETE CASCADE);
                CREATE TABLE IF NOT EXISTS FirewallEvents (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT, ApplicationId INTEGER NULL, AppName TEXT NOT NULL DEFAULT '',
                    Action TEXT NOT NULL, Direction TEXT NOT NULL, Protocol TEXT NOT NULL,
                    RemoteAddress TEXT NOT NULL, RemotePort INTEGER NOT NULL, RuleName TEXT NOT NULL DEFAULT '', Timestamp TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS AntivirusScans (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT, ScanType TEXT NOT NULL, StartDate TEXT NOT NULL, EndDate TEXT NULL,
                    Status TEXT NOT NULL, ThreatsFound INTEGER NOT NULL DEFAULT 0, FilesScanned INTEGER NULL, Target TEXT NULL);
                CREATE TABLE IF NOT EXISTS Threats (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT, ThreatName TEXT NOT NULL, FilePath TEXT NOT NULL, Severity TEXT NOT NULL,
                    DetectionDate TEXT NOT NULL, Action TEXT NOT NULL, Status TEXT NOT NULL,
                    Category TEXT NOT NULL DEFAULT '', DetectionId TEXT NOT NULL UNIQUE, Application TEXT NOT NULL DEFAULT '');
                CREATE TABLE IF NOT EXISTS Devices (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT, DeviceIdentifier TEXT NOT NULL UNIQUE, DeviceName TEXT NOT NULL,
                    FirstSeen TEXT NOT NULL, LastSeen TEXT NOT NULL, LastScanDate TEXT NULL);
                CREATE TABLE IF NOT EXISTS SecurityEvents (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT, EventType TEXT NOT NULL, Description TEXT NOT NULL,
                    Severity TEXT NOT NULL, Timestamp TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS AuditLogs (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT, User TEXT NOT NULL, Action TEXT NOT NULL,
                    Details TEXT NOT NULL, Timestamp TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS Settings (Key TEXT PRIMARY KEY, Value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS GeoCache (Address TEXT PRIMARY KEY, Country TEXT NOT NULL, Checked TEXT NOT NULL);

                CREATE INDEX IF NOT EXISTS IX_Connections_Time ON Connections(Timestamp);
                CREATE INDEX IF NOT EXISTS IX_Connections_App ON Connections(ApplicationId, Timestamp);
                CREATE INDEX IF NOT EXISTS IX_FwEvents_Time ON FirewallEvents(Timestamp);
                CREATE INDEX IF NOT EXISTS IX_Scans_Start ON AntivirusScans(StartDate);
                CREATE INDEX IF NOT EXISTS IX_Threats_Date ON Threats(DetectionDate);
                CREATE INDEX IF NOT EXISTS IX_Threats_Status ON Threats(Status);
                CREATE INDEX IF NOT EXISTS IX_Events_Time ON SecurityEvents(Timestamp);
                CREATE INDEX IF NOT EXISTS IX_Audit_Time ON AuditLogs(Timestamp);
                CREATE INDEX IF NOT EXISTS IX_Apps_LastSeen ON Applications(LastSeen);
                """;
            cmd.ExecuteNonQuery();
        }
    }

    // ---------- Applications / connexions ----------
    public long UpsertApplication(string name, string path, string publisher, string signatureStatus, out bool isNew)
    {
        lock (_lock)
        {
            using var c = Open();
            using var tx = c.BeginTransaction();
            long id;
            using (var q = c.CreateCommand())
            {
                q.Transaction = tx;
                q.CommandText = "SELECT Id FROM Applications WHERE Path=$p";
                q.Parameters.AddWithValue("$p", path);
                var o = q.ExecuteScalar();
                id = o is long l ? l : 0;
            }
            isNew = id == 0;
            using var cmd = c.CreateCommand();
            cmd.Transaction = tx;
            cmd.Parameters.AddWithValue("$n", name);
            cmd.Parameters.AddWithValue("$p", path);
            cmd.Parameters.AddWithValue("$pub", publisher);
            cmd.Parameters.AddWithValue("$s", signatureStatus);
            cmd.Parameters.AddWithValue("$t", Ts(DateTime.Now));
            if (isNew)
            {
                cmd.CommandText = "INSERT INTO Applications (Name,Path,Publisher,SignatureStatus,FirstSeen,LastSeen) VALUES ($n,$p,$pub,$s,$t,$t); SELECT last_insert_rowid();";
                id = (long)cmd.ExecuteScalar()!;
            }
            else
            {
                cmd.CommandText = "UPDATE Applications SET Name=$n, LastSeen=$t, Publisher=CASE WHEN $pub<>'' THEN $pub ELSE Publisher END, SignatureStatus=CASE WHEN $s<>'' THEN $s ELSE SignatureStatus END WHERE Path=$p";
                cmd.ExecuteNonQuery();
            }
            tx.Commit();
            return id;
        }
    }

    static ApplicationRecord MapApp(SqliteDataReader r) => new()
    {
        Id = r.GetInt64(0), Name = r.GetString(1), Path = r.GetString(2), Publisher = r.GetString(3),
        SignatureStatus = r.GetString(4), FirstSeen = FromTs(r.GetString(5)), LastSeen = FromTs(r.GetString(6)),
    };

    public ApplicationRecord? GetApplication(string path) => Query(
        "SELECT Id,Name,Path,Publisher,SignatureStatus,FirstSeen,LastSeen FROM Applications WHERE Path=$p", MapApp, ("$p", path)).FirstOrDefault();

    public List<ApplicationRecord> GetApplications() => Query(
        "SELECT Id,Name,Path,Publisher,SignatureStatus,FirstSeen,LastSeen FROM Applications ORDER BY LastSeen DESC LIMIT 5000", MapApp);

    public void AddConnections(long applicationId, IEnumerable<ConnectionRecord> rows)
    {
        lock (_lock)
        {
            using var c = Open();
            using var tx = c.BeginTransaction();
            using var cmd = c.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "INSERT INTO Connections (ApplicationId,Protocol,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,Timestamp) VALUES ($a,$pr,$la,$lp,$ra,$rp,$s,$t)";
            var pa = cmd.Parameters.Add("$a", SqliteType.Integer);
            var pp = cmd.Parameters.Add("$pr", SqliteType.Text);
            var pla = cmd.Parameters.Add("$la", SqliteType.Text);
            var plp = cmd.Parameters.Add("$lp", SqliteType.Integer);
            var pra = cmd.Parameters.Add("$ra", SqliteType.Text);
            var prp = cmd.Parameters.Add("$rp", SqliteType.Integer);
            var ps = cmd.Parameters.Add("$s", SqliteType.Text);
            var pt = cmd.Parameters.Add("$t", SqliteType.Text);
            foreach (var r in rows)
            {
                pa.Value = applicationId; pp.Value = r.Protocol; pla.Value = r.LocalAddress; plp.Value = r.LocalPort;
                pra.Value = r.RemoteAddress; prp.Value = r.RemotePort; ps.Value = r.State; pt.Value = Ts(r.Timestamp);
                cmd.ExecuteNonQuery();
            }
            tx.Commit();
        }
    }

    // ---------- Pare-feu ----------
    public void AddFirewallEvents(IEnumerable<FirewallEventRecord> rows)
    {
        lock (_lock)
        {
            using var c = Open();
            using var tx = c.BeginTransaction();
            foreach (var r in rows)
            {
                using var cmd = c.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = "INSERT INTO FirewallEvents (ApplicationId,AppName,Action,Direction,Protocol,RemoteAddress,RemotePort,RuleName,Timestamp) VALUES ($a,$n,$ac,$d,$p,$ra,$rp,$rn,$t)";
                cmd.Parameters.AddWithValue("$a", (object?)r.ApplicationId ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$n", r.Application);
                cmd.Parameters.AddWithValue("$ac", r.Action);
                cmd.Parameters.AddWithValue("$d", r.Direction);
                cmd.Parameters.AddWithValue("$p", r.Protocol);
                cmd.Parameters.AddWithValue("$ra", r.RemoteAddress);
                cmd.Parameters.AddWithValue("$rp", r.RemotePort);
                cmd.Parameters.AddWithValue("$rn", r.RuleName);
                cmd.Parameters.AddWithValue("$t", Ts(r.Timestamp));
                cmd.ExecuteNonQuery();
            }
            tx.Commit();
        }
    }

    public List<FirewallEventRecord> GetFirewallEvents(DateTime since, int limit = 1000) => Query(
        "SELECT Id,ApplicationId,AppName,Action,Direction,Protocol,RemoteAddress,RemotePort,RuleName,Timestamp FROM FirewallEvents WHERE Timestamp>=$s ORDER BY Id DESC LIMIT $l",
        r => new FirewallEventRecord
        {
            Id = r.GetInt64(0), ApplicationId = r.IsDBNull(1) ? null : r.GetInt64(1), Application = r.GetString(2), Action = r.GetString(3),
            Direction = r.GetString(4), Protocol = r.GetString(5), RemoteAddress = r.GetString(6), RemotePort = r.GetInt32(7),
            RuleName = r.GetString(8), Timestamp = FromTs(r.GetString(9)),
        }, ("$s", Ts(since)), ("$l", limit));

    // ---------- Analyses ----------
    public long StartScan(string type, string? target)
    {
        lock (_lock)
        {
            using var c = Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = "INSERT INTO AntivirusScans (ScanType,StartDate,Status,Target) VALUES ($t,$s,'En cours',$g); SELECT last_insert_rowid();";
            cmd.Parameters.AddWithValue("$t", type);
            cmd.Parameters.AddWithValue("$s", Ts(DateTime.Now));
            cmd.Parameters.AddWithValue("$g", (object?)target ?? DBNull.Value);
            return (long)cmd.ExecuteScalar()!;
        }
    }

    public void FinishScan(long id, int? files, int threats, string status) =>
        Exec("UPDATE AntivirusScans SET EndDate=$e, FilesScanned=$f, ThreatsFound=$t, Status=$s WHERE Id=$i",
            ("$e", Ts(DateTime.Now)), ("$f", files), ("$t", threats), ("$s", status), ("$i", id));

    public List<ScanRecord> GetScans(int limit = 200, int offset = 0) => Query(
        "SELECT Id,ScanType,StartDate,EndDate,FilesScanned,ThreatsFound,Status,Target FROM AntivirusScans ORDER BY Id DESC LIMIT $l OFFSET $o",
        r => new ScanRecord
        {
            Id = r.GetInt64(0), ScanType = r.GetString(1), StartDate = FromTs(r.GetString(2)), EndDate = FromTsN(r, 3),
            FilesScanned = r.IsDBNull(4) ? null : r.GetInt32(4), ThreatsFound = r.GetInt32(5), Status = r.GetString(6),
            Target = r.IsDBNull(7) ? null : r.GetString(7),
        }, ("$l", limit), ("$o", offset));

    // ---------- Menaces ----------
    public (bool Inserted, string? PreviousStatus) UpsertThreat(DefenderThreat t)
    {
        lock (_lock)
        {
            using var c = Open();
            string? prev;
            using (var q = c.CreateCommand())
            {
                q.CommandText = "SELECT Status FROM Threats WHERE DetectionId=$d";
                q.Parameters.AddWithValue("$d", t.DetectionId);
                prev = q.ExecuteScalar() as string;
            }
            using var cmd = c.CreateCommand();
            cmd.CommandText = prev == null
                ? "INSERT INTO Threats (ThreatName,FilePath,Severity,DetectionDate,Action,Status,Category,DetectionId,Application) VALUES ($n,$p,$s,$d,$a,$st,$c,$id,$app)"
                : "UPDATE Threats SET Action=$a, Status=$st WHERE DetectionId=$id";
            cmd.Parameters.AddWithValue("$n", t.Name);
            cmd.Parameters.AddWithValue("$p", t.FilePath);
            cmd.Parameters.AddWithValue("$s", t.Severity);
            cmd.Parameters.AddWithValue("$d", Ts(t.DetectionTime));
            cmd.Parameters.AddWithValue("$a", t.Action);
            cmd.Parameters.AddWithValue("$st", t.Status);
            cmd.Parameters.AddWithValue("$c", t.Category);
            cmd.Parameters.AddWithValue("$id", t.DetectionId);
            cmd.Parameters.AddWithValue("$app", t.Process);
            cmd.ExecuteNonQuery();
            return (prev == null, prev);
        }
    }

    public List<ThreatRecord> GetThreats(int limit = 500, int offset = 0, string? status = null) => Query(
        "SELECT Id,ThreatName,FilePath,Severity,DetectionDate,Action,Status,Category,DetectionId,Application FROM Threats " +
        (status == null ? "" : "WHERE Status=$st ") + "ORDER BY DetectionDate DESC LIMIT $l OFFSET $o",
        r => new ThreatRecord
        {
            Id = r.GetInt64(0), ThreatName = r.GetString(1), FilePath = r.GetString(2), Severity = r.GetString(3),
            DetectionDate = FromTs(r.GetString(4)), Action = r.GetString(5), Status = r.GetString(6), Category = r.GetString(7),
            DetectionId = r.GetString(8), Application = r.GetString(9),
        }, ("$st", status), ("$l", limit), ("$o", offset));

    // ---------- Événements ----------
    public void AddEvent(string type, string description, string severity = "Information") =>
        Exec("INSERT INTO SecurityEvents (EventType,Description,Severity,Timestamp) VALUES ($t,$d,$s,$ts)",
            ("$t", type), ("$d", description), ("$s", severity), ("$ts", Ts(DateTime.Now)));

    public List<SecurityEventRecord> GetEvents(int limit = 200, int offset = 0, string? search = null) => Query(
        "SELECT Id,EventType,Description,Severity,Timestamp FROM SecurityEvents " +
        (string.IsNullOrWhiteSpace(search) ? "" : "WHERE Description LIKE $q OR EventType LIKE $q ") + "ORDER BY Id DESC LIMIT $l OFFSET $o",
        r => new SecurityEventRecord
        {
            Id = r.GetInt64(0), EventType = r.GetString(1), Description = r.GetString(2), Severity = r.GetString(3), Timestamp = FromTs(r.GetString(4)),
        }, ("$q", "%" + search + "%"), ("$l", limit), ("$o", offset));

    // ---------- Périphériques ----------
    static DeviceRecord MapDevice(SqliteDataReader r) => new()
    {
        Id = r.GetInt64(0), DeviceIdentifier = r.GetString(1), DeviceName = r.GetString(2),
        FirstSeen = FromTs(r.GetString(3)), LastSeen = FromTs(r.GetString(4)), LastScanDate = FromTsN(r, 5),
    };

    public DeviceRecord? GetDevice(string identifier) => Query(
        "SELECT Id,DeviceIdentifier,DeviceName,FirstSeen,LastSeen,LastScanDate FROM Devices WHERE DeviceIdentifier=$i", MapDevice, ("$i", identifier)).FirstOrDefault();

    public List<DeviceRecord> GetDevices() => Query(
        "SELECT Id,DeviceIdentifier,DeviceName,FirstSeen,LastSeen,LastScanDate FROM Devices ORDER BY LastSeen DESC", MapDevice);

    public void SeenDevice(string name, string identifier) => Exec(
        "INSERT INTO Devices (DeviceIdentifier,DeviceName,FirstSeen,LastSeen) VALUES ($i,$n,$t,$t) ON CONFLICT(DeviceIdentifier) DO UPDATE SET DeviceName=$n, LastSeen=$t",
        ("$i", identifier), ("$n", name), ("$t", Ts(DateTime.Now)));

    public void MarkDeviceScanned(string identifier) =>
        Exec("UPDATE Devices SET LastScanDate=$t WHERE DeviceIdentifier=$i", ("$t", Ts(DateTime.Now)), ("$i", identifier));

    // ---------- Audit ----------
    public void AddAudit(string user, string action, string details) =>
        Exec("INSERT INTO AuditLogs (User,Action,Details,Timestamp) VALUES ($u,$a,$d,$t)",
            ("$u", user), ("$a", action), ("$d", details.Length > 2000 ? details[..2000] : details), ("$t", Ts(DateTime.Now)));

    public void Write(string action, string details) => AddAudit(Environment.UserName, action, details);

    public List<AuditLogRecord> GetAudit(int limit = 200, int offset = 0) => Query(
        "SELECT Id,User,Action,Details,Timestamp FROM AuditLogs ORDER BY Id DESC LIMIT $l OFFSET $o",
        r => new AuditLogRecord { Id = r.GetInt64(0), User = r.GetString(1), Action = r.GetString(2), Details = r.GetString(3), Timestamp = FromTs(r.GetString(4)) },
        ("$l", limit), ("$o", offset));

    // ---------- Statistiques ----------
    public Dictionary<string, int> TopApplications(DateTime since, int take) => Group(
        "SELECT a.Name, COUNT(*) AS n FROM Connections c JOIN Applications a ON a.Id=c.ApplicationId WHERE c.Timestamp>=$s GROUP BY a.Id ORDER BY n DESC LIMIT $t",
        ("$s", Ts(since)), ("$t", take));

    public Dictionary<string, int> ConnectionsByHour(DateTime since) => Group(
        "SELECT strftime('%Y-%m-%d %H:00', Timestamp, 'localtime') AS h, COUNT(*) FROM Connections WHERE Timestamp>=$s GROUP BY h ORDER BY h",
        ("$s", Ts(since)));

    public Dictionary<string, int> TopPorts(DateTime since, int take) => Group(
        "SELECT RemotePort, COUNT(*) AS n FROM Connections WHERE Timestamp>=$s AND RemotePort>0 GROUP BY RemotePort ORDER BY n DESC LIMIT $t",
        ("$s", Ts(since)), ("$t", take));

    public Dictionary<string, int> TopDestinations(DateTime since, int take) => Group(
        "SELECT RemoteAddress, COUNT(*) AS n FROM Connections WHERE Timestamp>=$s AND RemoteAddress<>'' GROUP BY RemoteAddress ORDER BY n DESC LIMIT $t",
        ("$s", Ts(since)), ("$t", take));

    public Dictionary<string, int> BlockedByApplication(DateTime since, int take) => Group(
        "SELECT CASE WHEN AppName='' THEN '(inconnu)' ELSE AppName END, COUNT(*) AS n FROM FirewallEvents WHERE Timestamp>=$s AND Action='Bloquée' GROUP BY AppName ORDER BY n DESC LIMIT $t",
        ("$s", Ts(since)), ("$t", take));

    int Scalar(string sql, params (string, object?)[] p) => Query(sql, r => r.GetInt32(0), p).FirstOrDefault();
    public int CountScans(DateTime since) => Scalar("SELECT COUNT(*) FROM AntivirusScans WHERE StartDate>=$s", ("$s", Ts(since)));
    public int CountThreats(DateTime since) => Scalar("SELECT COUNT(*) FROM Threats WHERE DetectionDate>=$s", ("$s", Ts(since)));
    public int CountBlocked(DateTime since) => Scalar("SELECT COUNT(*) FROM FirewallEvents WHERE Timestamp>=$s AND Action='Bloquée'", ("$s", Ts(since)));

    // ---------- Destinations et localisation ----------
    public List<RemoteTraffic> GetRemoteTraffic(DateTime since, int limit = 20000) => Query(
        "SELECT c.RemoteAddress, c.RemotePort, a.Name, COUNT(*) AS n, MAX(c.Timestamp) FROM Connections c JOIN Applications a ON a.Id=c.ApplicationId " +
        "WHERE c.Timestamp>=$s AND c.RemoteAddress<>'' GROUP BY c.RemoteAddress, c.RemotePort, a.Id ORDER BY n DESC LIMIT $l",
        r => new RemoteTraffic(r.GetString(0), r.GetInt32(1), r.GetString(2), r.GetInt32(3), FromTs(r.GetString(4))),
        ("$s", Ts(since)), ("$l", limit));

    public Dictionary<string, GeoCacheEntry> GetGeoCache(IEnumerable<string> addresses)
    {
        var result = new Dictionary<string, GeoCacheEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var chunk in addresses.Distinct(StringComparer.OrdinalIgnoreCase).Chunk(400))
        {
            var names = chunk.Select((_, i) => "$a" + i).ToArray();
            var rows = Query($"SELECT Address,Country,Checked FROM GeoCache WHERE Address IN ({string.Join(",", names)})",
                r => new GeoCacheEntry(r.GetString(0), r.GetString(1), FromTs(r.GetString(2))),
                chunk.Select((a, i) => (names[i], (object?)a)).ToArray());
            foreach (var e in rows) result[e.Address] = e;
        }
        return result;
    }

    public void SetGeoCache(IEnumerable<GeoCacheEntry> rows)
    {
        lock (_lock)
        {
            using var c = Open();
            using var tx = c.BeginTransaction();
            using var cmd = c.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "INSERT INTO GeoCache (Address,Country,Checked) VALUES ($a,$c,$t) ON CONFLICT(Address) DO UPDATE SET Country=$c, Checked=$t";
            var pa = cmd.Parameters.Add("$a", SqliteType.Text);
            var pc = cmd.Parameters.Add("$c", SqliteType.Text);
            var pt = cmd.Parameters.Add("$t", SqliteType.Text);
            foreach (var e in rows) { pa.Value = e.Address; pc.Value = e.Country; pt.Value = Ts(e.Checked); cmd.ExecuteNonQuery(); }
            tx.Commit();
        }
    }

    public int ClearGeoCache() => Exec("DELETE FROM GeoCache;");
    // ---------- Maintenance ----------
    public void PurgeOlderThan(DateTime limit)
    {
        var s = Ts(limit);
        Exec("DELETE FROM Connections WHERE Timestamp<$s; DELETE FROM FirewallEvents WHERE Timestamp<$s; DELETE FROM SecurityEvents WHERE Timestamp<$s; DELETE FROM AuditLogs WHERE Timestamp<$s; DELETE FROM GeoCache WHERE Checked<$s;", ("$s", s));
    }

    public void ClearHistory() => Exec(
        "DELETE FROM Connections; DELETE FROM FirewallEvents; DELETE FROM Threats; DELETE FROM SecurityEvents; DELETE FROM AntivirusScans; DELETE FROM AuditLogs; DELETE FROM Applications; DELETE FROM Devices; DELETE FROM GeoCache;");

    // ---------- Paramètres ----------
    public string? GetSetting(string key) => Query("SELECT Value FROM Settings WHERE Key=$k", r => r.GetString(0), ("$k", key)).FirstOrDefault();

    public void SetSetting(string key, string value) =>
        Exec("INSERT INTO Settings (Key,Value) VALUES ($k,$v) ON CONFLICT(Key) DO UPDATE SET Value=$v", ("$k", key), ("$v", value));
}

