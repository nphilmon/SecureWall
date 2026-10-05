using Microsoft.Extensions.Logging;

namespace SecureWall.Infrastructure.Logging;

/// <summary>Journal applicatif simple : un fichier par jour, 14 jours conservés. Ne journalise jamais de secrets.</summary>
public sealed class FileLoggerProvider : ILoggerProvider
{
    readonly string _dir;
    readonly string _prefix;
    readonly object _lock = new();
    readonly LogLevel _min;

    public FileLoggerProvider(string directory, string prefix = "securewall", LogLevel min = LogLevel.Information)
    {
        _dir = directory; _prefix = prefix; _min = min;
        Directory.CreateDirectory(_dir);
        Cleanup();
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);

    void Cleanup()
    {
        try
        {
            foreach (var f in Directory.GetFiles(_dir, _prefix + "-*.log"))
                if (File.GetLastWriteTimeUtc(f) < DateTime.UtcNow.AddDays(-14)) File.Delete(f);
        }
        catch { /* non bloquant */ }
    }

    internal void Write(LogLevel level, string category, string message, Exception? ex)
    {
        if (level < _min) return;
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level.ToString()[..3].ToUpperInvariant()}] {category}: {message}";
        if (ex != null) line += Environment.NewLine + ex;
        lock (_lock)
        {
            try { File.AppendAllText(Path.Combine(_dir, $"{_prefix}-{DateTime.Now:yyyyMMdd}.log"), line + Environment.NewLine); }
            catch { /* disque plein / verrouillé : on ne plante jamais à cause du journal */ }
        }
    }

    public void Dispose() { }

    sealed class FileLogger(FileLoggerProvider p, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel >= p._min;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            p.Write(logLevel, category, formatter(state, exception), exception);
        }
    }
}
