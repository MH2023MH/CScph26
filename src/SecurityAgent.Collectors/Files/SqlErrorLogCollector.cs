using System.Text;
using Microsoft.Extensions.Logging;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.State;

namespace SecurityAgent.Collectors.Files;

public sealed class SqlErrorLogCollectorOptions
{
    /// <summary>Ruta del ERRORLOG activo (p. ej. C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log\ERRORLOG).</summary>
    public string Path { get; set; } = "";
    public bool Utf16 { get; set; } = true;     // ERRORLOG de SQL Server es UTF-16 LE
}

public sealed class SqlErrorLogCollector : ICollector
{
    private readonly SqlErrorLogCollectorOptions _opt;
    private readonly LogTailer _tailer;
    private readonly SqlErrorLogParser _parser;
    private readonly bool _fileExistedAtStart;
    private readonly ILogger? _log;

    public SqlErrorLogCollector(IStateStore store, SqlErrorLogCollectorOptions options, TimeZoneInfo? serverTimeZone = null, ILogger? log = null)
    {
        _opt = options;
        _tailer = new LogTailer(store, options.Utf16 ? new UnicodeEncoding(false, true) : new UTF8Encoding(false));
        _parser = new SqlErrorLogParser(serverTimeZone);
        _fileExistedAtStart = File.Exists(options.Path);
        _log = log;
    }

    public string Name => "sql";

    public Task<CollectorBatch> PollAsync(CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(_opt.Path) || !File.Exists(_opt.Path)) return Task.FromResult(CollectorBatch.Empty);
        try
        {
            var result = _tailer.Read(_opt.Path, startAtEndIfNew: _fileExistedAtStart);
            var events = result.Lines.Select(l => _parser.Parse(l.Text, "sql")).Where(e => e != null).Select(e => e!).ToList();
            return Task.FromResult(new CollectorBatch(events, () => _tailer.Commit(result)));
        }
        catch (IOException e) { _log?.LogWarning(e, "No se pudo leer {Path}", _opt.Path); }
        catch (UnauthorizedAccessException e) { _log?.LogWarning(e, "Sin permiso para leer {Path}", _opt.Path); }
        return Task.FromResult(CollectorBatch.Empty);
    }
}
