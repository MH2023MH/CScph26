using System.Text;
using Microsoft.Extensions.Logging;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.State;

namespace SecurityAgent.Collectors.Files;

public sealed class IisLogCollectorOptions
{
    public string Root { get; set; } = @"C:\inetpub\logs\LogFiles";
    public string Pattern { get; set; } = "u_ex*.log";
    /// <summary>Solo se miran archivos modificados dentro de esta ventana.</summary>
    public TimeSpan MaxFileAge { get; set; } = TimeSpan.FromDays(2);
    public int MaxEventsPerPoll { get; set; } = 5000;
}

public sealed class IisLogCollector : ICollector
{
    private readonly IisLogCollectorOptions _opt;
    private readonly LogTailer _tailer;
    private readonly IStateStore _store;
    private readonly HashSet<string> _preExisting;
    private readonly ILogger? _log;
    private readonly Dictionary<string, IisLogParser> _parsers = new();

    private const string InitializedKey = "iis:initialized";

    public IisLogCollector(IStateStore store, IisLogCollectorOptions options, ILogger? log = null)
    {
        _opt = options;
        _store = store;
        _tailer = new LogTailer(store, new UTF8Encoding(false));
        _log = log;
        // Archivos ya presentes al arrancar: en la primera ejecución de la historia del agente se ignora su contenido previo.
        _preExisting = Directory.Exists(options.Root)
            ? Directory.EnumerateFiles(options.Root, options.Pattern, SearchOption.AllDirectories).ToHashSet()
            : new HashSet<string>();
    }

    public string Name => "iis";

    public Task<CollectorBatch> PollAsync(CancellationToken ct = default)
    {
        var events = new List<SecurityEvent>();
        var results = new List<TailResult>();
        if (!Directory.Exists(_opt.Root)) return Task.FromResult(CollectorBatch.Empty);

        var cutoff = DateTime.UtcNow - _opt.MaxFileAge;
        foreach (var path in Directory.EnumerateFiles(_opt.Root, _opt.Pattern, SearchOption.AllDirectories).OrderBy(p => p, StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            if (events.Count >= _opt.MaxEventsPerPoll) break;
            try
            {
                if (File.GetLastWriteTimeUtc(path) < cutoff) continue;
                // Sin cursor: archivo que ya existía en la primera ejecución del agente → ignorar su historial; cualquier otro → leer desde el inicio.
                var firstRunEver = _store.GetCursor(InitializedKey) is null;
                var result = _tailer.Read(path, startAtEndIfNew: firstRunEver && _preExisting.Contains(path));

                if (!_parsers.TryGetValue(path, out var parser))
                {
                    _parsers[path] = parser = new IisLogParser();
                    parser.SetFields(IisLogParser.ReadFieldsFromHead(path));
                }
                var prefix = "iis-" + new DirectoryInfo(Path.GetDirectoryName(path)!).Name + "-" + Path.GetFileNameWithoutExtension(path);
                foreach (var line in result.Lines)
                    if (parser.Parse(line.Text, prefix, line.Offset) is { } ev) events.Add(ev);
                results.Add(result);
            }
            catch (IOException e) { _log?.LogWarning(e, "No se pudo leer {Path}", path); }
            catch (UnauthorizedAccessException e) { _log?.LogWarning(e, "Sin permiso para leer {Path}", path); }
        }
        return Task.FromResult(new CollectorBatch(events, () => { foreach (var r in results) _tailer.Commit(r); _store.SetCursor(InitializedKey, 1); }));
    }
}
