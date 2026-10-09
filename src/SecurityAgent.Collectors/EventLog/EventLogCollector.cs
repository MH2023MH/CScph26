using Microsoft.Extensions.Logging;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.State;

namespace SecurityAgent.Collectors.EventLog;

public enum StartPolicy
{
    /// <summary>Primera ejecución: ignorar el historial y leer solo lo nuevo (producción).</summary>
    FromLatest,
    /// <summary>Primera ejecución: leer desde el primer registro (pruebas / reproducción).</summary>
    FromStart
}

public sealed class EventLogCollectorOptions
{
    /// <summary>Vacío = canales por defecto. (El binder de configuración AÑADE a las listas con valores por defecto, por eso no se prellenan.)</summary>
    public List<string> Channels { get; set; } = new();

    public static readonly string[] DefaultChannels =
    {
        "Security", "System",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-Sysmon/Operational"
    };

    public IReadOnlyList<string> EffectiveChannels => (Channels.Count > 0 ? (IEnumerable<string>)Channels : DefaultChannels).Distinct().ToList();

    public int MaxPerChannelPerPoll { get; set; } = 2000;
    public StartPolicy StartPolicy { get; set; } = StartPolicy.FromLatest;
}

public sealed class EventLogCollector(IEventRecordSource source, IStateStore store, EventLogCollectorOptions options, ILogger? log = null,
    Action<string, string?>? report = null) : ICollector
{
    public string Name => "eventlog";

    private readonly Dictionary<string, string?> _lastReported = new();

    private void Report(string channel)
    {
        var err = source.LastError(channel);
        _lastReported.TryGetValue(channel, out var prev);
        if (prev == err) return;                      // sin cambios (incluye "sigue todo bien" la primera vez)
        _lastReported[channel] = err;
        report?.Invoke("eventlog:" + channel, err);
        if (err != null) log?.LogWarning("No se puede leer el canal {Channel}: {Error}", channel, err);
        else if (prev != null) log?.LogInformation("El canal {Channel} vuelve a ser legible", channel);
    }

    private static string CursorKey(string channel) => "eventlog:" + channel;

    public Task<CollectorBatch> PollAsync(CancellationToken ct = default)
    {
        var events = new List<SecurityEvent>();
        var commits = new List<(string Key, long Value)>();

        foreach (var channel in options.EffectiveChannels)
        {
            ct.ThrowIfCancellationRequested();
            var key = CursorKey(channel);
            var cursor = store.GetCursor(key);
            if (cursor is null)
            {
                if (options.StartPolicy == StartPolicy.FromLatest)
                {
                    store.SetCursor(key, source.LatestRecordId(channel));
                    Report(channel);
                    continue;
                }
                cursor = 0;
            }

            var records = source.Read(channel, cursor.Value, options.MaxPerChannelPerPoll);
            Report(channel);
            if (records.Count == 0) continue;
            foreach (var r in records)
            {
                var ev = EventLogXmlParser.Parse(r.Xml, channel);
                if (ev is null) { log?.LogDebug("Registro {Id} de {Channel} ilegible; se omite", r.RecordId, channel); continue; }
                events.Add(ev);
            }
            commits.Add((key, records.Max(r => r.RecordId)));
        }

        return Task.FromResult(new CollectorBatch(events, () => { foreach (var (k, v) in commits) store.SetCursor(k, v); }));
    }
}
