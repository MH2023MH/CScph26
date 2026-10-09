using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;

namespace SecurityAgent.Collectors.EventLog;

/// <summary>Lectura real del Event Log de Windows por consulta XPath sobre EventRecordID (solo Windows).</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEventRecordSource : IEventRecordSource
{
    private readonly ConcurrentDictionary<string, string> _errors = new();

    public string? LastError(string channel) => _errors.TryGetValue(channel, out var e) ? e : null;

    public IReadOnlyList<RawEventRecord> Read(string channel, long afterRecordId, int max)
    {
        var list = new List<RawEventRecord>();
        try
        {
            var query = new EventLogQuery(channel, PathType.LogName, $"*[System[EventRecordID > {afterRecordId}]]");
            using var reader = new EventLogReader(query);
            EventRecord? rec;
            while (list.Count < max && (rec = reader.ReadEvent()) != null)
            {
                using (rec)
                    if (rec.RecordId is { } id) list.Add(new RawEventRecord(id, rec.ToXml()));
            }
        }
        catch (EventLogNotFoundException) { _errors[channel] = "el canal no existe (¿Sysmon sin instalar?)"; return list; }
        catch (UnauthorizedAccessException e) { _errors[channel] = "acceso denegado: " + e.Message; return list; }
        catch (EventLogException e) { _errors[channel] = $"{e.GetType().Name}: {e.Message}"; return list; }
        _errors.TryRemove(channel, out _);
        return list;
    }

    public long LatestRecordId(string channel)
    {
        try
        {
            var query = new EventLogQuery(channel, PathType.LogName) { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            using var rec = reader.ReadEvent();
            _errors.TryRemove(channel, out _);
            return rec?.RecordId ?? 0;
        }
        catch (EventLogNotFoundException) { _errors[channel] = "el canal no existe (¿Sysmon sin instalar?)"; return 0; }
        catch (UnauthorizedAccessException e) { _errors[channel] = "acceso denegado: " + e.Message; return 0; }
        catch (EventLogException e) { _errors[channel] = $"{e.GetType().Name}: {e.Message}"; return 0; }
    }
}
