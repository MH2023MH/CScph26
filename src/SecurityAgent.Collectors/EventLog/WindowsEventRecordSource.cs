using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;

namespace SecurityAgent.Collectors.EventLog;

/// <summary>Lectura real del Event Log de Windows por consulta XPath sobre EventRecordID (solo Windows).</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEventRecordSource : IEventRecordSource
{
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
        catch (EventLogNotFoundException) { }            // p. ej. Sysmon aún no instalado
        catch (EventLogException) { }                    // sin permiso o canal deshabilitado: se omite
        return list;
    }

    public long LatestRecordId(string channel)
    {
        try
        {
            var query = new EventLogQuery(channel, PathType.LogName) { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            using var rec = reader.ReadEvent();
            return rec?.RecordId ?? 0;
        }
        catch (EventLogException) { return 0; }
    }
}
