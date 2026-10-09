namespace SecurityAgent.Collectors.EventLog;

public sealed record RawEventRecord(long RecordId, string Xml);

/// <summary>Origen de registros del Event Log. Implementación real: <see cref="WindowsEventRecordSource"/>; en pruebas, archivos XML.</summary>
public interface IEventRecordSource
{
    /// <summary>Registros con RecordId &gt; afterRecordId, en orden ascendente, hasta max. Un canal inexistente devuelve vacío.</summary>
    IReadOnlyList<RawEventRecord> Read(string channel, long afterRecordId, int max);

    /// <summary>RecordId más reciente del canal (0 si vacío o inexistente).</summary>
    long LatestRecordId(string channel);

    /// <summary>Último error al leer el canal (permiso denegado, canal inexistente...), o null si la última lectura fue correcta.</summary>
    string? LastError(string channel) => null;
}
