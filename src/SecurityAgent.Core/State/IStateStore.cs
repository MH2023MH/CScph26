using SecurityAgent.Core.Alerts;
using SecurityAgent.Core.Events;

namespace SecurityAgent.Core.State;

public enum RuleMode { Observe, Enforce }

/// <summary>Bloqueo de IP con expiración obligatoria (principio 3).</summary>
public sealed record BlockEntry(string Ip, string RuleId, string Reason, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt);

public static class AuditKinds
{
    public const string Hardening = "hardening";
    public const string Certificates = "certificates";
    public const string Backups = "backups";
}

/// <summary>Resultado de una auditoría periódica (la escribe el Scheduler; la API de estado la lee).</summary>
public sealed record AuditEntry(string Kind, string Status, DateTimeOffset CheckedAt, string Summary);

/// <summary>Elemento con su posición (rowid) en el State Store; sirve de cursor para el envío de logs al exterior.</summary>
public sealed record Stored<T>(long RowId, T Item);

public sealed record PurgeResult(int EventsDeleted, int BlocksDeleted);

public interface IStateStore
{
    void AddEvent(SecurityEvent ev);
    SecurityEvent? GetEvent(string id);
    IReadOnlyList<SecurityEvent> QueryEvents(DateTimeOffset? since = null, string? source = null, string? ip = null, int limit = 100);

    /// <summary>Eventos con rowid &gt; afterRowId, en orden de inserción (para enviarlos fuera del servidor).</summary>
    IReadOnlyList<Stored<SecurityEvent>> EventsAfter(long afterRowId, int limit);
    IReadOnlyList<Stored<Alert>> AlertsAfter(long afterRowId, int limit);

    void AddBlock(BlockEntry block);
    IReadOnlyList<BlockEntry> ListActiveBlocks();
    bool RemoveBlock(string ip);
    /// <summary>Bloqueos vencidos que aún no se han retirado del firewall.</summary>
    IReadOnlyList<BlockEntry> ListExpiredBlocks();

    void AddAlert(Alert alert);
    Alert? GetAlert(string id);
    IReadOnlyList<Alert> ListAlerts(DateTimeOffset? since = null, string? ruleId = null, Severity? minSeverity = null, int limit = 100);

    /// <summary>Posición de lectura de un collector (offset de archivo, último RecordId...). Sobrevive a reinicios.</summary>
    long? GetCursor(string name);
    void SetCursor(string name, long value);

    void SetAudit(AuditEntry audit);
    AuditEntry? GetAudit(string kind);

    /// <summary>Las reglas sin estado guardado arrancan en Observe (principio 1).</summary>
    RuleMode GetRuleMode(string ruleId);
    void SetRuleMode(string ruleId, RuleMode mode);

    /// <summary>Aplica retención, tope de eventos, tope de tamaño y limpia bloqueos expirados.</summary>
    PurgeResult Purge();
}
