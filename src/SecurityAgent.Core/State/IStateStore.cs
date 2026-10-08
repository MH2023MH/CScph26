using SecurityAgent.Core.Events;

namespace SecurityAgent.Core.State;

public enum RuleMode { Observe, Enforce }

/// <summary>Bloqueo de IP con expiración obligatoria (principio 3).</summary>
public sealed record BlockEntry(string Ip, string RuleId, string Reason, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt);

public sealed record PurgeResult(int EventsDeleted, int BlocksDeleted);

public interface IStateStore
{
    void AddEvent(SecurityEvent ev);
    SecurityEvent? GetEvent(string id);
    IReadOnlyList<SecurityEvent> QueryEvents(DateTimeOffset? since = null, string? source = null, string? ip = null, int limit = 100);

    void AddBlock(BlockEntry block);
    IReadOnlyList<BlockEntry> ListActiveBlocks();
    bool RemoveBlock(string ip);

    /// <summary>Las reglas sin estado guardado arrancan en Observe (principio 1).</summary>
    RuleMode GetRuleMode(string ruleId);
    void SetRuleMode(string ruleId, RuleMode mode);

    /// <summary>Aplica retención, tope de eventos, tope de tamaño y limpia bloqueos expirados.</summary>
    PurgeResult Purge();
}
