using SecurityAgent.Core.Events;
using SecurityAgent.Core.State;

namespace SecurityAgent.Core.Alerts;

/// <summary>Alerta generada por una regla. Lo que el sistema 2 cita por ID (principio 13).</summary>
public sealed record Alert(
    string Id,
    string RuleId,
    DateTimeOffset Timestamp,
    Severity Severity,
    string? GroupKey,
    string Message,
    IReadOnlyList<string> EventIds,
    RuleMode Mode,
    string? ActionTaken);
