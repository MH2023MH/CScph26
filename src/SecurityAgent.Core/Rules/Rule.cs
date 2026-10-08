using System.Text.RegularExpressions;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.State;

namespace SecurityAgent.Core.Rules;

public enum GroupBy { None, Ip, Actor, Target }

public static class RuleActions
{
    public const string BlockIp = "firewall.block_ip";
    public const string Notify = "notify";
    public static readonly string[] Known = { BlockIp, Notify };
}

/// <summary>Regla ya validada y lista para evaluar (cargada desde YAML).</summary>
public sealed record Rule(
    string Id,
    string Name,
    RuleMode FileMode,
    string Source,
    IReadOnlySet<string> EventTypes,
    GroupBy GroupBy,
    int Threshold,
    TimeSpan Window,
    Severity Severity,
    bool ExcludeAllowlist,
    string? Action,
    TimeSpan? BlockDuration,
    IReadOnlyList<string> Notify,
    string? Runbook,
    IReadOnlySet<string>? Sources = null,
    IReadOnlyList<EventFilter>? Filters = null,
    IReadOnlyList<EventFilter>? Except = null,
    bool ExcludeDeployWindows = false)
{
    /// <summary>Fuentes aceptadas (una regla puede mirar varias, p. ej. SEC-004: System y Security).</summary>
    public IReadOnlySet<string> AllSources => Sources ?? new HashSet<string> { Source };
    public IReadOnlyList<EventFilter> AllFilters => Filters ?? Array.Empty<EventFilter>();
    public IReadOnlyList<EventFilter> AllExcept => Except ?? Array.Empty<EventFilter>();
}

/// <summary>
/// Condición sobre un campo del evento. Alternativas dentro de 'contiene' son OR (sin distinguir mayúsculas);
/// 'regex' usa el motor NonBacktracking (tiempo lineal: un atacante no puede provocar ReDoS con texto hostil).
/// </summary>
public sealed record EventFilter(string Field, IReadOnlyList<string> Contains, Regex? Pattern, string? ExactValue)
{
    public static readonly string[] Fields = { "objeto", "detalle", "usuario", "texto", "ip", "tipo" };

    public bool Matches(SecurityEvent ev)
    {
        var value = Field switch
        {
            "objeto" => ev.Target,
            "detalle" => ev.Detail,
            "usuario" => ev.Actor,
            "ip" => ev.Ip,
            "tipo" => ev.Type,
            "texto" => string.Join(' ', new[] { ev.Target, ev.Detail }.Where(x => !string.IsNullOrEmpty(x))),
            _ => null
        };
        if (string.IsNullOrEmpty(value)) return false;
        if (ExactValue != null) return value.Equals(ExactValue, StringComparison.OrdinalIgnoreCase);
        if (Contains.Count > 0 && Contains.Any(c => value.Contains(c, StringComparison.OrdinalIgnoreCase))) return true;
        return Pattern != null && Pattern.IsMatch(value);
    }
}

public sealed record RuleHit(Rule Rule, string GroupKey, IReadOnlyList<string> EventIds, DateTimeOffset Timestamp)
{
    /// <summary>IP objetivo cuando la regla agrupa por IP.</summary>
    public string? Ip => Rule.GroupBy == GroupBy.Ip ? GroupKey : null;
}
