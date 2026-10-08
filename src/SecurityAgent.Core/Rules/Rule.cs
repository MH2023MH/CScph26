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
    string? Runbook);

public sealed record RuleHit(Rule Rule, string GroupKey, IReadOnlyList<string> EventIds, DateTimeOffset Timestamp)
{
    /// <summary>IP objetivo cuando la regla agrupa por IP.</summary>
    public string? Ip => Rule.GroupBy == GroupBy.Ip ? GroupKey : null;
}
