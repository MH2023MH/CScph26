using SecurityAgent.Core.Alerts;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;
using SecurityAgent.Core.Text;
using SecurityAgent.StatusContract;

namespace SecurityAgent.StatusApi;

/// <summary>Lectura del estado del agente para la API. Solo consulta; no expone ninguna operación de escritura.</summary>
public sealed class StatusService
{
    private const int MaxLimit = 200;
    private readonly IStateStore _store;
    private readonly IReadOnlyList<Rule> _rules;
    private readonly Heartbeat _heartbeat;
    private readonly AgentHealth _health;
    private readonly TimeProvider _time;
    private readonly string _version;

    public StatusService(IStateStore store, IReadOnlyList<Rule> rules, Heartbeat heartbeat, TimeProvider? time = null, string? version = null, AgentHealth? health = null)
    {
        _store = store;
        _rules = rules;
        _heartbeat = heartbeat;
        _health = health ?? new AgentHealth();
        _time = time ?? TimeProvider.System;
        _version = version ?? typeof(StatusService).Assembly.GetName().Version?.ToString() ?? "0.0.0";
    }

    public StatusDto GetStatus()
    {
        var now = _time.GetUtcNow();
        var beat = _heartbeat.LastBeat;
        return new StatusDto(_version, now, _heartbeat.StartedAt, beat, beat is null ? null : (now - beat.Value).TotalSeconds,
            _rules.Select(r => new RuleStatusDto(r.Id, Sanitizer.Clean(r.Name)!, RuleModes.Effective(r, _store).ToString().ToLowerInvariant(),
                r.FileMode.ToString().ToLowerInvariant())).ToList(), _health.LogShipping, _health.Integrity, _health.Problems().Select(p => Sanitizer.Clean(p, 300)!).ToList());
    }

    public ListDto<AlertDto> ListAlerts(DateTimeOffset? since, string? ruleId, Severity? minSeverity, string? ip, int limit)
    {
        limit = Math.Clamp(limit, 1, MaxLimit);
        var cleanIp = ip is null ? null : Sanitizer.CleanIp(ip) ?? "\0invalida";
        // El filtro por IP se aplica sobre GroupKey; se pide más para poder filtrar y luego recortar.
        var raw = _store.ListAlerts(since, ruleId, minSeverity, cleanIp is null ? limit : MaxLimit * 5);
        var items = raw.Where(a => cleanIp is null || a.GroupKey == cleanIp).Take(limit).Select(ToDto).ToList();
        return new ListDto<AlertDto>(items, items.Count);
    }

    public ListDto<BlockDto> ListBlocks()
    {
        var items = _store.ListActiveBlocks().Take(MaxLimit)
            .Select(b => new BlockDto(Sanitizer.CleanIp(b.Ip) ?? "(inválida)", b.RuleId, Sanitizer.Clean(b.Reason)!, b.CreatedAt, b.ExpiresAt)).ToList();
        return new ListDto<BlockDto>(items, items.Count);
    }

    public RuleDetailDto? GetRule(string id)
    {
        var r = _rules.FirstOrDefault(x => x.Id == id);
        if (r is null) return null;
        return new RuleDetailDto(r.Id, Sanitizer.Clean(r.Name)!, RuleModes.Effective(r, _store).ToString().ToLowerInvariant(),
            r.FileMode.ToString().ToLowerInvariant(), r.Source, r.EventTypes.OrderBy(x => x).ToList(), r.GroupBy.ToString().ToLowerInvariant(),
            r.Threshold, (int)r.Window.TotalSeconds, r.Severity.ToString().ToLowerInvariant(), r.Action, r.Runbook,
            _store.ListAlerts(ruleId: r.Id, limit: 10).Select(ToDto).ToList());
    }

    public AuditSummaryDto GetAudit()
    {
        AuditEntryDto Of(string kind) => _store.GetAudit(kind) is { } a
            ? new AuditEntryDto(Sanitizer.Clean(a.Status)!, a.CheckedAt, Sanitizer.Clean(a.Summary, 500)!)
            : new AuditEntryDto("sin_datos", null, "No hay información: la auditoría aún no se ha ejecutado.");
        return new AuditSummaryDto(Of(AuditKinds.Hardening), Of(AuditKinds.Certificates), Of(AuditKinds.Backups));
    }

    public EventDetailDto? GetEvent(string id)
    {
        if (id.StartsWith("ALR-", StringComparison.Ordinal))
            return _store.GetAlert(id) is { } a ? new EventDetailDto("alert", null, ToDto(a)) : null;
        return _store.GetEvent(id) is { } e ? new EventDetailDto("event", ToDto(e), null) : null;
    }

    private static AlertDto ToDto(Alert a) => new(a.Id, a.RuleId, a.Timestamp, a.Severity.ToString().ToLowerInvariant(),
        Sanitizer.Clean(a.GroupKey), Sanitizer.Clean(a.Message, 400)!, a.EventIds, a.Mode.ToString().ToLowerInvariant(),
        Sanitizer.Clean(a.ActionTaken, 300));

    private static EventDto ToDto(SecurityEvent e) => new(e.Id, e.Timestamp, Sanitizer.Clean(e.Source)!, Sanitizer.Clean(e.Type)!,
        e.Severity.ToString().ToLowerInvariant(), Sanitizer.Clean(e.Actor), Sanitizer.CleanIp(e.Ip), Sanitizer.Clean(e.Target), Sanitizer.Clean(e.Detail, 300));
}
