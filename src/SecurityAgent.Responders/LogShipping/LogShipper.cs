using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecurityAgent.Core.Alerts;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.State;

namespace SecurityAgent.Responders.LogShipping;

public sealed class LogShipperOptions
{
    public int BatchSize { get; set; } = 500;
    /// <summary>Fuentes de eventos que se envían además de TODAS las alertas. Vacío = valores por defecto (IIS queda fuera por volumen: lo relevante llega como alerta).</summary>
    public List<string> EventSources { get; set; } = new();
    public static readonly string[] DefaultEventSources = { "eventlog.security", "eventlog.system", "defender", "sysmon", "sql", "fs" };
    public IReadOnlyList<string> EffectiveEventSources => EventSources.Count > 0 ? EventSources : DefaultEventSources.ToList();
    public TimeSpan StatusInterval { get; set; } = TimeSpan.FromHours(1);
}

/// <summary>
/// Envía alertas y eventos del State Store a un destino externo leyendo desde un cursor persistente.
/// Si el destino no responde el cursor no avanza y se reintenta: nada se pierde mientras no se purgue localmente.
/// </summary>
public sealed class LogShipper
{
    public const string EventsCursor = "ship:events";
    public const string AlertsCursor = "ship:alerts";

    private readonly IStateStore _store;
    private readonly ILogSink _sink;
    private readonly LogShipperOptions _opt;
    private readonly TimeProvider _time;
    private readonly ILogger? _log;
    private readonly Func<IReadOnlyDictionary<string, string?>>? _statusInfo;
    private readonly string _host = Environment.MachineName;
    private DateTimeOffset _lastStatus = DateTimeOffset.MinValue;

    public LogShipper(IStateStore store, ILogSink sink, LogShipperOptions options, TimeProvider? time = null, ILogger? log = null,
        Func<IReadOnlyDictionary<string, string?>>? statusInfo = null)
    {
        _store = store;
        _sink = sink;
        _opt = options;
        _time = time ?? TimeProvider.System;
        _log = log;
        _statusInfo = statusInfo;
    }

    public int ConsecutiveFailures { get; private set; }

    /// <summary>Un ciclo de envío. Devuelve cuántos registros salieron (0 si no había nada o falló el destino).</summary>
    public async Task<int> ShipOnceAsync(CancellationToken ct = default)
    {
        var sources = _opt.EffectiveEventSources.ToHashSet(StringComparer.Ordinal);
        var alertCursor = _store.GetCursor(AlertsCursor) ?? 0;
        var eventCursor = _store.GetCursor(EventsCursor) ?? 0;

        var alerts = _store.AlertsAfter(alertCursor, _opt.BatchSize);
        var events = _store.EventsAfter(eventCursor, _opt.BatchSize);

        var lines = new List<string>(alerts.Count + events.Count + 1);
        lines.AddRange(alerts.Select(a => Serialize(AlertRecord(a.Item))));
        lines.AddRange(events.Where(e => sources.Contains(e.Item.Source)).Select(e => Serialize(EventRecord(e.Item))));

        var now = _time.GetUtcNow();
        var statusDue = _statusInfo != null && now - _lastStatus >= _opt.StatusInterval;
        if (statusDue) lines.Add(Serialize(StatusRecord(now)));

        if (lines.Count == 0 && alerts.Count == 0 && events.Count == 0) return 0;
        try
        {
            if (lines.Count > 0) await _sink.SendAsync(lines, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e)
        {
            ConsecutiveFailures++;
            _log?.LogWarning(e, "No se pudieron enviar {Count} registros al destino externo (fallos seguidos: {N})", lines.Count, ConsecutiveFailures);
            return 0;
        }

        ConsecutiveFailures = 0;
        if (alerts.Count > 0) _store.SetCursor(AlertsCursor, alerts[^1].RowId);
        if (events.Count > 0) _store.SetCursor(EventsCursor, events[^1].RowId);   // también avanza sobre los filtrados (no se reenvían)
        if (statusDue) _lastStatus = now;
        return lines.Count;
    }

    private Dictionary<string, object?> AlertRecord(Alert a) => new()
    {
        ["type"] = "alert", ["host"] = _host, ["id"] = a.Id, ["rule_id"] = a.RuleId, ["timestamp"] = a.Timestamp,
        ["severity"] = a.Severity.ToString().ToLowerInvariant(), ["group_key"] = a.GroupKey, ["message"] = a.Message,
        ["event_ids"] = a.EventIds, ["mode"] = a.Mode.ToString().ToLowerInvariant(), ["action"] = a.ActionTaken,
    };

    private Dictionary<string, object?> EventRecord(SecurityEvent e) => new()
    {
        ["type"] = "event", ["host"] = _host, ["id"] = e.Id, ["timestamp"] = e.Timestamp, ["source"] = e.Source, ["event_type"] = e.Type,
        ["severity"] = e.Severity.ToString().ToLowerInvariant(), ["actor"] = e.Actor, ["ip"] = e.Ip, ["target"] = e.Target, ["detail"] = e.Detail,
    };

    private Dictionary<string, object?> StatusRecord(DateTimeOffset now)
    {
        var d = new Dictionary<string, object?> { ["type"] = "agent_status", ["host"] = _host, ["timestamp"] = now };
        foreach (var kv in _statusInfo!()) d[kv.Key] = kv.Value;
        return d;
    }

    private static string Serialize(object o) => JsonSerializer.Serialize(o);
}
