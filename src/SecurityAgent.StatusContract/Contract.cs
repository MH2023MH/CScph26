using System.Text.Json;

namespace SecurityAgent.StatusContract;

// Contrato de la API de estado (solo lectura). Sin dependencias: lo usan el servidor (StatusApi) y el cliente (SecurityAdvisor).
// Los campos de texto que provienen del exterior (actor, objeto, mensaje, motivo) llegan ya saneados.

public sealed record RuleStatusDto(string Id, string Name, string Mode, string FileMode);

public sealed record StatusDto(
    string Version, DateTimeOffset ServerTime, DateTimeOffset StartedAt,
    DateTimeOffset? HeartbeatAt, double? HeartbeatAgeSeconds, IReadOnlyList<RuleStatusDto> Rules,
    string LogShipping = "disabled", string Integrity = "unknown");

public sealed record AlertDto(
    string Id, string RuleId, DateTimeOffset Timestamp, string Severity, string? GroupKey, string Message,
    IReadOnlyList<string> EventIds, string Mode, string? ActionTaken);

public sealed record BlockDto(string Ip, string RuleId, string Reason, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt);

public sealed record ListDto<T>(IReadOnlyList<T> Items, int Count);

public sealed record RuleDetailDto(
    string Id, string Name, string Mode, string FileMode, string Source, IReadOnlyList<string> EventTypes,
    string GroupBy, int Threshold, int WindowSeconds, string Severity, string? Action, string? Runbook,
    IReadOnlyList<AlertDto> RecentAlerts);

public sealed record AuditEntryDto(string Status, DateTimeOffset? CheckedAt, string Summary);

public sealed record AuditSummaryDto(AuditEntryDto Hardening, AuditEntryDto Certificates, AuditEntryDto Backups);

public sealed record EventDto(
    string Id, DateTimeOffset Timestamp, string Source, string Type, string Severity, string? Actor, string? Ip, string? Target, string? Detail = null);

/// <summary>Kind: "event" o "alert".</summary>
public sealed record EventDetailDto(string Kind, EventDto? Event, AlertDto? Alert);

public sealed record ErrorDto(string Error);

public static class StatusJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower,
    };
}

/// <summary>Rutas de la API v1 (nombre de herramienta del sistema 2 → ruta).</summary>
public static class StatusRoutes
{
    public const string Status = "/api/v1/status";          // get_status
    public const string Alerts = "/api/v1/alerts";          // list_alerts
    public const string Blocks = "/api/v1/blocks";          // list_blocks
    public const string Rule = "/api/v1/rules/{id}";        // get_rule
    public const string Audit = "/api/v1/audit";            // get_audit_summary
    public const string Event = "/api/v1/events/{id}";      // get_event
}
