namespace SecurityAgent.Collectors.Audits;

public static class AuditStatus
{
    public const string Ok = "ok";
    public const string Warn = "warn";
    public const string Fail = "fail";
    public const string NotConfigured = "sin_configurar";
    public const string Error = "error";
}

public sealed record AuditOutcome(string Status, string Summary, IReadOnlyList<string> Findings)
{
    /// <summary>Huella estable del resultado para no repetir la misma alerta en cada ciclo.</summary>
    public string Fingerprint => Status + "|" + string.Join(";", Findings.OrderBy(x => x, StringComparer.Ordinal));
}

/// <summary>Auditoría periódica (Scheduler). El resultado se guarda en el State Store y la API de estado lo expone.</summary>
public interface IAudit
{
    /// <summary>hardening | certificates | backups</summary>
    string Kind { get; }
    /// <summary>ID de regla bajo el que se emite la alerta cuando el resultado empeora (p. ej. SEC-009).</summary>
    string AlertRuleId { get; }
    TimeSpan Interval { get; }
    Task<AuditOutcome> RunAsync(CancellationToken ct = default);
}
