using System.Text.Json;
using SecurityAdvisor.Api;
using SecurityAdvisor.Model;
using SecurityAdvisor.Safety;
using SecurityAgent.StatusContract;

namespace SecurityAdvisor.Tools;

/// <summary>Resultado de una herramienta: JSON para el modelo y los identificadores que el modelo puede citar porque vienen en campos estructurados.</summary>
public sealed record ToolResult(string Name, bool Ok, bool HasData, string Json, IReadOnlySet<string> Evidence, string? Error);

/// <summary>
/// Las herramientas del sistema 2 son EXACTAMENTE las seis consultas de la API de estado (principio 10).
/// No hay shell, ni escritura, ni acceso a archivos o a agent.db: lo que no está aquí, no existe para el modelo.
/// </summary>
public sealed class ToolRegistry(StatusApiClient api, Redactor redactor)
{
    public static readonly string[] ToolNames = { "get_status", "list_alerts", "list_blocks", "get_rule", "get_audit_summary", "get_event" };

    public IReadOnlyList<ToolSpec> Specs { get; } = new[]
    {
        new ToolSpec("get_status", "Estado general del agente de seguridad: versión, latido, modo (observe/enforce) de cada regla, envío de logs e integridad.", Schema()),
        new ToolSpec("list_alerts", "Alertas recientes, de la más nueva a la más antigua. Filtros opcionales.",
            Schema(null, ("rule", "string", "ID de regla, p. ej. SEC-001"), ("severity", "string", "severidad mínima: info|baja|media|alta|critica"),
                   ("ip", "string", "IP del grupo de la alerta"), ("since", "string", "fecha-hora ISO 8601 (UTC) desde la que buscar"), ("limit", "integer", "máximo de resultados (1-200)"))),
        new ToolSpec("list_blocks", "Bloqueos de IP activos, con regla, motivo y expiración.", Schema()),
        new ToolSpec("get_rule", "Detalle de una regla: modo, umbral, ventana y sus últimas alertas.", Schema(new[] { "id" }, ("id", "string", "ID de la regla, p. ej. SEC-001"))),
        new ToolSpec("get_audit_summary", "Resultado de la última auditoría de hardening, certificados y respaldos.", Schema()),
        new ToolSpec("get_event", "Detalle de un evento o alerta por su ID (ALR-… para alertas).", Schema(new[] { "id" }, ("id", "string", "ID del evento o alerta"))),
    };

    private static string Schema() => Schema(null);
    private static string Schema(string[]? required, params (string Name, string Type, string Description)[] props)
    {
        var p = props.ToDictionary(x => x.Name, x => new { type = x.Type, description = x.Description });
        return JsonSerializer.Serialize(new { type = "object", properties = p, required = required ?? Array.Empty<string>() });
    }

    public async Task<ToolResult> ExecuteAsync(ToolCall call, CancellationToken ct = default)
    {
        string? Str(string name) => call.Arguments.ValueKind == JsonValueKind.Object && call.Arguments.TryGetProperty(name, out var v)
            ? v.ValueKind == JsonValueKind.String ? v.GetString() : v.ToString() : null;
        int? Int(string name) => int.TryParse(Str(name), out var n) ? n : null;

        switch (call.Name)
        {
            case "get_status":
            {
                var r = await api.GetStatusAsync(ct);
                return Build(call.Name, r, v => v.Rules.Select(x => x.Id));
            }
            case "list_alerts":
            {
                var r = await api.ListAlertsAsync(Str("rule"), Str("severity"), Str("ip"), Str("since"), Int("limit"), ct);
                if (r.Ok) r = r with { Value = r.Value! with { Items = r.Value.Items.Select(redactor.Apply).ToList() } };
                return Build(call.Name, r, v => v.Items.SelectMany(a => new[] { a.Id, a.RuleId }.Concat(a.EventIds).Concat(a.GroupKey is { } g && IsIpOrMasked(g) ? new[] { g } : Array.Empty<string>())),
                    v => v.Items.Count > 0);
            }
            case "list_blocks":
            {
                var r = await api.ListBlocksAsync(ct);
                if (r.Ok) r = r with { Value = r.Value! with { Items = r.Value.Items.Select(redactor.Apply).ToList() } };
                return Build(call.Name, r, v => v.Items.SelectMany(b => new[] { b.Ip, b.RuleId }), v => v.Items.Count > 0);
            }
            case "get_rule":
            {
                var id = Str("id");
                if (string.IsNullOrWhiteSpace(id)) return Invalid(call.Name, "falta el parámetro 'id'");
                var r = await api.GetRuleAsync(id, ct);
                if (r.Ok) r = r with { Value = redactor.Apply(r.Value!) };
                return Build(call.Name, r, v => new[] { v.Id }.Concat(v.RecentAlerts.Select(a => a.Id)).Concat(v.RecentAlerts.SelectMany(a => a.EventIds)));
            }
            case "get_audit_summary":
            {
                var r = await api.GetAuditSummaryAsync(ct);
                return Build(call.Name, r, _ => new[] { "hardening", "certificates", "backups" },
                    v => new[] { v.Hardening, v.Certificates, v.Backups }.Any(e => e.Status != "sin_datos" && e.Status != "sin_configurar"));
            }
            case "get_event":
            {
                var id = Str("id");
                if (string.IsNullOrWhiteSpace(id)) return Invalid(call.Name, "falta el parámetro 'id'");
                var r = await api.GetEventAsync(id, ct);
                if (r.Ok) r = r with { Value = redactor.Apply(r.Value!) };
                return Build(call.Name, r, v => v.Event is { } e ? new[] { e.Id }.Concat(e.Ip is null ? Array.Empty<string>() : new[] { e.Ip })
                                              : v.Alert is { } a ? new[] { a.Id, a.RuleId }.Concat(a.EventIds) : Array.Empty<string>());
            }
            default:
                // Cualquier otro nombre (p. ej. un intento del modelo, manipulado o no, de "bloquear_ip" o "ejecutar") no existe.
                return Invalid(call.Name, $"la herramienta '{call.Name}' no existe; solo hay: {string.Join(", ", ToolNames)}");
        }
    }

    /// <summary>La clave de grupo de una alerta puede ser texto del atacante (usuario, ruta...). Solo una IP (o su versión enmascarada) es citable.</summary>
    private static bool IsIpOrMasked(string s) =>
        System.Net.IPAddress.TryParse(s, out _) || System.Text.RegularExpressions.Regex.IsMatch(s, @"^(\d{1,3}\.){3}x$");

    private static ToolResult Invalid(string name, string error) =>
        new(name, false, false, JsonSerializer.Serialize(new { error }), new HashSet<string>(), error);

    private static ToolResult Build<T>(string name, ApiResult<T> r, Func<T, IEnumerable<string>> evidence, Func<T, bool>? hasData = null)
    {
        if (!r.Ok)
            return new ToolResult(name, false, false, JsonSerializer.Serialize(new { error = r.Error, no_hay_informacion = true }), new HashSet<string>(), r.Error);
        var has = hasData?.Invoke(r.Value!) ?? true;
        return new ToolResult(name, true, has, JsonSerializer.Serialize(r.Value, StatusJson.Options),
            new HashSet<string>(evidence(r.Value!), StringComparer.OrdinalIgnoreCase), null);
    }
}
