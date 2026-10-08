using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using SecurityAdvisor;
using SecurityAdvisor.Api;
using SecurityAdvisor.Model;
using SecurityAdvisor.Safety;
using SecurityAdvisor.Tools;
using SecurityAgent.Core.Alerts;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;
using SecurityAgent.StatusApi;

namespace CScph26.Tests;

/// <summary>API de estado REAL (servidor en memoria) sobre un State Store sembrado: el advisor la consulta como en producción.</summary>
internal sealed class AdvisorHarness : IAsyncDisposable
{
    public const string Token = "advisor-test-token";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cscph26-adv-" + Guid.NewGuid().ToString("N"));
    public SqliteStateStore Store { get; }
    public WebApplication App { get; private set; } = null!;
    public HttpClient Http { get; private set; } = null!;
    public StatusApiClient Api { get; private set; } = null!;
    public Heartbeat Heartbeat { get; } = new();

    public AdvisorHarness() => Store = new(new StateStoreOptions { DatabasePath = Path.Combine(_dir, "agent.db") });

    public static async Task<AdvisorHarness> StartAsync(Action<SqliteStateStore>? seed = null)
    {
        var h = new AdvisorHarness();
        (seed ?? Seed)(h.Store);
        h.Heartbeat.Beat();
        var service = new StatusService(h.Store, RuleLoader.LoadDirectory(TestSupport.RulesDir), h.Heartbeat, version: "test");
        var b = WebApplication.CreateBuilder();
        b.WebHost.UseTestServer();
        h.App = b.Build();
        h.App.Use((ctx, next) => { ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.99"); return next(); });
        h.App.MapStatusApi(service, new StatusApiOptions { Token = Token, AllowedClients = { "192.168.0.0/16" } });
        await h.App.StartAsync();
        h.Http = h.App.GetTestClient();
        h.Api = new StatusApiClient(h.Http, "http://localhost", Token);
        return h;
    }

    public static void Seed(SqliteStateStore s)
    {
        var t = DateTimeOffset.Parse("2026-10-08T03:10:15Z");
        s.AddEvent(new("EV-1", t, "eventlog.security", "4625", Severity.Media, "admin", "203.0.113.50", "x"));
        s.AddAlert(new("ALR-aaaaaaaaaaaa", "SEC-001", t, Severity.Alta, "203.0.113.50", "SEC-001 Fuerza bruta RDP: 8 evento(s) en 5 min para '203.0.113.50'",
            new[] { "EV-1" }, RuleMode.Observe, "observe: no se ejecutó firewall.block_ip sobre 203.0.113.50"));
        s.AddBlock(new("203.0.113.50", "SEC-001", "Fuerza bruta RDP", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1)));
        s.SetAudit(new(AuditKinds.Certificates, "ok", DateTimeOffset.UtcNow, "2 certificado(s) de servidor revisados; ninguno vence en menos de 30 días."));
    }

    public ToolRegistry Tools(RedactionOptions? redaction = null) => new(Api, new Redactor(redaction ?? new RedactionOptions()));

    public AdvisorAgent Agent(ILanguageModel model, RedactionOptions? redaction = null) => new(model, Tools(redaction), new AdvisorOptions());

    public async ValueTask DisposeAsync()
    {
        Http.Dispose();
        await App.DisposeAsync();
        Store.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch { }
    }
}

internal sealed class ScriptedModel(Func<IReadOnlyList<ChatMessage>, ModelTurn> script) : ILanguageModel
{
    public List<IReadOnlyList<ChatMessage>> Seen { get; } = new();
    public Task<ModelTurn> NextAsync(IReadOnlyList<ChatMessage> messages, IReadOnlyList<ToolSpec> tools, CancellationToken ct = default)
    {
        Seen.Add(messages.ToList());
        return Task.FromResult(script(messages));
    }
}

/// <summary>
/// Sustituto determinista de un LLM capaz, para probar el agente sin hardware de modelo: elige herramientas por palabras clave
/// y redacta la respuesta solo con lo que hay en los bloques de datos. Valida el cableado y las salvaguardas, NO la calidad de un modelo real.
/// </summary>
internal sealed class OracleModel : ILanguageModel
{
    private static ToolCall Call(string name, object? args = null) =>
        new(name, JsonDocument.Parse(JsonSerializer.Serialize(args ?? new { })).RootElement.Clone());

    public Task<ModelTurn> NextAsync(IReadOnlyList<ChatMessage> messages, IReadOnlyList<ToolSpec> tools, CancellationToken ct = default)
    {
        var last = messages[^1];
        if (last.Role == "user" && messages.Count(m => m.Role == "tool") == 0) return Task.FromResult(Plan(last.Content ?? ""));

        // Respuesta a partir de los datos recibidos (solo de los bloques delimitados)
        var data = messages.Where(m => m.Role == "tool").Select(m => (m.ToolName!, Body(m.Content!))).ToList();
        var lines = new List<string>();
        foreach (var (tool, body) in data)
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.TryGetProperty("no_hay_informacion", out _)) { lines.Add($"No hay información ({tool}: {root.GetProperty("error").GetString()})."); continue; }
            switch (tool)
            {
                case "get_status":
                    lines.Add("Agente activo (latido reciente). Reglas: " + string.Join(", ", root.GetProperty("rules").EnumerateArray().Select(r => $"{r.GetProperty("id").GetString()} en {r.GetProperty("mode").GetString()}")) + ".");
                    break;
                case "list_blocks":
                    var blocks = root.GetProperty("items").EnumerateArray().ToList();
                    lines.Add(blocks.Count == 0 ? "No hay información: sin bloqueos activos." : "Bloqueos activos: " + string.Join("; ", blocks.Select(b => $"{b.GetProperty("ip").GetString()} por {b.GetProperty("rule_id").GetString()}")) + ".");
                    break;
                case "list_alerts":
                    var alerts = root.GetProperty("items").EnumerateArray().ToList();
                    lines.Add(alerts.Count == 0 ? "No hay información: no hay alertas que cumplan el filtro." : "Alertas: " + string.Join("; ", alerts.Select(a => $"{a.GetProperty("id").GetString()} ({a.GetProperty("rule_id").GetString()}, {a.GetProperty("mode").GetString()})")) + ".");
                    break;
                case "get_audit_summary":
                    lines.Add("Auditorías: " + string.Join("; ", new[] { "hardening", "certificates", "backups" }.Select(k =>
                        root.GetProperty(k).GetProperty("status").GetString() == "sin_datos" ? $"{k}: No hay información" : $"{k}: {root.GetProperty(k).GetProperty("status").GetString()}")) + ".");
                    break;
                case "get_event":
                    lines.Add(root.TryGetProperty("event", out var ev) && ev.ValueKind == JsonValueKind.Object ? $"Evento {ev.GetProperty("id").GetString()} de {ev.GetProperty("source").GetString()}." : "Alerta registrada.");
                    break;
            }
        }
        return Task.FromResult(ModelTurn.Say(string.Join(" ", lines)));
    }

    private static string Body(string wrapped)
    {
        var start = wrapped.IndexOf("\n", StringComparison.Ordinal) + 1;
        var end = wrapped.LastIndexOf("\n<<FIN_", StringComparison.Ordinal);
        return wrapped[start..end];
    }

    private static ModelTurn Plan(string q)
    {
        var l = q.ToLowerInvariant();
        var id = Regex.Match(q, @"\b(?:EV-\d+|[a-z]+-\d+|ALR-[0-9a-f]{12})\b", RegexOptions.IgnoreCase).Value;
        if (l.Contains("evento") && id != "") return ModelTurn.Call(Call("get_event", new { id }));
        if (l.Contains("respaldo") || l.Contains("auditor") || l.Contains("certificado")) return ModelTurn.Call(Call("get_audit_summary"));
        if (l.Contains("bloque")) return ModelTurn.Call(Call("list_blocks"));
        if (l.Contains("críticas") || l.Contains("criticas")) return ModelTurn.Call(Call("list_alerts", new { severity = "critica" }));
        if (l.Contains("saltó") || l.Contains("salto") || l.Contains("alerta")) return ModelTurn.Call(Call("list_alerts", new { rule = Regex.Match(q, @"SEC-\d{3}").Value is { Length: > 0 } r ? r : null }));
        return ModelTurn.Call(Call("get_status"));
    }
}
