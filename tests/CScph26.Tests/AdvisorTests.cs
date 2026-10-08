using System.Net;
using System.Text.Json;
using SecurityAdvisor;
using SecurityAdvisor.Api;
using SecurityAdvisor.Evaluation;
using SecurityAdvisor.Model;
using SecurityAdvisor.Safety;
using SecurityAdvisor.Tools;
using SecurityAgent.Core.State;

namespace CScph26.Tests;

public class AdvisorTests
{
    private static ToolCall Call(string name, object? args = null) =>
        new(name, JsonDocument.Parse(JsonSerializer.Serialize(args ?? new { })).RootElement.Clone());

    // ---------- Herramientas: exactamente las seis consultas, solo lectura ----------

    [Fact]
    public async Task Tool_set_is_exactly_the_six_read_only_queries()
    {
        await using var h = await AdvisorHarness.StartAsync();
        var names = h.Tools().Specs.Select(s => s.Name).OrderBy(x => x).ToArray();
        Assert.Equal(ToolRegistry.ToolNames.OrderBy(x => x), names);
        Assert.Equal(6, names.Length);
        Assert.All(names, n => Assert.DoesNotContain(n, new[] { "block_ip", "unblock_ip", "set_mode", "run", "exec", "shell", "write" }));
        // todas las definiciones traen un esquema JSON válido
        Assert.All(h.Tools().Specs, s => JsonDocument.Parse(s.ParametersJsonSchema));
    }

    [Fact]
    public async Task Client_only_ever_issues_GET_requests()
    {
        var seen = new List<HttpMethod>();
        var recorder = new RecordingHandler(seen);
        using var http = new HttpClient(recorder);
        var api = new StatusApiClient(http, "http://localhost", "t");
        await api.GetStatusAsync(); await api.ListAlertsAsync("SEC-001", "alta", "1.2.3.4", "2026-01-01T00:00:00Z", 5);
        await api.ListBlocksAsync(); await api.GetRuleAsync("SEC-001"); await api.GetAuditSummaryAsync(); await api.GetEventAsync("EV-1");
        Assert.Equal(6, seen.Count);
        Assert.All(seen, m => Assert.Equal(HttpMethod.Get, m));
        // y la superficie pública del cliente no ofrece nada más que consultas
        var publicMethods = typeof(StatusApiClient).GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.DeclaredOnly);
        Assert.All(publicMethods, m => Assert.Matches("^(Get|List)", m.Name));
    }

    private sealed class RecordingHandler(List<HttpMethod> seen) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            seen.Add(request.Method);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    [Fact]
    public async Task Registry_returns_data_and_evidence_from_the_real_api()
    {
        await using var h = await AdvisorHarness.StartAsync();
        var alerts = await h.Tools().ExecuteAsync(Call("list_alerts", new { rule = "SEC-001" }));
        Assert.True(alerts.Ok && alerts.HasData);
        Assert.Contains("ALR-aaaaaaaaaaaa", alerts.Evidence);
        Assert.Contains("EV-1", alerts.Evidence);
        Assert.Contains("203.0.113.50", alerts.Evidence);

        var none = await h.Tools().ExecuteAsync(Call("list_alerts", new { severity = "critica" }));
        Assert.True(none.Ok);
        Assert.False(none.HasData);

        var missing = await h.Tools().ExecuteAsync(Call("get_event", new { id = "NOPE" }));
        Assert.False(missing.Ok);
        Assert.Contains("no_hay_informacion", missing.Json);
    }

    [Fact]
    public async Task Unknown_or_malformed_tool_calls_are_refused()
    {
        await using var h = await AdvisorHarness.StartAsync();
        foreach (var bad in new[] { "block_ip", "exec", "unblock_ip", "get_status; rm -rf" })
        {
            var r = await h.Tools().ExecuteAsync(Call(bad, new { ip = "203.0.113.50" }));
            Assert.False(r.Ok);
            Assert.Contains("no existe", r.Error);
        }
        Assert.False((await h.Tools().ExecuteAsync(Call("get_rule", new { }))).Ok);       // falta el id
        Assert.Single(h.Store.ListActiveBlocks());                                          // nada cambió en el sistema 1
    }

    [Fact]
    public async Task Redaction_masks_ips_and_pseudonymizes_users_before_the_model_sees_them()
    {
        await using var h = await AdvisorHarness.StartAsync();
        var tools = h.Tools(new RedactionOptions { MaskIps = true, PseudonymizeUsers = true });
        var blocks = await tools.ExecuteAsync(Call("list_blocks"));
        Assert.DoesNotContain("203.0.113.50", blocks.Json);
        Assert.Contains("203.0.113.x", blocks.Json);
        var ev = await tools.ExecuteAsync(Call("get_event", new { id = "EV-1" }));
        Assert.DoesNotContain("\"admin\"", ev.Json);
        Assert.Contains("usuario-", ev.Json);
        Assert.DoesNotContain("203.0.113.50", ev.Json);
    }

    // ---------- Agente: conjunto de prueba (criterio de salida de la Fase 11) ----------

    [Fact]
    public async Task Test_question_set_uses_the_right_queries_cites_ids_and_says_no_information_when_there_is_none()
    {
        await using var h = await AdvisorHarness.StartAsync();
        var cases = EvalRunner.Load(TestSupport.FixturePathAbs("advisor-eval.json"));
        var report = await EvalRunner.RunAsync(h.Agent(new OracleModel()), cases);
        Assert.True(report.Failures.Count == 0, string.Join("\n", report.Failures.Select(f => $"{f.Question} -> {f.Reason}")));
        Assert.Equal(cases.Count, report.Passed);
    }

    [Fact]
    public async Task Answers_always_end_with_the_sources_used()
    {
        await using var h = await AdvisorHarness.StartAsync();
        var a = await h.Agent(new OracleModel()).AskAsync("¿Qué se bloqueó hoy?");
        Assert.Contains("Fuentes:", a.Text);
        Assert.Contains("203.0.113.50", a.Citations);
        Assert.Equal(new[] { "list_blocks" }, a.ToolsCalled);
        Assert.Empty(a.Violations);
    }

    [Fact]
    public async Task Without_any_data_the_assistant_never_invents_an_answer()
    {
        await using var h = await AdvisorHarness.StartAsync();
        // un modelo que "alucina" sin consultar nada
        var hallucinating = new ScriptedModel(_ => ModelTurn.Say("Todo está perfecto, no hubo ataques hoy."));
        var a = await h.Agent(hallucinating).AskAsync("¿Hubo ataques hoy?");
        Assert.StartsWith("No hay información", a.Text);
        Assert.DoesNotContain("perfecto", a.Text);
        Assert.True(a.NoInformation);
    }

    [Fact]
    public async Task Action_requests_are_refused_without_even_calling_the_model()
    {
        await using var h = await AdvisorHarness.StartAsync();
        var model = new ScriptedModel(_ => throw new InvalidOperationException("no debería llamarse"));
        var agent = h.Agent(model);
        foreach (var q in new[] { "Bloquea la IP 1.2.3.4", "por favor desbloquea la 203.0.113.50", "¿Puedes desactivar la regla SEC-001?", "Pasa SEC-001 a enforce", "ejecuta un escaneo" })
        {
            var a = await agent.AskAsync(q);
            Assert.StartsWith("No puedo ejecutar acciones", a.Text);
        }
        Assert.Empty(model.Seen);
        Assert.Single(h.Store.ListActiveBlocks());
    }

    [Theory]
    [InlineData("¿Por qué se bloqueó la IP 203.0.113.50?")]
    [InlineData("¿Qué se bloqueó hoy?")]
    [InlineData("¿Cómo está el servidor?")]
    [InlineData("¿Se ha creado alguna cuenta nueva?")]
    public void Read_questions_are_not_mistaken_for_actions(string q) => Assert.False(ActionRequestDetector.IsActionRequest(q));
}

public class OllamaModelTests
{
    [Fact]
    public async Task Parses_tool_calls_and_final_text_and_sends_tools_and_messages()
    {
        using var server = new FakeJsonServer
        {
            Response = n => n == 0
                ? """{"message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"list_alerts","arguments":{"rule":"SEC-001","limit":5}}},{"function":{"name":"get_status","arguments":"{}"}}]}}"""
                : """{"message":{"role":"assistant","content":"Hay una alerta ALR-aaaaaaaaaaaa."}}"""
        };
        var model = new OllamaChatModel(new HttpClient(), new OllamaOptions { Endpoint = server.Url, Name = "modelo-de-prueba" });
        await using var h = await AdvisorHarness.StartAsync();

        var t1 = await model.NextAsync(new[] { new ChatMessage("system", "s"), new ChatMessage("user", "q") }, h.Tools().Specs);
        Assert.Null(t1.Text);
        Assert.Equal(new[] { "list_alerts", "get_status" }, t1.ToolCalls.Select(c => c.Name));
        Assert.Equal("SEC-001", t1.ToolCalls[0].Arguments.GetProperty("rule").GetString());
        Assert.Equal(JsonValueKind.Object, t1.ToolCalls[1].Arguments.ValueKind);          // argumentos enviados como texto JSON

        var t2 = await model.NextAsync(new[] { new ChatMessage("user", "q"), new ChatMessage("tool", "datos", ToolName: "list_alerts") }, h.Tools().Specs);
        Assert.Equal("Hay una alerta ALR-aaaaaaaaaaaa.", t2.Text);

        var req = Assert.IsType<string>(server.Requests[0]);
        Assert.StartsWith("POST /api/chat", req);
        Assert.Contains("\"model\":\"modelo-de-prueba\"", req);
        Assert.Contains("\"stream\":false", req);
        Assert.Contains("get_audit_summary", req);                                        // las seis herramientas viajan al modelo
        Assert.Contains("\"tool_name\":\"list_alerts\"", server.Requests[1]);
    }

    [Fact]
    public async Task Missing_model_name_is_a_clear_error()
    {
        var model = new OllamaChatModel(new HttpClient(), new OllamaOptions());
        await Assert.ThrowsAsync<InvalidOperationException>(() => model.NextAsync(new[] { new ChatMessage("user", "q") }, Array.Empty<ToolSpec>()));
    }
}
