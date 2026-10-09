using System.Text.Json;
using SecurityAdvisor;
using SecurityAdvisor.Model;
using SecurityAdvisor.Safety;
using SecurityAgent.Core.Alerts;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;

namespace CScph26.Tests;

/// <summary>Cobertura de la redacción (qué datos no llegan al modelo) y de la limpieza de lo que ve el usuario.</summary>
public class AdvisorRedactionTests
{
    private static ToolCall Call(string name, object? args = null) =>
        new(name, JsonDocument.Parse(JsonSerializer.Serialize(args ?? new { })).RootElement.Clone());

    private static readonly RedactionOptions Full = new() { MaskIps = true, PseudonymizeUsers = true };

    [Fact]
    public async Task Rule_details_and_alert_details_are_redacted_including_free_text()
    {
        await using var h = await AdvisorHarness.StartAsync();
        var tools = h.Tools(Full);

        foreach (var (tool, args) in new (string, object)[] { ("get_rule", new { id = "SEC-001" }), ("get_event", new { id = "ALR-aaaaaaaaaaaa" }), ("list_alerts", new { }) })
        {
            var r = await tools.ExecuteAsync(Call(tool, args));
            Assert.True(r.Ok, tool);
            Assert.DoesNotContain("203.0.113.50", r.Json);   // ni en GroupKey, ni en el mensaje, ni en la acción tomada
            Assert.Contains("203.0.113.x", r.Json);
        }
    }

    [Fact]
    public async Task Users_and_ips_in_event_text_fields_are_scrubbed()
    {
        await using var h = await AdvisorHarness.StartAsync(s =>
            s.AddEvent(new("EV-9", DateTimeOffset.Parse("2026-10-08T03:10:15Z"), "eventlog.security", "4625", Severity.Media,
                @"CORP\jperez", "198.51.100.7", @"cuenta CORP\jperez", @"login de corp\JPEREZ desde 198.51.100.7 y 2001:db8::1.")));
        var r = await h.Tools(Full).ExecuteAsync(Call("get_event", new { id = "EV-9" }));
        Assert.True(r.Ok);
        Assert.DoesNotContain("jperez", r.Json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("198.51.100.7", r.Json);
        Assert.DoesNotContain("2001:db8", r.Json);
        Assert.Contains("usuario-", r.Json);
    }

    [Fact]
    public async Task Without_redaction_options_nothing_changes()
    {
        await using var h = await AdvisorHarness.StartAsync();
        var r = await h.Tools().ExecuteAsync(Call("get_rule", new { id = "SEC-001" }));
        Assert.Contains("203.0.113.50", r.Json);
    }

    [Theory]
    [InlineData("desde 203.0.113.50 y 10.1.2.3.", "desde 203.0.113.x y 10.1.2.x.")]
    [InlineData("conexión 203.0.113.50:8080 rechazada", "conexión 203.0.113.x:8080 rechazada")]
    [InlineData("origen 2001:db8::1.", "origen ip-oculta.")]
    [InlineData("origen ::ffff:203.0.113.50 fin", "origen ip-oculta fin")]
    [InlineData("a las 12:30:45 de hoy", "a las 12:30:45 de hoy")]
    [InlineData("versión 1.2.3 y host cafe", "versión 1.2.3 y host cafe")]
    [InlineData("999.1.1.1 no es una IP", "999.1.1.1 no es una IP")]
    public void Text_masks_ip_literals_but_leaves_times_and_versions(string input, string expected) =>
        Assert.Equal(expected, new Redactor(new RedactionOptions { MaskIps = true }).Text(input));

    [Fact]
    public void Text_pseudonymizes_known_users_case_insensitively_and_longest_first()
    {
        var r = new Redactor(new RedactionOptions { PseudonymizeUsers = true });
        var text = r.Text(@"CORP\ana y CORP\anabel y corp\ANA", @"CORP\ana", @"CORP\anabel")!;
        Assert.DoesNotContain("ana", text.Replace("usuario-", ""), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(3, text.Split("usuario-").Length - 1);
        Assert.Equal(r.User(@"CORP\anabel"), text.Split(" y ")[1]);
    }

    [Fact]
    public void Text_is_a_no_op_when_both_options_are_off() =>
        Assert.Equal("desde 203.0.113.50", new Redactor(new RedactionOptions()).Text("desde 203.0.113.50", "x"));

    // ---------- Lo que ve el usuario ----------

    [Fact]
    public void Output_sanitizer_drops_terminal_escapes_and_bidi_marks_but_keeps_text_layout()
    {
        var dirty = "Título\u001b]0;pwn\u0007\u001b[31m rojo\u001b[0m\r\nlínea\t2 ‮atnatsuca⁦ fin";
        var clean = OutputSanitizer.Clean(dirty);
        Assert.DoesNotContain('\u001b', clean);
        Assert.DoesNotContain('\u0007', clean);
        Assert.DoesNotContain('‮', clean);
        Assert.DoesNotContain('⁦', clean);
        Assert.DoesNotContain('\r', clean);
        Assert.Contains("\nlínea\t2", clean);
        Assert.Contains("Título", clean);
        Assert.Contains("😀", OutputSanitizer.Clean("ok 😀"));
    }

    [Fact]
    public async Task Answer_text_never_carries_control_sequences_from_the_model_or_from_a_hostile_tool_name()
    {
        await using var h = await AdvisorHarness.StartAsync();
        var model = new ScriptedModel(msgs => msgs.Any(m => m.Role == "tool")
            ? ModelTurn.Say("Hay una alerta ALR-aaaaaaaaaaaa \u001b]0;pwned\u0007\u001b[2J de SEC-001.")
            : ModelTurn.Call(Call("list_alerts"), Call("\u001b[31mformatear_disco")));
        var a = await h.Agent(model).AskAsync("¿Qué alertas hay?");
        Assert.DoesNotContain('\u001b', a.Text);
        Assert.DoesNotContain('\u0007', a.Text);
        Assert.Contains("ALR-aaaaaaaaaaaa", a.Text);
    }
}
