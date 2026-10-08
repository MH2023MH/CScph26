using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SecurityAgent.Core.Alerts;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.Integrity;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;
using SecurityAgent.Responders.LogShipping;
using SecurityAgent.Responders.Notifications;
using SecurityAgent.Worker;

namespace CScph26.Tests;

public sealed class IntegrityTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "cscph26-int-" + Guid.NewGuid().ToString("N"));
    private static readonly byte[] Key = Encoding.UTF8.GetBytes("clave-de-prueba");

    public IntegrityTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "rules"));
        Directory.CreateDirectory(Path.Combine(_root, "data"));
        Directory.CreateDirectory(Path.Combine(_root, "logs"));
        File.WriteAllText(Path.Combine(_root, "SecurityAgent.Worker.dll"), "binario v1");
        File.WriteAllText(Path.Combine(_root, "SecurityAgent.Worker.exe"), "exe v1");
        File.WriteAllText(Path.Combine(_root, "appsettings.json"), "{}");
        File.WriteAllText(Path.Combine(_root, "rules", "SEC-001.yaml"), "id: SEC-001\n");
        File.WriteAllText(Path.Combine(_root, "rules", "allowlist.yaml"), "red_interna: [192.168.0.0/16]\n");
        File.WriteAllText(Path.Combine(_root, "data", "agent.db.json"), "cambia siempre");        // no se protege
        File.WriteAllText(Path.Combine(_root, "logs", "x.json"), "cambia siempre");             // no se protege
        File.WriteAllText(Path.Combine(_root, "notas.txt"), "irrelevante");                      // patrón no protegido
    }

    private void Seal(byte[]? key = null) =>
        File.WriteAllText(Path.Combine(_root, IntegrityManifest.FileName), IntegrityManifest.Create(_root, key).ToJson());

    [Fact]
    public void Untouched_install_verifies_ok_and_ignores_data_logs_and_unprotected_patterns()
    {
        Seal(Key);
        var r = IntegrityVerifier.Verify(_root, Key);
        Assert.True(r.Ok, r.Describe());
        var m = IntegrityManifest.FromJson(File.ReadAllText(Path.Combine(_root, IntegrityManifest.FileName)));
        Assert.Equal(5, m.Files.Count);
        Assert.DoesNotContain(m.Files.Keys, k => k.StartsWith("data/") || k.StartsWith("logs/") || k.EndsWith(".txt"));
    }

    [Fact]
    public void Modified_binary_is_detected()
    {
        Seal(Key);
        File.WriteAllText(Path.Combine(_root, "SecurityAgent.Worker.dll"), "binario troyanizado");
        var r = IntegrityVerifier.Verify(_root, Key);
        Assert.False(r.Ok);
        Assert.Equal(new[] { "SecurityAgent.Worker.dll" }, r.Modified);
    }

    [Fact]
    public void Modified_rule_or_allowlist_is_detected()
    {
        Seal(Key);
        File.WriteAllText(Path.Combine(_root, "rules", "allowlist.yaml"), "red_interna: [0.0.0.0/0]\n");   // ampliar la lista blanca para desactivar la protección
        Assert.Equal(new[] { "rules/allowlist.yaml" }, IntegrityVerifier.Verify(_root, Key).Modified);
    }

    [Fact]
    public void Deleted_and_planted_files_are_detected()
    {
        Seal(Key);
        File.Delete(Path.Combine(_root, "rules", "SEC-001.yaml"));
        File.WriteAllText(Path.Combine(_root, "evil.dll"), "plantado");
        File.WriteAllText(Path.Combine(_root, "rules", "SEC-999.yaml"), "id: SEC-999\n");
        var r = IntegrityVerifier.Verify(_root, Key);
        Assert.Equal(new[] { "rules/SEC-001.yaml" }, r.Missing);
        Assert.Equal(new[] { "evil.dll", "rules/SEC-999.yaml" }, r.Unexpected);
    }

    [Fact]
    public void Regenerating_the_manifest_without_the_key_is_rejected()
    {
        Seal(Key);
        File.WriteAllText(Path.Combine(_root, "SecurityAgent.Worker.dll"), "binario troyanizado");
        // el atacante recalcula el manifiesto pero no conoce la clave
        File.WriteAllText(Path.Combine(_root, IntegrityManifest.FileName), IntegrityManifest.Create(_root, null).ToJson());
        var r = IntegrityVerifier.Verify(_root, Key);
        Assert.False(r.SignatureValid);
        Assert.False(r.Ok);
        // con otra clave tampoco
        File.WriteAllText(Path.Combine(_root, IntegrityManifest.FileName), IntegrityManifest.Create(_root, Encoding.UTF8.GetBytes("otra")).ToJson());
        Assert.False(IntegrityVerifier.Verify(_root, Key).SignatureValid);
    }

    [Fact]
    public void Missing_or_corrupt_manifest_is_a_violation()
    {
        Assert.False(IntegrityVerifier.Verify(_root, Key).ManifestPresent);
        File.WriteAllText(Path.Combine(_root, IntegrityManifest.FileName), "{ no es json");
        var r = IntegrityVerifier.Verify(_root, Key);
        Assert.True(r.ManifestPresent);
        Assert.False(r.Ok);
    }

    public void Dispose() { try { Directory.Delete(_root, true); } catch { } }
}

public sealed class IntegrityMonitorTests : StoreTestBase
{
    [Fact]
    public async Task Alerts_once_per_change_and_reports_restoration()
    {
        var root = Path.Combine(Dir, "app");
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "a.dll"), "v1");
        File.WriteAllText(Path.Combine(root, IntegrityManifest.FileName), IntegrityManifest.Create(root).ToJson());

        var health = new AgentHealth();
        var publisher = new SystemAlertPublisher(Store, new NotificationDispatcher(Array.Empty<IAlertNotifier>()));
        var monitor = new IntegrityMonitor(new AgentOptions(), publisher, health, NullLogger<IntegrityMonitor>.Instance) { Root = root };

        await monitor.CheckOnceAsync();
        Assert.Equal("ok", health.Integrity);
        Assert.Empty(Store.ListAlerts());                            // el primer chequeo sano no alerta

        File.WriteAllText(Path.Combine(root, "a.dll"), "troyano");
        await monitor.CheckOnceAsync();
        await monitor.CheckOnceAsync();                              // mismo estado: sin alerta duplicada
        var alert = Assert.Single(Store.ListAlerts());
        Assert.Equal("SELF-INTEGRITY", alert.RuleId);
        Assert.Equal(Severity.Critica, alert.Severity);
        Assert.Contains("a.dll", alert.Message);
        Assert.Equal("violated", health.Integrity);

        File.WriteAllText(Path.Combine(root, "a.dll"), "v1");
        await monitor.CheckOnceAsync();
        Assert.Equal(2, Store.ListAlerts().Count);
        Assert.Equal("ok", health.Integrity);
    }
}

public sealed class LogShipperTests : StoreTestBase
{
    private static Alert MakeAlert(string id) => new(id, "SEC-001", DateTimeOffset.Parse("2026-10-08T03:10:15Z"), Severity.Alta, "203.0.113.50",
        "m", new[] { "E1" }, RuleMode.Observe, "observe");
    private static SecurityEvent MakeEvent(string id, string source) =>
        new(id, DateTimeOffset.Parse("2026-10-08T03:10:01Z"), source, "4625", Severity.Info, "admin", "203.0.113.50");

    private sealed class FlakySink : ILogSink
    {
        public bool Fail { get; set; }
        public List<string> Lines { get; } = new();
        public Task SendAsync(IReadOnlyList<string> jsonLines, CancellationToken ct = default)
        {
            if (Fail) throw new HttpRequestException("destino caído");
            Lines.AddRange(jsonLines);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task Ships_alerts_and_relevant_events_once_and_skips_high_volume_sources()
    {
        var sink = new FlakySink();
        var shipper = new LogShipper(Store, sink, new LogShipperOptions());
        Store.AddEvent(MakeEvent("sec-1", "eventlog.security"));
        Store.AddEvent(MakeEvent("iis-1", "iis"));                   // volumen alto: no se envía
        Store.AddAlert(MakeAlert("ALR-1"));

        Assert.Equal(2, await shipper.ShipOnceAsync());
        Assert.Contains(sink.Lines, l => l.Contains("\"type\":\"alert\"") && l.Contains("ALR-1"));
        Assert.Contains(sink.Lines, l => l.Contains("\"id\":\"sec-1\""));
        Assert.DoesNotContain(sink.Lines, l => l.Contains("iis-1"));

        Assert.Equal(0, await shipper.ShipOnceAsync());              // nada nuevo: no se duplica
        Assert.Equal(2, sink.Lines.Count);

        Store.AddAlert(MakeAlert("ALR-2"));
        Assert.Equal(1, await shipper.ShipOnceAsync());
        Assert.Contains(sink.Lines, l => l.Contains("ALR-2"));
    }

    [Fact]
    public async Task Failure_keeps_the_cursor_and_retries_without_loss()
    {
        var sink = new FlakySink { Fail = true };
        var shipper = new LogShipper(Store, sink, new LogShipperOptions());
        Store.AddAlert(MakeAlert("ALR-1"));
        Store.AddEvent(MakeEvent("sec-1", "eventlog.security"));

        Assert.Equal(0, await shipper.ShipOnceAsync());
        Assert.Equal(1, shipper.ConsecutiveFailures);
        await shipper.ShipOnceAsync();
        Assert.Equal(2, shipper.ConsecutiveFailures);
        Assert.Empty(sink.Lines);

        sink.Fail = false;
        Assert.Equal(2, await shipper.ShipOnceAsync());              // recupera todo lo pendiente
        Assert.Equal(0, shipper.ConsecutiveFailures);
    }

    [Fact]
    public async Task Cursor_survives_restart()
    {
        var sink = new FlakySink();
        Store.AddAlert(MakeAlert("ALR-1"));
        await new LogShipper(Store, sink, new LogShipperOptions()).ShipOnceAsync();
        sink.Lines.Clear();
        Assert.Equal(0, await new LogShipper(Store, sink, new LogShipperOptions()).ShipOnceAsync());   // otra instancia = reinicio
        Assert.Empty(sink.Lines);
    }

    [Fact]
    public async Task Periodic_status_record_carries_manifest_hash()
    {
        var sink = new FlakySink();
        var time = new Microsoft.Extensions.Time.Testing.FakeTimeProvider(DateTimeOffset.Parse("2026-10-08T12:00:00Z"));
        var shipper = new LogShipper(Store, sink, new LogShipperOptions { StatusInterval = TimeSpan.FromHours(1) }, time,
            statusInfo: () => new Dictionary<string, string?> { ["manifest_sha256"] = "abc123" });
        await shipper.ShipOnceAsync();
        Assert.Single(sink.Lines, l => l.Contains("agent_status") && l.Contains("abc123"));
        await shipper.ShipOnceAsync();                               // aún no toca
        Assert.Single(sink.Lines);
        time.Advance(TimeSpan.FromHours(2));
        await shipper.ShipOnceAsync();
        Assert.Equal(2, sink.Lines.Count);
    }

    [Fact]
    public async Task File_sink_appends_jsonl_with_date_placeholder()
    {
        var time = new Microsoft.Extensions.Time.Testing.FakeTimeProvider(DateTimeOffset.Parse("2026-10-08T12:00:00Z"));
        var sink = new FileLogSink(new FileLogSinkOptions { Path = Path.Combine(Dir, "share", "{date}.jsonl") }, time);
        await sink.SendAsync(new[] { "{\"a\":1}", "{\"a\":2}" });
        await sink.SendAsync(new[] { "{\"a\":3}" });
        var lines = File.ReadAllLines(Path.Combine(Dir, "share", "20261008.jsonl"));
        Assert.Equal(new[] { "{\"a\":1}", "{\"a\":2}", "{\"a\":3}" }, lines);
        Assert.All(lines, l => JsonDocument.Parse(l));
    }

    [Fact]
    public async Task Http_sink_posts_ndjson_with_bearer_token()
    {
        using var hook = new FakeWebhook();
        var sink = new HttpLogSink(new HttpClient(), new HttpLogSinkOptions { Url = hook.Url, Token = "t0k" });
        await sink.SendAsync(new[] { "{\"a\":1}", "{\"a\":2}" });
        var body = Assert.Single(hook.Bodies);
        Assert.Equal(2, body.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length);

        hook.StatusToReturn = 500;
        await Assert.ThrowsAsync<HttpRequestException>(() => sink.SendAsync(new[] { "{}" }));
    }
}

public sealed class CliTests : StoreTestBase
{
    private IConfiguration Config(Dictionary<string, string?>? extra = null)
    {
        var d = new Dictionary<string, string?> { ["SecurityAgent:Store:DatabasePath"] = Path.Combine(Dir, "agent.db"), ["SecurityAgent:Integrity:HmacKey"] = "k" };
        if (extra != null) foreach (var kv in extra) d[kv.Key] = kv.Value;
        return new ConfigurationBuilder().AddInMemoryCollection(d).Build();
    }

    [Fact]
    public void Make_and_verify_manifest_roundtrip_with_exit_codes()
    {
        var app = Path.Combine(Dir, "app");
        Directory.CreateDirectory(app);
        File.WriteAllText(Path.Combine(app, "a.dll"), "x");
        var o = new StringWriter();
        Assert.Equal(0, Cli.TryRun(new[] { "--make-manifest" }, app, Config(), o));
        Assert.Contains("firmado: sí", o.ToString());
        Assert.Equal(0, Cli.TryRun(new[] { "--verify-manifest" }, app, Config(), new StringWriter()));

        File.WriteAllText(Path.Combine(app, "a.dll"), "alterado");
        var o2 = new StringWriter();
        Assert.Equal(2, Cli.TryRun(new[] { "--verify-manifest" }, app, Config(), o2));
        Assert.Contains("a.dll", o2.ToString());
    }

    [Fact]
    public void Unblock_ip_removes_block_and_calls_firewall_and_list_blocks_shows_it()
    {
        Store.Dispose();
        var fw = new FakeFirewall();
        using (var s = new SqliteStateStore(new StateStoreOptions { DatabasePath = Path.Combine(Dir, "agent.db") }))
            s.AddBlock(new("203.0.113.50", "SEC-001", "fuerza bruta", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1)));

        var list = new StringWriter();
        Assert.Equal(0, Cli.TryRun(new[] { "--list-blocks" }, Dir, Config(), list));
        Assert.Contains("203.0.113.50", list.ToString());

        var o = new StringWriter();
        Assert.Equal(0, Cli.TryRun(new[] { "--unblock-ip", "203.0.113.50" }, Dir, Config(), o, fw));
        Assert.Contains("203.0.113.50", fw.Unblocked);
        var after = new StringWriter();
        Cli.TryRun(new[] { "--list-blocks" }, Dir, Config(), after);
        Assert.Contains("Sin bloqueos", after.ToString());
    }

    [Fact]
    public void Unblock_ip_rejects_invalid_input_and_normal_startup_is_not_a_cli_command()
    {
        Assert.Equal(1, Cli.TryRun(new[] { "--unblock-ip", "1.2.3.4; calc" }, Dir, Config(), new StringWriter(), new FakeFirewall()));
        Assert.Equal(1, Cli.TryRun(new[] { "--unblock-ip" }, Dir, Config(), new StringWriter(), new FakeFirewall()));
        Assert.Null(Cli.TryRun(Array.Empty<string>(), Dir, Config(), new StringWriter()));
    }
}

public class ResourceGovernorTests
{
    [Fact]
    public void Disabled_does_nothing_and_enabled_never_throws()
    {
        ResourceGovernor.Apply(new ResourceLimitsOptions { Enabled = false }, NullLogger.Instance);
        ResourceGovernor.Apply(new ResourceLimitsOptions { Enabled = true, LowPriority = false, MaxMemoryMb = 0, MaxCpuPercent = 0 }, NullLogger.Instance);
    }
}

public class FirewallArgsTests
{
    [Fact]
    public void Show_args_use_the_same_rule_name()
    {
        Assert.Contains("name=CScph26-block-203.0.113.50", WindowsFirewall.BuildShowArgs("203.0.113.50"));
        Assert.Throws<ArgumentException>(() => WindowsFirewall.BuildShowArgs("x; y"));
    }
}
