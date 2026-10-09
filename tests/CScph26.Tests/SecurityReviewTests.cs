using System.Net;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SecurityAgent.Collectors.Files;
using SecurityAgent.Core.Alerts;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.Integrity;
using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;
using SecurityAgent.Core.Text;
using SecurityAgent.Responders;
using SecurityAgent.Responders.Notifications;
using SecurityAgent.StatusApi;
using SecurityAgent.Worker;

namespace CScph26.Tests;

// Pruebas de los hallazgos de la revisión de seguridad independiente (cada una reproduce el defecto reportado).

public class SqlClientIpSpoofingTests
{
    private readonly SqlErrorLogParser _p = new(TimeZoneInfo.Utc);

    private static string Line(string user, string client) =>
        $"2026-10-08 03:10:15.12 Logon       Login failed for user '{user}'. Reason: Could not find a login matching the name provided. [CLIENT: {client}]";

    [Theory]
    [InlineData("sa", "203.0.113.9", "203.0.113.9")]
    [InlineData("x [CLIENT: 8.8.8.8]", "203.0.113.9", "203.0.113.9")]                 // el usuario que escribe el atacante no decide la IP
    [InlineData("[CLIENT: 8.8.8.8", "203.0.113.9", "203.0.113.9")]
    [InlineData("a] [CLIENT: 8.8.8.8] [b", "203.0.113.9", "203.0.113.9")]
    [InlineData("x [CLIENT: 8.8.8.8]", "<local machine>", null)]                       // sin IP real no se hereda la falsa
    public void Client_ip_is_taken_from_the_final_field_never_from_the_username(string user, string client, string? expected)
    {
        var ev = _p.Parse(Line(user, client), "sql");
        Assert.NotNull(ev);
        Assert.Equal(expected, ev!.Ip);
    }
}

public class IisTrustedPeerTests
{
    [Theory]
    [InlineData("127.0.0.1", "203.0.113.5", "203.0.113.5")]       // cloudflared local
    [InlineData("::1", "203.0.113.5", "203.0.113.5")]
    [InlineData("10.1.1.1", "8.8.8.8", "10.1.1.1")]               // un equipo de la LAN no puede acusar a otra IP
    [InlineData("192.168.1.50", "8.8.8.8", "192.168.1.50")]
    [InlineData("172.16.0.9", "8.8.8.8", "172.16.0.9")]
    [InlineData("198.51.100.9", "8.8.8.8", "198.51.100.9")]
    public void Default_trust_is_loopback_only(string peer, string cf, string expected) =>
        Assert.Equal(expected, IisLogParser.ClientIp(peer, cf, a => IPAddress.IsLoopback(a)));

    [Fact]
    public void Own_server_address_is_trusted_when_cloudflared_targets_the_lan_ip()
    {
        var host = new HostAddresses(() => (new[] { IPAddress.Parse("192.168.1.10") }, Array.Empty<IPAddress>()));
        Assert.True(host.IsOwn(IPAddress.Parse("192.168.1.10")));
        Assert.False(host.IsOwn(IPAddress.Parse("192.168.1.11")));
        var p = new IisLogParser(a => IPAddress.IsLoopback(a) || host.IsOwn(a));
        p.Parse("#Fields: date time c-ip cs-uri-stem CF-Connecting-IP", "x", 0);
        Assert.Equal("203.0.113.5", p.Parse("2026-10-08 07:00:00 192.168.1.10 /a 203.0.113.5", "x", 1)!.Ip);
        Assert.Equal("192.168.1.11", p.Parse("2026-10-08 07:00:00 192.168.1.11 /a 203.0.113.5", "x", 2)!.Ip);
    }
}

public class BlockablePolicyTests
{
    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("255.255.255.255")]
    [InlineData("224.0.0.1")]
    [InlineData("239.255.255.250")]
    [InlineData("169.254.10.10")]
    [InlineData("::")]
    [InlineData("ff02::1")]
    [InlineData("fe80::1")]
    [InlineData("127.0.0.1")]
    [InlineData("::ffff:0.0.0.0")]
    public void Special_addresses_are_never_blockable(string ip) => Assert.True(Allowlist.Empty.IsAllowed(ip));

    [Theory]
    [InlineData("203.0.113.9")]
    [InlineData("8.8.8.8")]
    [InlineData("10.20.30.40")]
    [InlineData("2001:db8::1")]
    public void Ordinary_addresses_remain_blockable_when_not_allowlisted(string ip) => Assert.False(Allowlist.Empty.IsAllowed(ip));

    [Fact]
    public void Own_gateway_dns_and_dhcp_addresses_are_protected()
    {
        var host = new HostAddresses(() => (new[] { IPAddress.Parse("10.0.0.5") }, new[] { IPAddress.Parse("10.0.0.1"), IPAddress.Parse("10.0.0.2"), IPAddress.Parse("fe80::1%3") }));
        var allow = new Allowlist(Array.Empty<string>(), host.IsProtected);
        foreach (var ip in new[] { "10.0.0.5", "10.0.0.1", "10.0.0.2", "::ffff:10.0.0.1" }) Assert.True(allow.IsAllowed(ip), ip);
        Assert.False(allow.IsAllowed("10.0.0.3"));
    }

    [Fact]
    public void Host_addresses_refresh_after_the_ttl_and_survive_read_failures()
    {
        var calls = 0;
        var current = new[] { IPAddress.Parse("10.0.0.5") };
        var host = new HostAddresses(() =>
        {
            calls++;
            if (calls == 3) throw new InvalidOperationException("sin red");
            return (current, Array.Empty<IPAddress>());
        }, TimeSpan.FromMilliseconds(1));
        Assert.True(host.IsOwn(IPAddress.Parse("10.0.0.5")));
        current = new[] { IPAddress.Parse("10.0.0.6") };
        Thread.Sleep(20);
        Assert.True(host.IsOwn(IPAddress.Parse("10.0.0.6")));      // refrescado
        Thread.Sleep(20);
        Assert.True(host.IsOwn(IPAddress.Parse("10.0.0.6")));      // la lectura falló: se conserva lo último conocido
    }
}

public sealed class ResponderLimitsTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cscph26-" + Guid.NewGuid().ToString("N"));
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 10, 8, 12, 0, 0, TimeSpan.Zero));
    private readonly SqliteStateStore _store;
    private readonly FakeFirewall _fw = new();

    public ResponderLimitsTests() => _store = new(new StateStoreOptions { DatabasePath = Path.Combine(_dir, "agent.db") }, _time);

    private static Rule BlockRule() => new(
        "SEC-001", "Fuerza bruta RDP", RuleMode.Enforce, "eventlog.security", new HashSet<string> { "4625" }, GroupBy.Ip, 8,
        TimeSpan.FromMinutes(5), Severity.Alta, true, RuleActions.BlockIp, TimeSpan.FromHours(1), new[] { "correo" }, null);

    private RuleHit Hit(string ip) => new(BlockRule(), ip, new[] { "E1" }, _time.GetUtcNow());

    private ResponseExecutor Exec(BlockLimits? limits = null, AgentHealth? health = null)
    {
        _store.SetRuleMode("SEC-001", RuleMode.Enforce);
        return new ResponseExecutor(_store, _fw, Allowlist.Empty, _time, limits, health);
    }

    [Fact]
    public void Repeated_hits_on_a_blocked_ip_do_not_launch_another_firewall_rule()
    {
        var ex = Exec();
        ex.Handle(Hit("203.0.113.50"));
        var again = ex.Handle(Hit("203.0.113.50"));
        Assert.Single(_fw.Blocked);
        Assert.Single(_store.ListActiveBlocks());
        Assert.Contains("ya estaba bloqueada", again.ActionTaken);
    }

    [Fact]
    public void New_blocks_per_minute_are_capped_and_the_window_slides()
    {
        var ex = Exec(new BlockLimits { MaxNewPerMinute = 3 });
        for (var i = 1; i <= 5; i++) ex.Handle(Hit($"203.0.113.{i}"));
        Assert.Equal(3, _fw.Blocked.Count);
        var limited = _store.ListAlerts().Count(a => a.ActionTaken!.Contains("se limita"));
        Assert.Equal(2, limited);
        _time.Advance(TimeSpan.FromSeconds(61));
        ex.Handle(Hit("203.0.113.6"));
        Assert.Equal(4, _fw.Blocked.Count);
    }

    [Fact]
    public void Active_blocks_are_capped()
    {
        var ex = Exec(new BlockLimits { MaxActive = 2, MaxNewPerMinute = 100 });
        for (var i = 1; i <= 4; i++) ex.Handle(Hit($"203.0.113.{i}"));
        Assert.Equal(2, _fw.Blocked.Count);
        Assert.Equal(2, _store.ListActiveBlocks().Count);
    }

    [Fact]
    public void Block_is_recorded_with_the_canonical_ip()
    {
        Exec().Handle(Hit("2001:0DB8:0:0:0:0:0:1"));
        Assert.Equal("2001:db8::1", Assert.Single(_store.ListActiveBlocks()).Ip);
    }

    [Fact]
    public void Expired_block_whose_removal_fails_is_kept_retried_reported_and_never_purged()
    {
        var health = new AgentHealth();
        var ex = Exec(health: health);
        ex.Handle(Hit("203.0.113.50"));
        _time.Advance(TimeSpan.FromHours(2));
        _fw.FailUnblock = true;
        Assert.Equal(0, ex.SweepExpired());
        Assert.Contains(health.Problems(), p => p.Contains("203.0.113.50"));

        _time.Advance(TimeSpan.FromDays(10));                         // antes se purgaba a las 24 h y la regla quedaba huérfana
        _store.Purge();
        Assert.Single(_store.ListExpiredBlocks());

        _fw.FailUnblock = false;
        Assert.Equal(1, ex.SweepExpired());
        Assert.Empty(_store.ListExpiredBlocks());
        Assert.Empty(health.Problems());
    }

    public void Dispose()
    {
        _store.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch { }
    }
}

public sealed class LogTailerByteExactTests : StoreTestBase
{
    private string File1 => Path.Combine(Dir, "u.log");

    [Fact]
    public void Invalid_utf8_bytes_do_not_shift_the_cursor()
    {
        var bytes = new List<byte>();
        bytes.AddRange(Encoding.ASCII.GetBytes("linea1 "));
        bytes.AddRange(Enumerable.Repeat((byte)0xFF, 100));                 // 100 bytes inválidos: cada uno se decodifica como U+FFFD (3 bytes)
        bytes.AddRange(Encoding.ASCII.GetBytes("\nlinea2\n"));
        File.WriteAllBytes(File1, bytes.ToArray());
        var t = new LogTailer(Store, new UTF8Encoding(false));

        var r1 = t.Read(File1, false);
        Assert.Equal(2, r1.Lines.Count);
        Assert.Equal("linea2", r1.Lines[1].Text);
        Assert.Equal(bytes.Count, r1.NewOffset);                             // el cursor es el tamaño real del archivo
        Assert.Equal(bytes.Count - "linea2\n".Length, r1.Lines[1].Offset);
        t.Commit(r1);

        File.AppendAllText(File1, "linea3\n");
        var r2 = t.Read(File1, false);
        Assert.Equal(new[] { "linea3" }, r2.Lines.Select(l => l.Text));      // no se pierde ni se repite nada
    }

    [Fact]
    public void Utf16_offsets_are_exact()
    {
        var enc = new UnicodeEncoding(false, true);
        var content = enc.GetPreamble().Concat(enc.GetBytes("uno\r\ndos\r\n")).ToArray();
        File.WriteAllBytes(File1, content);
        var r = new LogTailer(Store, enc).Read(File1, false);
        Assert.Equal(new[] { "uno", "dos" }, r.Lines.Select(l => l.Text));
        Assert.Equal(content.Length, r.NewOffset);
    }

    [Fact]
    public void A_line_that_fills_the_whole_buffer_without_a_newline_is_skipped_instead_of_blinding_the_collector()
    {
        File.WriteAllBytes(File1, Encoding.ASCII.GetBytes(new string('A', 5000) + "\nluego\n"));
        var t = new LogTailer(Store, new UTF8Encoding(false), maxBytesPerPoll: 1000);
        var r = t.Read(File1, false);
        Assert.Empty(r.Lines);
        t.Commit(r);
        for (var i = 0; i < 10 && t.Read(File1, false) is { } step; i++)
        {
            t.Commit(step);
            if (step.Lines.Any(l => l.Text == "luego")) return;
        }
        Assert.Fail("el lector quedó atascado en la línea demasiado larga");
    }
}

public class StatusApiOptionsTests
{
    private static readonly string Good = new('x', 40);

    [Fact]
    public void Configured_clients_replace_the_defaults_instead_of_being_appended()
    {
        var cfg = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Token"] = Good, ["AllowedClients:0"] = "10.9.9.9",
        }).Build();
        var o = cfg.Get<StatusApiOptions>()!;
        Assert.Equal(new[] { "10.9.9.9" }, o.EffectiveAllowedClients);
        Assert.Equal(StatusApiOptions.DefaultAllowedClients, new StatusApiOptions().EffectiveAllowedClients);
    }

    [Theory]
    [InlineData("", "falta el token")]
    [InlineData("CAMBIAR-por-un-token-largo-y-aleatorio-123456", "valor de ejemplo")]
    [InlineData("corto", "demasiado corto")]
    public void Weak_or_placeholder_tokens_are_rejected(string token, string reason) =>
        Assert.Contains(reason, new StatusApiOptions { Token = token }.Validate());

    [Fact]
    public void A_malformed_client_entry_disables_the_api_instead_of_crashing_the_process()
    {
        var o = new StatusApiOptions { Token = Good, AllowedClients = { "127.0.0.1", "192.168.X.X" } };
        Assert.Contains("AllowedClients", o.Validate());
        Assert.Null(new StatusApiOptions { Token = Good }.Validate());
    }
}

public class SecretScrubberTests
{
    [Theory]
    [InlineData("/login?user=ana&password=hunter2&next=/", "/login?user=ana&password=***&next=/")]
    [InlineData("/api?access_token=abc123DEF&x=1", "/api?access_token=***&x=1")]
    [InlineData("/a?apikey=K3Y&b=2", "/a?apikey=***&b=2")]
    [InlineData("Server=db;User Id=sa;Password=P@ss w0rd;", "Server=db;User Id=sa;Password=***;")]
    [InlineData("powershell -Password S3cr3t! -File x.ps1", "powershell -Password *** -File x.ps1")]
    [InlineData("tool.exe /pwd:Abc123 /v", "tool.exe /pwd:*** /v")]
    [InlineData("curl --token=zzz https://h/", "curl --token=*** https://h/")]
    [InlineData("git clone https://ana:ghp_abc123@github.com/x/y", "git clone https://ana:***@github.com/x/y")]
    [InlineData("Authorization: Bearer eyJhbGciOi.abc.def", "Authorization: Bearer ***")]
    [InlineData("{\"password\": \"hunter2\", \"user\": \"ana\"}", "{\"password\": ***, \"user\": \"ana\"}")]
    public void Secrets_are_masked(string input, string expected) => Assert.Equal(expected, SecretScrubber.Scrub(input));

    [Theory]
    [InlineData("/products/list?page=2&sort=name")]
    [InlineData("GET 200 Mozilla/5.0 (Windows NT 10.0)")]
    [InlineData("C:\\Windows\\System32\\svchost.exe -k netsvcs")]
    [InlineData("../../etc/passwd")]
    [InlineData("")]
    public void Ordinary_text_is_left_alone(string input) => Assert.Equal(input, SecretScrubber.Scrub(input));

    [Fact]
    public void Null_and_pathological_input_are_safe()
    {
        Assert.Null(SecretScrubber.Scrub((string?)null));
        var hostile = string.Concat(Enumerable.Repeat("password=", 20_000));
        Assert.NotNull(SecretScrubber.Scrub(hostile));
    }

    [Fact]
    public async Task Stored_events_are_scrubbed_but_rules_still_see_the_original_attack_payload()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cscph26-" + Guid.NewGuid().ToString("N"));
        using var store = new SqliteStateStore(new StateStoreOptions { DatabasePath = Path.Combine(dir, "agent.db") });
        var allow = Allowlist.Empty;
        var pipeline = new SecurityPipeline(store, new RuleEngine(RuleLoader.LoadDirectory(TestSupport.RulesDir), allow),
            new ResponseExecutor(store, new FakeFirewall(), allow), new NotificationDispatcher(Array.Empty<IAlertNotifier>()));

        var t0 = DateTimeOffset.Parse("2026-10-08T07:00:00Z");
        for (var i = 0; i < 3; i++)
            await pipeline.ProcessAsync(new SecurityEvent($"iis-test-{i}", t0.AddSeconds(i), "iis", "http.request", Severity.Info,
                null, "203.0.113.77", "/a/../../etc/passwd?token=supersecretvalue1", "GET 404 curl"));

        Assert.Contains(store.ListAlerts(), a => a.RuleId == "SEC-007");                 // la regla vio la ruta con "../"
        var stored = store.GetEvent("iis-test-0")!;
        Assert.DoesNotContain("supersecretvalue1", stored.Target);
        Assert.Contains("../", stored.Target);                                           // la evidencia del ataque se conserva
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(dir, true); } catch { }
    }
}

public sealed class BoundedStateTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cscph26-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public void Rule_engine_tracked_keys_stay_bounded_under_a_flood_of_distinct_keys()
    {
        var rule = new Rule("SEC-X", "x", RuleMode.Observe, "sql", new HashSet<string> { "login.failed" }, GroupBy.Actor, 1000,
            TimeSpan.FromHours(1), Severity.Baja, false, RuleActions.Notify, null, Array.Empty<string>(), null);
        var engine = new RuleEngine(new[] { rule }, Allowlist.Empty);
        var t0 = DateTimeOffset.Parse("2026-10-08T07:00:00Z");
        for (var i = 0; i < 60_000; i++)
            engine.Process(new SecurityEvent($"e{i}", t0.AddMilliseconds(i), "sql", "login.failed", Severity.Info, $"user{i}"));
        Assert.InRange(engine.TrackedKeys, 1, 20_000);
    }

    [Fact]
    public void One_noisy_source_cannot_push_out_the_evidence_of_the_others()
    {
        using var store = new SqliteStateStore(new StateStoreOptions
        {
            DatabasePath = Path.Combine(_dir, "agent.db"), MaxEvents = 1000, MaxEventsPerSource = 400,
        });
        var t0 = DateTimeOffset.UtcNow.AddMinutes(-30);
        for (var i = 0; i < 20; i++) store.AddEvent(new($"sec-{i}", t0.AddSeconds(i), "eventlog.security", "4625", Severity.Media, "a", "203.0.113.1"));
        for (var i = 0; i < 2000; i++) store.AddEvent(new($"iis-{i}", t0.AddSeconds(100 + i), "iis", "http.request", Severity.Info));
        store.Purge();
        Assert.Equal(20, store.QueryEvents(source: "eventlog.security", limit: 100).Count);   // la evidencia de Security sobrevive a la ráfaga
        Assert.Equal(400, store.QueryEvents(source: "iis", limit: 1000).Count);
        Assert.Equal("iis-1999", store.QueryEvents(source: "iis", limit: 1)[0].Id);            // se conserva lo más reciente
    }

    [Fact]
    public void Size_cap_trims_the_largest_source_first()
    {
        using var store = new SqliteStateStore(new StateStoreOptions { DatabasePath = Path.Combine(_dir, "size.db"), MaxDatabaseBytes = 600_000 });
        var t0 = DateTimeOffset.UtcNow.AddMinutes(-30);
        for (var i = 0; i < 10; i++) store.AddEvent(new($"sec-{i}", t0.AddSeconds(i), "eventlog.security", "4625", Severity.Media, "a", "203.0.113.1"));
        for (var i = 0; i < 4000; i++) store.AddEvent(new($"iis-{i}", t0.AddSeconds(100 + i), "iis", "http.request", Severity.Info, null, "203.0.113.2", "/p" + new string('x', 150)));
        store.Purge();
        Assert.True(store.UsedBytes <= 600_000, $"UsedBytes={store.UsedBytes}");
        Assert.Equal(10, store.QueryEvents(source: "eventlog.security", limit: 100).Count);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch { }
    }
}

public class SelfProtectionReportingTests : StoreTestBase
{
    [Fact]
    public async Task Unsigned_integrity_manifest_is_reported_as_a_problem_and_a_placeholder_key_too()
    {
        var root = Path.Combine(Dir, "app");
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "a.dll"), "v1");
        File.WriteAllText(Path.Combine(root, IntegrityManifest.FileName), IntegrityManifest.Create(root).ToJson());
        var health = new AgentHealth();
        var publisher = new SystemAlertPublisher(Store, new NotificationDispatcher(Array.Empty<IAlertNotifier>()));

        var monitor = new IntegrityMonitor(new AgentOptions(), publisher, health, NullLogger<IntegrityMonitor>.Instance) { Root = root };
        await monitor.CheckOnceAsync();
        Assert.Contains(health.Problems(), p => p.Contains("no está firmado"));

        var o = new AgentOptions { Integrity = { HmacKey = "CAMBIAR-por-una-clave" } };
        await new IntegrityMonitor(o, publisher, health, NullLogger<IntegrityMonitor>.Instance) { Root = root }.CheckOnceAsync();
        Assert.Contains(health.Problems(), p => p.Contains("valor de ejemplo"));
        Assert.DoesNotContain(health.Problems(), p => p.Contains("no está firmado"));
    }

    [Fact]
    public void Teams_text_escapes_markdown_and_html_from_attacker_controlled_fields()
    {
        var evil = "Haga clic [aquí](https://evil.example/login) <img src=x onerror=1> **urgente** `x` _y_ #h";
        var escaped = TeamsWebhookNotifier.EscapeMarkdown(evil);
        Assert.DoesNotContain("](", escaped.Replace("\\](", ""));
        Assert.DoesNotContain("<img", escaped);
        Assert.Contains("&lt;img", escaped);
        Assert.Contains("\\[aquí\\]\\(https://evil.example/login\\)", escaped);
        Assert.Contains("\\*\\*urgente\\*\\*", escaped);
    }
}

public class EventXmlHardeningTests
{
    [Fact]
    public void Xml_with_a_dtd_or_external_entity_is_rejected_not_expanded()
    {
        var xxe = "<?xml version=\"1.0\"?><!DOCTYPE e [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>" +
                  "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>4625</EventID><Channel>Security</Channel><EventRecordID>1</EventRecordID>" +
                  "<TimeCreated SystemTime=\"2026-10-08T03:10:15.0Z\"/></System><EventData><Data Name=\"IpAddress\">&x;</Data></EventData></Event>";
        Assert.Null(SecurityAgent.Collectors.EventLog.EventLogXmlParser.Parse(xxe));
        Assert.Null(SecurityAgent.Collectors.EventLog.EventLogXmlParser.RecordIdOf(xxe));
    }
}
