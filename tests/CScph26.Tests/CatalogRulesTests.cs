using System.Diagnostics;
using SecurityAgent.Collectors.EventLog;
using SecurityAgent.Collectors.Files;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.Rules;

namespace CScph26.Tests;

/// <summary>Fase 9: cada regla del catálogo tiene pruebas, runbook y entrada en el catálogo.</summary>
public class CatalogRulesTests
{
    private static readonly string[] ExpectedIds =
        { "SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005", "SEC-006", "SEC-007", "SEC-007-404", "SEC-008", "SEC-010", "SEC-010-TEMP" };

    private static IReadOnlyList<Rule> Rules() => RuleLoader.LoadDirectory(TestSupport.RulesDir);
    private static Allowlist Allow() => Allowlist.LoadFile(Path.Combine(TestSupport.RulesDir, "allowlist.yaml"));

    private static List<RuleHit> Run(IEnumerable<SecurityEvent> events, DeployWindows? windows = null)
    {
        var engine = new RuleEngine(Rules(), Allow(), windows);
        return events.SelectMany(engine.Process).ToList();
    }

    private static List<SecurityEvent> Raw(string channel) =>
        new XmlFixtureEventSource(XmlFixtureEventSource.RawDir).Read(channel, 0, 10_000)
            .Select(r => EventLogXmlParser.Parse(r.Xml, channel)!).ToList();

    // ---------- Gobierno del catálogo ----------

    [Fact]
    public void Every_catalog_rule_exists_starts_in_observe_and_has_a_runbook_and_catalog_entry()
    {
        var rules = Rules();
        Assert.Equal(ExpectedIds.OrderBy(x => x), rules.Select(r => r.Id).OrderBy(x => x));
        var catalog = File.ReadAllText(Path.Combine(TestSupport.RepoRoot(), "CLAUDE.md"));
        foreach (var r in rules)
        {
            Assert.Equal(SecurityAgent.Core.State.RuleMode.Observe, r.FileMode);
            Assert.False(string.IsNullOrEmpty(r.Runbook), $"{r.Id} sin runbook");
            Assert.True(File.Exists(Path.Combine(TestSupport.RepoRoot(), r.Runbook!)), $"{r.Id}: falta {r.Runbook}");
            var baseId = string.Join('-', r.Id.Split('-').Take(2));
            Assert.Contains($"| {baseId} |", catalog);
        }
    }

    [Fact]
    public void Every_runbook_has_the_required_sections()
    {
        foreach (var r in Rules().Select(x => x.Runbook!).Distinct())
        {
            var text = File.ReadAllText(Path.Combine(TestSupport.RepoRoot(), r));
            foreach (var section in new[] { "## Qué significa", "## Cómo verificar", "## Contención", "## Erradicación", "## Recuperación", "## A quién avisar" })
                Assert.True(text.Contains(section), $"{r}: falta la sección '{section}'");
        }
    }

    [Fact]
    public void Transversal_plans_exist()
    {
        foreach (var f in new[] { "respuesta-a-incidentes", "compromiso-de-cuenta", "ransomware", "desbloqueo-y-rollback", "hardening-y-calendario" })
            Assert.True(File.Exists(Path.Combine(TestSupport.RepoRoot(), "docs", "planes", f + ".md")), $"falta docs/planes/{f}.md");
    }

    // ---------- SEC-002 ----------

    [Fact]
    public void Sec002_fires_on_sql_login_brute_force_from_external_ip_only()
    {
        var parser = new SqlErrorLogParser(TimeZoneInfo.Utc);
        var events = File.ReadAllLines(TestSupport.FixturePath("sql-errorlog.txt"))
            .Select(l => parser.Parse(l, "sql")).Where(e => e != null).Select(e => e!).ToList();
        var hit = Assert.Single(Run(events), h => h.Rule.Id == "SEC-002");
        Assert.Equal("203.0.113.90", hit.Ip);
    }

    // ---------- SEC-004 ----------

    [Fact]
    public void Sec004_fires_on_new_service_and_new_scheduled_task()
    {
        var hits = Run(Raw("System").Concat(Raw("Security"))).Where(h => h.Rule.Id == "SEC-004").ToList();
        Assert.Equal(2, hits.Count);
        Assert.Equal(2, hits.SelectMany(h => h.EventIds).Count());
    }

    // ---------- SEC-006 y ventanas de deploy ----------

    private static SecurityEvent Fs(string type, string path, string time) =>
        new($"fs-{type}-{time}", DateTimeOffset.Parse(time), "fs", type, Severity.Info, null, null, path);

    [Fact]
    public void Sec006_fires_outside_deploy_windows_and_stays_quiet_inside()
    {
        var windows = DeployWindows.ParseYaml("""
            zona_horaria: UTC
            recurrentes:
              - dias: [jue]
                desde: "22:00"
                hasta: "23:30"
            puntuales:
              - desde: "2026-10-10T22:00:00Z"
                hasta: "2026-10-10T23:00:00Z"
                motivo: "deploy extraordinario"
            """);
        // 2026-10-08 es jueves
        var outside = Run(new[] { Fs("file.changed", @"D:\Apps\shop\web.config", "2026-10-08T15:00:00Z") }, windows);
        var insideRecurring = Run(new[] { Fs("file.changed", @"D:\Apps\shop\web.config", "2026-10-08T22:30:00Z") }, windows);
        var insideOneOff = Run(new[] { Fs("file.changed", @"D:\Apps\shop\web.config", "2026-10-10T22:30:00Z") }, windows);
        var afterOneOff = Run(new[] { Fs("file.changed", @"D:\Apps\shop\web.config", "2026-10-10T23:30:00Z") }, windows);

        Assert.Single(outside, h => h.Rule.Id == "SEC-006");
        Assert.DoesNotContain(insideRecurring, h => h.Rule.Id == "SEC-006");
        Assert.DoesNotContain(insideOneOff, h => h.Rule.Id == "SEC-006");
        Assert.Contains(afterOneOff, h => h.Rule.Id == "SEC-006");
    }

    [Fact]
    public void Sec006_without_configured_windows_always_alerts_and_overflow_is_reported()
    {
        var hits = Run(new[]
        {
            Fs("file.created", @"D:\Apps\shop\bin\evil.dll", "2026-10-08T03:00:00Z"),
            Fs("fs.overflow", @"D:\Apps", "2026-10-08T03:00:05Z"),
        });
        Assert.Equal(2, hits.Count(h => h.Rule.Id == "SEC-006"));
    }

    [Fact]
    public void Deploy_window_crossing_midnight_belongs_to_the_day_it_starts()
    {
        var w = DeployWindows.ParseYaml("zona_horaria: UTC\nrecurrentes:\n  - dias: [vie]\n    desde: \"22:00\"\n    hasta: \"02:00\"\n");
        Assert.True(w.IsInWindow(DateTimeOffset.Parse("2026-10-09T23:00:00Z")));    // viernes 23:00
        Assert.True(w.IsInWindow(DateTimeOffset.Parse("2026-10-10T01:00:00Z")));    // sábado 01:00 (sigue la ventana del viernes)
        Assert.False(w.IsInWindow(DateTimeOffset.Parse("2026-10-10T23:00:00Z")));   // sábado 23:00: no
        Assert.False(w.IsInWindow(DateTimeOffset.Parse("2026-10-09T12:00:00Z")));
    }

    [Theory]
    [InlineData("recurrentes:\n  - dias: [xyz]\n    desde: \"22:00\"\n    hasta: \"23:00\"\n")]
    [InlineData("recurrentes:\n  - dias: [lun]\n    desde: \"25:00\"\n    hasta: \"23:00\"\n")]
    [InlineData("puntuales:\n  - desde: \"2026-10-10T23:00:00Z\"\n    hasta: \"2026-10-10T22:00:00Z\"\n")]
    [InlineData("zona_horaria: Mordor/Standard\n")]
    public void Invalid_deploy_windows_fail_loudly(string yaml) =>
        Assert.Throws<RuleValidationException>(() => DeployWindows.ParseYaml(yaml));

    [Fact]
    public void Repository_deploy_windows_file_loads_empty() =>
        Assert.False(DeployWindows.LoadFile(Path.Combine(TestSupport.RulesDir, "deploy-windows.yaml")).IsInWindow(DateTimeOffset.UtcNow));

    // ---------- SEC-007 ----------

    private static List<SecurityEvent> IisEvents(string file)
    {
        var parser = new IisLogParser();
        return File.ReadAllLines(file).Select((l, i) => parser.Parse(l, "iis-test", i)).Where(e => e != null).Select(e => e!).ToList();
    }

    [Fact]
    public void Sec007_fires_on_attack_signatures_in_the_iis_fixture()
    {
        var hits = Run(IisEvents(TestSupport.FixturePath("iis-attack.log"))).Where(h => h.Rule.Id == "SEC-007").ToList();
        var hit = Assert.Single(hits);
        Assert.Equal("203.0.113.77", hit.Ip);
        Assert.Equal(3, hit.EventIds.Count);
    }

    private static IEnumerable<SecurityEvent> Requests(string ip, int count, int status, string path = "/page") =>
        Enumerable.Range(0, count).Select(i => new SecurityEvent($"{ip}-{status}-{i}", DateTimeOffset.Parse("2026-10-08T07:00:00Z").AddSeconds(i),
            "iis", "http.request", Severity.Info, null, ip, $"{path}{i}", $"GET {status} Mozilla/5.0"));

    [Fact]
    public void Sec007_404_fires_only_for_a_burst_of_404s_from_an_external_ip()
    {
        Assert.Single(Run(Requests("203.0.113.99", 40, 404)), h => h.Rule.Id == "SEC-007-404");
        Assert.Empty(Run(Requests("203.0.113.99", 40, 200)));                    // mismo volumen, pero respuestas correctas
        Assert.Empty(Run(Requests("192.168.1.30", 40, 404)));                    // red interna: lista blanca
        Assert.Empty(Run(Requests("203.0.113.99", 10, 404)));                    // bajo el umbral
    }

    [Fact]
    public void Signatures_are_plain_substrings_and_ordinary_traffic_does_not_match()
    {
        Assert.Empty(Run(Requests("203.0.113.55", 20, 200, "/products/item-")));
        // Limitación conocida y deliberada: una firma simple también coincide con rutas que contengan la palabra ("nmap").
        // Los falsos positivos se miden en observación y se afinan con 'excepto' antes de pasar a enforce (Fase 10).
        Assert.NotEmpty(Run(Requests("203.0.113.55", 20, 200, "/products/nmapping-guide-")));
    }

    [Fact]
    public void Client_ip_comes_from_CF_Connecting_IP_only_when_the_peer_is_local()
    {
        var p = new IisLogParser();
        p.Parse("#Fields: date time c-ip cs-uri-stem CF-Connecting-IP", "x", 0);
        Assert.Equal("203.0.113.5", p.Parse("2026-10-08 07:00:00 127.0.0.1 /a 203.0.113.5", "x", 1)!.Ip);       // vía túnel local
        Assert.Equal("203.0.113.5", p.Parse("2026-10-08 07:00:00 10.0.0.7 /a 203.0.113.5", "x", 2)!.Ip);       // red privada también cuenta como par local
        Assert.Equal("198.51.100.9", p.Parse("2026-10-08 07:00:00 198.51.100.9 /a 203.0.113.5", "x", 3)!.Ip);  // par externo: la cabecera podría ser falsa
        Assert.Equal("127.0.0.1", p.Parse("2026-10-08 07:00:00 127.0.0.1 /a not-an-ip", "x", 4)!.Ip);
    }

    // ---------- SEC-008 ----------

    [Fact]
    public void Sec008_fires_on_malware_detection_and_on_realtime_protection_disabled()
    {
        var evs = Raw("Microsoft-Windows-Windows Defender/Operational");
        Assert.All(evs, e => Assert.Equal("defender", e.Source));
        var detection = evs.Single(e => e.Type == "1116");
        Assert.Equal("Trojan:Win32/Test", detection.Target);
        Assert.Contains("evil.exe", detection.Detail);

        var hits = Run(evs).Where(h => h.Rule.Id == "SEC-008").ToList();
        Assert.Equal(2, hits.Count);                                             // 1116 y 5001; el 2000 (firmas actualizadas) no
    }

    // ---------- SEC-010 ----------

    [Fact]
    public void Sec010_distinguishes_encoded_powershell_temp_execution_and_benign_processes()
    {
        var evs = Raw("Microsoft-Windows-Sysmon/Operational");
        Assert.Equal("powershell.exe", Path.GetFileName(evs[0].Target!.Replace('\\', '/')));
        Assert.Contains("-enc", evs[0].Detail);

        var hits = Run(evs);
        Assert.Equal(new[] { "sysmon-9001" }, hits.Where(h => h.Rule.Id == "SEC-010").SelectMany(h => h.EventIds));
        Assert.Equal(new[] { "sysmon-9002" }, hits.Where(h => h.Rule.Id == "SEC-010-TEMP").SelectMany(h => h.EventIds));
        Assert.DoesNotContain(hits.SelectMany(h => h.EventIds), id => id is "sysmon-9003" or "sysmon-9004");
    }

    // ---------- Filtros del motor ----------

    [Fact]
    public void Regex_filters_run_in_linear_time_on_hostile_input()
    {
        var rule = Rules().Single(r => r.Id == "SEC-010");
        var hostile = "powershell.exe " + new string('-', 200_000) + " -e " + new string('A', 100_000) + "!";
        var ev = new SecurityEvent("h", DateTimeOffset.UtcNow, "sysmon", "1", Severity.Info, null, null, "C:\\powershell.exe", hostile);
        var sw = Stopwatch.StartNew();
        foreach (var f in rule.AllFilters) f.Matches(ev);
        Assert.True(sw.ElapsedMilliseconds < 2000, $"tardó {sw.ElapsedMilliseconds} ms");
    }

    private const string Base = "id: T\nfuente: fs\ncondicion:\n  event_id: x\n  umbral: 1\n  ventana: 1m\n";

    [Theory]
    [InlineData("  filtros:\n    - campo: inexistente\n      contiene: [a]\n", "campo inválido")]
    [InlineData("  filtros:\n    - campo: texto\n", "necesita")]
    [InlineData("  filtros:\n    - campo: texto\n      igual: a\n      contiene: [b]\n", "no se combina")]
    [InlineData("  filtros:\n    - campo: texto\n      regex: '(a)\\1'\n", "regex inválida")]     // retroreferencia: no admitida por el motor sin retroceso
    public void Invalid_filters_are_rejected_for_the_right_reason(string extra, string expectedMessage)
    {
        var e = Assert.Throws<RuleValidationException>(() => RuleLoader.ParseYaml(Base + extra));
        Assert.Contains(expectedMessage, e.Message);
    }

    [Fact]
    public void Except_filters_skip_matching_events_and_all_filters_must_match()
    {
        var rule = RuleLoader.ParseYaml(Base + "  filtros:\n    - campo: objeto\n      contiene: [alfa]\n    - campo: detalle\n      igual: ok\n  excepto:\n    - campo: usuario\n      igual: root\n");
        var engine = new RuleEngine(new[] { rule }, Allowlist.Empty);
        SecurityEvent E(string id, string? target, string? detail, string? actor) =>
            new(id, DateTimeOffset.UtcNow, "fs", "x", Severity.Info, actor, null, target, detail);
        Assert.Single(engine.Process(E("1", "xx-ALFA-xx", "ok", null)));         // contiene sin distinguir mayúsculas
        Assert.Empty(engine.Process(E("2", "xx-alfa-xx", "no", null)));          // falla el segundo filtro
        Assert.Empty(engine.Process(E("3", "beta", "ok", null)));                // falla el primero
        Assert.Empty(engine.Process(E("4", "alfa", "ok", "root")));              // excepción
    }

    [Fact]
    public void Multiple_sources_are_supported_and_unknown_yaml_keys_still_fail()
    {
        var rule = RuleLoader.ParseYaml("id: M\nfuente: [a, b]\ncondicion:\n  event_id: x\n  umbral: 1\n  ventana: 1m\n");
        Assert.Equal(new[] { "a", "b" }, rule.AllSources.OrderBy(x => x));
        Assert.Throws<RuleValidationException>(() => RuleLoader.ParseYaml("id: M\nfuente: a\nmal: 1\ncondicion:\n  event_id: x\n  umbral: 1\n  ventana: 1m\n"));
    }
}
