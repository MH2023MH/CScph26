using SecurityAgent.Core.Events;
using SecurityAgent.Core.Rules;

namespace CScph26.Tests;

public class RuleLoadingTests
{
    private const string Valid = """
        id: T-1
        fuente: eventlog.security
        condicion: { event_id: 4625, agrupar_por: ip_origen, umbral: 3, ventana: 5m }
        severidad: alta
        excluir: [lista_blanca]
        respuesta: { accion: firewall.block_ip, duracion: 1h }
        """;

    [Fact]
    public void Repository_rules_load_and_start_in_observe()
    {
        var rules = RuleLoader.LoadDirectory(TestSupport.RulesDir);
        Assert.Contains(rules, r => r.Id == "SEC-001");
        Assert.Contains(rules, r => r.Id == "SEC-003");
        Assert.Contains(rules, r => r.Id == "SEC-005");
        Assert.All(rules, r => Assert.Equal(SecurityAgent.Core.State.RuleMode.Observe, r.FileMode));
    }

    [Fact]
    public void Valid_rule_parses_fields()
    {
        var r = RuleLoader.ParseYaml(Valid);
        Assert.Equal(3, r.Threshold);
        Assert.Equal(TimeSpan.FromMinutes(5), r.Window);
        Assert.Equal(TimeSpan.FromHours(1), r.BlockDuration);
        Assert.Equal(GroupBy.Ip, r.GroupBy);
        Assert.Equal(Severity.Alta, r.Severity);
    }

    [Theory]
    [InlineData("modo: encendido")]                               // modo inválido
    [InlineData("typo_desconocido: 1")]                           // clave desconocida
    public void Invalid_rules_are_rejected(string extra) =>
        Assert.Throws<RuleValidationException>(() => RuleLoader.ParseYaml(Valid + "\n" + extra));

    [Fact]
    public void Block_rule_without_allowlist_exclusion_is_rejected() =>
        Assert.Throws<RuleValidationException>(() => RuleLoader.ParseYaml(Valid.Replace("excluir: [lista_blanca]\n", "")));

    [Fact]
    public void Block_rule_requires_duration_and_ip_grouping()
    {
        Assert.Throws<RuleValidationException>(() => RuleLoader.ParseYaml(Valid.Replace(", duracion: 1h", "")));
        Assert.Throws<RuleValidationException>(() => RuleLoader.ParseYaml(Valid.Replace("agrupar_por: ip_origen", "agrupar_por: usuario")));
    }

    [Theory]
    [InlineData("umbral: 3", "umbral: 0")]
    [InlineData("ventana: 5m", "ventana: 5x")]
    public void Bad_numbers_are_rejected(string from, string to) =>
        Assert.Throws<RuleValidationException>(() => RuleLoader.ParseYaml(Valid.Replace(from, to)));
}

public class AllowlistTests
{
    [Fact]
    public void Matches_cidr_and_single_ips()
    {
        var a = new Allowlist(new[] { "192.168.0.0/16", "10.1.2.3", "2001:db8::/32" });
        Assert.True(a.IsAllowed("192.168.44.5"));
        Assert.True(a.IsAllowed("10.1.2.3"));
        Assert.False(a.IsAllowed("10.1.2.4"));
        Assert.False(a.IsAllowed("203.0.113.50"));
        Assert.True(a.IsAllowed("2001:db8::1"));
        Assert.False(a.IsAllowed("192.169.0.1"));
    }

    [Fact]
    public void Unparseable_or_missing_ip_is_treated_as_protected()
    {
        var a = Allowlist.Empty;
        Assert.True(a.IsAllowed("no-es-ip"));
        Assert.True(a.IsAllowed(null));
    }

    [Fact]
    public void Invalid_entries_fail_loudly()
    {
        Assert.Throws<RuleValidationException>(() => new Allowlist(new[] { "192.168.XXX.XXX" }));
        Assert.Throws<RuleValidationException>(() => new Allowlist(new[] { "10.0.0.0/40" }));
    }

    [Fact]
    public void Repository_allowlist_loads()
    {
        var a = Allowlist.LoadFile(Path.Combine(TestSupport.RulesDir, "allowlist.yaml"));
        Assert.True(a.IsAllowed("192.168.1.25"));
        Assert.False(a.IsAllowed("203.0.113.50"));
    }
}

public class RuleEngineTests
{
    private static RuleEngine Engine() => new(RuleLoader.LoadDirectory(TestSupport.RulesDir),
        Allowlist.LoadFile(Path.Combine(TestSupport.RulesDir, "allowlist.yaml")));

    [Fact]
    public void Sec001_fires_once_on_rdp_burst_and_ignores_internal_ip()
    {
        var engine = Engine();
        var hits = TestSupport.LoadJsonFixture("eventlog-security.json", "eventlog.security")
            .SelectMany(engine.Process).Where(h => h.Rule.Id == "SEC-001").ToList();
        var hit = Assert.Single(hits);
        Assert.Equal("203.0.113.50", hit.Ip);
        Assert.Equal(8, hit.EventIds.Count);
    }

    [Fact]
    public void Allowlisted_ip_never_produces_a_hit_even_with_a_huge_burst()
    {
        var engine = Engine();
        var t = DateTimeOffset.Parse("2026-10-08T10:00:00Z");
        var hits = Enumerable.Range(0, 100)
            .SelectMany(i => engine.Process(new($"X{i}", t.AddSeconds(i), "eventlog.security", "4625", Severity.Info, "u", "192.168.1.25")))
            .ToList();
        Assert.Empty(hits);
    }

    [Fact]
    public void Sec003_fires_for_account_creation_and_group_add()
    {
        var engine = Engine();
        var hits = TestSupport.LoadJsonFixture("eventlog-security.json", "eventlog.security")
            .SelectMany(engine.Process).Where(h => h.Rule.Id == "SEC-003").ToList();
        Assert.Equal(2, hits.Count);
    }

    [Fact]
    public void Sec005_fires_on_repeated_app_pool_failures()
    {
        var engine = Engine();
        var hits = TestSupport.LoadJsonFixture("eventlog-system.json", "eventlog.system")
            .SelectMany(engine.Process).Where(h => h.Rule.Id == "SEC-005").ToList();
        var hit = Assert.Single(hits);
        Assert.Equal("AppPoolDemo", hit.GroupKey);
    }

    [Fact]
    public void Events_spread_beyond_the_window_do_not_fire()
    {
        var engine = Engine();
        var t = DateTimeOffset.Parse("2026-10-08T10:00:00Z");
        var hits = Enumerable.Range(0, 20)
            .SelectMany(i => engine.Process(new($"S{i}", t.AddMinutes(i), "eventlog.security", "4625", Severity.Info, "u", "203.0.113.60")))
            .ToList();
        Assert.Empty(hits);   // 1 evento por minuto: nunca 8 dentro de 5 min
    }

    [Fact]
    public void Different_sources_or_types_do_not_match()
    {
        var engine = Engine();
        var t = DateTimeOffset.Parse("2026-10-08T10:00:00Z");
        var hits = Enumerable.Range(0, 20)
            .SelectMany(i => engine.Process(new($"Y{i}", t.AddSeconds(i), "iis", "4625", Severity.Info, "u", "203.0.113.61")))
            .ToList();
        Assert.Empty(hits);
    }
}
