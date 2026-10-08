using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SecurityAgent.Collectors.Audits;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;
using SecurityAgent.Responders.Notifications;
using SecurityAgent.Worker;
using Microsoft.Extensions.Configuration;

namespace CScph26.Tests;

public sealed class AuditTests : StoreTestBase
{
    private readonly FakeTimeProvider _time = new(DateTimeOffset.Parse("2026-10-08T12:00:00Z"));

    private sealed class FakeCerts(params CertInfo[] certs) : ICertificateSource
    {
        public IReadOnlyList<CertInfo> List() => certs;
    }

    private CertInfo Cert(string subject, double daysLeft, bool key = true) =>
        new(subject, "T" + subject.GetHashCode(), _time.GetUtcNow().AddDays(daysLeft), key, "My");

    // ---------- Certificados ----------

    [Fact]
    public async Task Certificates_classify_ok_warn_and_fail_and_ignore_irrelevant_ones()
    {
        var audit = new CertificateAudit(new FakeCerts(
            Cert("CN=ok.local", 200),
            Cert("CN=pronto.local", 20),                   // < 30 d: aviso
            Cert("CN=critico.local", 3),                   // < 7 d: fallo
            Cert("CN=vencido.local", -2),                  // vencido: fallo
            Cert("CN=abandonado.local", -200),             // vencido hace mucho: se ignora
            Cert("CN=sin-clave.local", 1, key: false)),    // sin clave privada: no es de servidor
            new CertificateAuditOptions(), _time);
        var r = await audit.RunAsync();
        Assert.Equal(AuditStatus.Fail, r.Status);
        Assert.Equal(3, r.Findings.Count);
        Assert.Contains(r.Findings, f => f.Contains("pronto.local"));
        Assert.Contains(r.Findings, f => f.StartsWith("VENCIDO") && f.Contains("vencido.local"));
        Assert.DoesNotContain(r.Findings, f => f.Contains("abandonado") || f.Contains("sin-clave"));
    }

    [Fact]
    public async Task Certificates_only_warn_when_nothing_is_critical_and_ok_when_all_are_healthy()
    {
        var warn = await new CertificateAudit(new FakeCerts(Cert("CN=a", 20)), new CertificateAuditOptions(), _time).RunAsync();
        Assert.Equal(AuditStatus.Warn, warn.Status);
        var ok = await new CertificateAudit(new FakeCerts(Cert("CN=a", 90)), new CertificateAuditOptions(), _time).RunAsync();
        Assert.Equal(AuditStatus.Ok, ok.Status);
        Assert.Empty(ok.Findings);
    }

    // ---------- Respaldos ----------

    private BackupTarget Target(string name, int maxHours = 26) => new() { Name = name, Path = Path.Combine(Dir, name), Pattern = "*.bak", MaxAgeHours = maxHours };

    private void WriteBackup(string folder, string file, DateTimeOffset when, int size = 100)
    {
        Directory.CreateDirectory(Path.Combine(Dir, folder));
        var path = Path.Combine(Dir, folder, file);
        File.WriteAllBytes(path, new byte[size]);
        File.SetLastWriteTimeUtc(path, when.UtcDateTime);
    }

    [Fact]
    public async Task Backups_not_configured_is_reported_explicitly_without_failing()
    {
        var r = await new BackupAudit(new BackupAuditOptions(), _time).RunAsync();
        Assert.Equal(AuditStatus.NotConfigured, r.Status);
    }

    [Fact]
    public async Task Backups_detect_stale_missing_empty_and_absent_folders()
    {
        WriteBackup("sql", "db.bak", _time.GetUtcNow().AddHours(-3));
        WriteBackup("viejo", "db.bak", _time.GetUtcNow().AddHours(-60));
        WriteBackup("vacio", "db.bak", _time.GetUtcNow().AddHours(-1), size: 0);
        Directory.CreateDirectory(Path.Combine(Dir, "sinarchivos"));
        var options = new BackupAuditOptions { Targets = { Target("sql"), Target("viejo"), Target("vacio"), Target("sinarchivos"), Target("noexiste") } };

        var r = await new BackupAudit(options, _time).RunAsync();
        Assert.Equal(AuditStatus.Fail, r.Status);
        Assert.Equal(4, r.Findings.Count);
        Assert.DoesNotContain(r.Findings, f => f.StartsWith("sql:"));
        Assert.Contains(r.Findings, f => f.StartsWith("viejo:") && f.Contains("60 h"));
        Assert.Contains(r.Findings, f => f.StartsWith("vacio:") && f.Contains("vacío"));

        var healthy = await new BackupAudit(new BackupAuditOptions { Targets = { Target("sql") } }, _time).RunAsync();
        Assert.Equal(AuditStatus.Ok, healthy.Status);
    }

    // ---------- Hardening ----------

    private sealed class FakeProbe(params HardeningCheck[] checks) : IHardeningProbe
    {
        public IReadOnlyList<HardeningCheck> Run() => checks;
    }

    [Fact]
    public async Task Hardening_warns_on_failed_checks_and_ignores_undetermined_ones()
    {
        var bad = await new HardeningAudit(new FakeProbe(new("Firewall", true, "ok"), new("NLA", false, "UserAuthentication=0"), new("SMB1", null, "?"))).RunAsync();
        Assert.Equal(AuditStatus.Warn, bad.Status);
        Assert.Equal(new[] { "NLA: UserAuthentication=0" }, bad.Findings);
        var good = await new HardeningAudit(new FakeProbe(new("Firewall", true, "ok"), new("SMB1", null, "?"))).RunAsync();
        Assert.Equal(AuditStatus.Ok, good.Status);
    }

    // ---------- AuditRunner ----------

    private sealed class StubAudit(string kind, string rule, Func<AuditOutcome> next) : IAudit
    {
        public string Kind => kind;
        public string AlertRuleId => rule;
        public TimeSpan Interval => TimeSpan.FromHours(1);
        public Task<AuditOutcome> RunAsync(CancellationToken ct = default) => Task.FromResult(next());
    }

    private AuditRunner Runner() => new(Store, new SystemAlertPublisher(Store, new NotificationDispatcher(Array.Empty<IAlertNotifier>()), _time),
        _time, NullLogger<AuditRunner>.Instance);

    [Fact]
    public async Task Runner_stores_results_and_alerts_once_per_distinct_problem_and_again_after_recovery()
    {
        var outcome = new AuditOutcome(AuditStatus.Fail, "vence pronto", new[] { "CN=a vence" });
        var audit = new StubAudit(AuditKinds.Certificates, "SEC-009", () => outcome);
        var runner = Runner();

        await runner.RunAsync(audit);
        await runner.RunAsync(audit);                                           // mismo problema: sin alerta repetida
        var alert = Assert.Single(Store.ListAlerts());
        Assert.Equal("SEC-009", alert.RuleId);
        Assert.Equal(Severity.Alta, alert.Severity);
        Assert.Equal(AuditStatus.Fail, Store.GetAudit(AuditKinds.Certificates)!.Status);

        outcome = new AuditOutcome(AuditStatus.Fail, "vence pronto", new[] { "CN=a vence", "CN=b vence" });
        await runner.RunAsync(audit);                                           // hallazgos distintos: nueva alerta
        Assert.Equal(2, Store.ListAlerts().Count);

        outcome = new AuditOutcome(AuditStatus.Ok, "todo bien", Array.Empty<string>());
        await runner.RunAsync(audit);                                           // recuperado: sin alerta, queda registrado
        Assert.Equal(2, Store.ListAlerts().Count);
        Assert.Equal(AuditStatus.Ok, Store.GetAudit(AuditKinds.Certificates)!.Status);

        outcome = new AuditOutcome(AuditStatus.Warn, "otra vez", new[] { "CN=a vence" });
        await runner.RunAsync(audit);
        Assert.Equal(3, Store.ListAlerts().Count);
        Assert.Equal(Severity.Media, Store.ListAlerts(limit: 1)[0].Severity);
    }

    [Fact]
    public async Task Runner_does_not_alert_when_not_configured_and_survives_a_crashing_audit()
    {
        var runner = Runner();
        await runner.RunAsync(new StubAudit(AuditKinds.Backups, "SEC-009", () => new AuditOutcome(AuditStatus.NotConfigured, "sin configurar", Array.Empty<string>())));
        Assert.Empty(Store.ListAlerts());
        Assert.Equal(AuditStatus.NotConfigured, Store.GetAudit(AuditKinds.Backups)!.Status);

        var r = await runner.RunAsync(new StubAudit(AuditKinds.Hardening, "AUDIT-HARDENING", () => throw new InvalidOperationException("boom")));
        Assert.Equal(AuditStatus.Error, r.Status);
        Assert.Equal(AuditStatus.Error, Store.GetAudit(AuditKinds.Hardening)!.Status);
    }

    [Fact]
    public async Task Audit_results_are_visible_through_the_status_service()
    {
        await Runner().RunAsync(new StubAudit(AuditKinds.Backups, "SEC-009", () => new AuditOutcome(AuditStatus.Ok, "1 respaldo(s) al día.", Array.Empty<string>())));
        var svc = new SecurityAgent.StatusApi.StatusService(Store, Array.Empty<SecurityAgent.Core.Rules.Rule>(), new Heartbeat());
        Assert.Equal("ok", svc.GetAudit().Backups.Status);
        Assert.Equal("sin_datos", svc.GetAudit().Hardening.Status);
    }

    // ---------- CLI: aprobación de enforce ----------

    [Fact]
    public void Set_mode_stores_the_human_approval_and_warns_about_the_second_key()
    {
        Store.Dispose();
        var cfg = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SecurityAgent:Store:DatabasePath"] = Path.Combine(Dir, "agent.db"),
            ["SecurityAgent:RulesDir"] = TestSupport.RulesDir,
        }).Build();

        var o = new StringWriter();
        Assert.Equal(0, Cli.TryRun(new[] { "--set-mode", "SEC-001", "enforce" }, Dir, cfg, o));
        Assert.Contains("AVISO", o.ToString());                               // el YAML sigue en observe
        using (var s = new SqliteStateStore(new StateStoreOptions { DatabasePath = Path.Combine(Dir, "agent.db") }))
            Assert.Equal(RuleMode.Enforce, s.GetRuleMode("SEC-001"));

        Assert.Equal(1, Cli.TryRun(new[] { "--set-mode", "SEC-999", "enforce" }, Dir, cfg, new StringWriter()));
        Assert.Equal(1, Cli.TryRun(new[] { "--set-mode", "SEC-001", "quizas" }, Dir, cfg, new StringWriter()));
    }
}
