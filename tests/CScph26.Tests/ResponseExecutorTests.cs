using Microsoft.Extensions.Time.Testing;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;

namespace CScph26.Tests;

public sealed class ResponseExecutorTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cscph26-" + Guid.NewGuid().ToString("N"));
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 10, 8, 12, 0, 0, TimeSpan.Zero));
    private readonly SqliteStateStore _store;
    private readonly FakeFirewall _fw = new();
    private readonly Allowlist _allow = new(new[] { "192.168.0.0/16" });

    public ResponseExecutorTests() => _store = new(new StateStoreOptions { DatabasePath = Path.Combine(_dir, "agent.db") }, _time);

    private ResponseExecutor Exec() => new(_store, _fw, _allow, _time);

    private static Rule BlockRule(RuleMode fileMode, bool excludeAllow = true) => new(
        "SEC-001", "Fuerza bruta RDP", fileMode, "eventlog.security", new HashSet<string> { "4625" }, GroupBy.Ip, 8,
        TimeSpan.FromMinutes(5), Severity.Alta, excludeAllow, RuleActions.BlockIp, TimeSpan.FromHours(1),
        new[] { "correo" }, null);

    private RuleHit Hit(Rule r, string ip) => new(r, ip, new[] { "E1", "E2" }, _time.GetUtcNow());

    [Fact]
    public void Observe_mode_never_executes_actions()
    {
        // archivo en observe (aunque el estado diga enforce) y estado en observe (aunque el archivo diga enforce)
        _store.SetRuleMode("SEC-001", RuleMode.Enforce);
        var a1 = Exec().Handle(Hit(BlockRule(RuleMode.Observe), "203.0.113.50"));
        _store.SetRuleMode("SEC-001", RuleMode.Observe);
        var a2 = Exec().Handle(Hit(BlockRule(RuleMode.Enforce), "203.0.113.50"));

        Assert.Empty(_fw.Blocked);
        Assert.Empty(_store.ListActiveBlocks());
        Assert.All(new[] { a1, a2 }, a => { Assert.Equal(RuleMode.Observe, a.Mode); Assert.StartsWith("observe", a.ActionTaken); });
        Assert.Equal(2, _store.ListAlerts().Count);    // la alerta sí queda registrada
    }

    [Fact]
    public void Enforce_requires_both_keys_and_blocks_with_expiry()
    {
        _store.SetRuleMode("SEC-001", RuleMode.Enforce);
        var alert = Exec().Handle(Hit(BlockRule(RuleMode.Enforce), "203.0.113.50"));

        Assert.Equal(RuleMode.Enforce, alert.Mode);
        Assert.Equal(new[] { "203.0.113.50" }, _fw.Blocked);
        var block = Assert.Single(_store.ListActiveBlocks());
        Assert.Equal(_time.GetUtcNow().AddHours(1), block.ExpiresAt);
        Assert.Contains("bloqueo", alert.ActionTaken);
    }

    [Fact]
    public void Allowlisted_ip_is_never_blocked_even_in_enforce_without_rule_exclusion()
    {
        _store.SetRuleMode("SEC-001", RuleMode.Enforce);
        var alert = Exec().Handle(Hit(BlockRule(RuleMode.Enforce, excludeAllow: false), "192.168.1.25"));

        Assert.Empty(_fw.Blocked);
        Assert.Empty(_store.ListActiveBlocks());
        Assert.StartsWith("omitido", alert.ActionTaken);
    }

    [Fact]
    public void Unblock_rolls_back_firewall_and_store()
    {
        _store.SetRuleMode("SEC-001", RuleMode.Enforce);
        var ex = Exec();
        ex.Handle(Hit(BlockRule(RuleMode.Enforce), "203.0.113.50"));
        Assert.True(ex.Unblock("203.0.113.50"));
        Assert.Contains("203.0.113.50", _fw.Unblocked);
        Assert.Empty(_store.ListActiveBlocks());
        Assert.False(ex.Unblock("203.0.113.50"));
    }

    [Fact]
    public void SweepExpired_removes_old_blocks_and_retries_when_firewall_fails()
    {
        _store.SetRuleMode("SEC-001", RuleMode.Enforce);
        var ex = Exec();
        ex.Handle(Hit(BlockRule(RuleMode.Enforce), "203.0.113.50"));
        _time.Advance(TimeSpan.FromHours(2));

        _fw.FailUnblock = true;
        Assert.Equal(0, ex.SweepExpired());
        Assert.Single(_store.ListExpiredBlocks());       // se conserva para reintentar

        _fw.FailUnblock = false;
        Assert.Equal(1, ex.SweepExpired());
        Assert.Empty(_store.ListExpiredBlocks());
        Assert.Contains("203.0.113.50", _fw.Unblocked);
    }

    [Fact]
    public void Firewall_failure_is_reported_without_recording_a_block()
    {
        _store.SetRuleMode("SEC-001", RuleMode.Enforce);
        var failing = new ThrowingFirewall();
        var alert = new ResponseExecutor(_store, failing, _allow, _time).Handle(Hit(BlockRule(RuleMode.Enforce), "203.0.113.50"));
        Assert.StartsWith("error", alert.ActionTaken);
        Assert.Empty(_store.ListActiveBlocks());
    }

    [Fact]
    public void Alerts_are_queryable_by_rule_and_severity()
    {
        var ex = Exec();
        ex.Handle(Hit(BlockRule(RuleMode.Observe), "203.0.113.50"));
        Assert.Single(_store.ListAlerts(ruleId: "SEC-001"));
        Assert.Empty(_store.ListAlerts(ruleId: "SEC-999"));
        Assert.Empty(_store.ListAlerts(minSeverity: Severity.Critica));
        var a = _store.ListAlerts()[0];
        Assert.Equal(a.Id, _store.GetAlert(a.Id)!.Id);
        Assert.Equal(new[] { "E1", "E2" }, _store.GetAlert(a.Id)!.EventIds);
    }

    private sealed class ThrowingFirewall : IFirewall
    {
        public void BlockIp(string ip, string ruleName) => throw new InvalidOperationException("netsh falló");
        public void UnblockIp(string ip) { }
    }

    public void Dispose()
    {
        _store.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch { }
    }
}

public class WindowsFirewallTests
{
    [Fact]
    public void Builds_expected_netsh_arguments()
    {
        var args = WindowsFirewall.BuildAddArgs("203.0.113.50");
        Assert.Contains("name=CScph26-block-203.0.113.50", args);
        Assert.Contains("action=block", args);
        Assert.Contains("remoteip=203.0.113.50", args);
        Assert.Equal("delete", WindowsFirewall.BuildDeleteArgs("203.0.113.50")[2]);
    }

    [Theory]
    [InlineData("1.2.3.4; calc")]
    [InlineData("any")]
    [InlineData("")]
    public void Rejects_anything_that_is_not_an_ip(string ip)
    {
        Assert.Throws<ArgumentException>(() => WindowsFirewall.BuildAddArgs(ip));
        Assert.Throws<ArgumentException>(() => WindowsFirewall.BuildDeleteArgs(ip));
    }
}
