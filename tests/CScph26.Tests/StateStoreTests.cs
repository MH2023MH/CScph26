using Microsoft.Extensions.Time.Testing;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.State;

namespace CScph26.Tests;

public sealed class StateStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cscph26-" + Guid.NewGuid().ToString("N"));
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 10, 8, 12, 0, 0, TimeSpan.Zero));
    private string Db => Path.Combine(_dir, "agent.db");

    private SqliteStateStore Open(StateStoreOptions? o = null) =>
        new(o ?? new StateStoreOptions { DatabasePath = Db }, _time);

    private static SecurityEvent Ev(string id, DateTimeOffset ts, string? ip = "203.0.113.50", string source = "eventlog.security") =>
        new(id, ts, source, "4625", Severity.Media, "admin", ip, null);

    [Fact]
    public void Events_persist_across_reopen()
    {
        using (var s = Open()) s.AddEvent(Ev("E1", _time.GetUtcNow()));
        using var s2 = Open();
        var e = s2.GetEvent("E1");
        Assert.NotNull(e);
        Assert.Equal("203.0.113.50", e!.Ip);
        Assert.Equal(Severity.Media, e.Severity);
        Assert.Null(s2.GetEvent("NOPE"));
    }

    [Fact]
    public void Query_filters_by_ip_source_and_time()
    {
        using var s = Open();
        var now = _time.GetUtcNow();
        s.AddEvent(Ev("A", now.AddMinutes(-10)));
        s.AddEvent(Ev("B", now.AddMinutes(-1), ip: "203.0.113.99"));
        s.AddEvent(Ev("C", now.AddMinutes(-1), source: "iis"));
        Assert.Equal(2, s.QueryEvents(ip: "203.0.113.50").Count);
        Assert.Single(s.QueryEvents(source: "iis"));
        Assert.Equal(2, s.QueryEvents(since: now.AddMinutes(-5)).Count);
    }

    [Fact]
    public void Blocks_expire_and_can_be_removed()
    {
        using var s = Open();
        var now = _time.GetUtcNow();
        s.AddBlock(new("203.0.113.50", "SEC-001", "fuerza bruta", now, now.AddHours(1)));
        s.AddBlock(new("203.0.113.51", "SEC-001", "fuerza bruta", now, now.AddHours(3)));
        Assert.Equal(2, s.ListActiveBlocks().Count);
        _time.Advance(TimeSpan.FromHours(2));
        Assert.Single(s.ListActiveBlocks());
        Assert.Single(s.ListExpiredBlocks());
        Assert.Equal(0, s.Purge().BlocksDeleted);   // vencido: se conserva hasta que el responder confirme que retiró la regla del firewall
        _time.Advance(TimeSpan.FromDays(2));
        Assert.Equal(0, s.Purge().BlocksDeleted);   // ni siquiera con el tiempo: borrarlo antes dejaría una regla huérfana y permanente
        Assert.Equal(2, s.ListExpiredBlocks().Count);
        Assert.True(s.RemoveBlock("203.0.113.50"));
        Assert.True(s.RemoveBlock("203.0.113.51"));
        s.AddBlock(new("203.0.113.51", "SEC-001", "fuerza bruta", _time.GetUtcNow(), _time.GetUtcNow().AddHours(1)));
        Assert.True(s.RemoveBlock("203.0.113.51"));
        Assert.False(s.RemoveBlock("203.0.113.51"));
        Assert.Empty(s.ListActiveBlocks());
    }

    [Fact]
    public void Block_without_future_expiration_is_rejected()
    {
        using var s = Open();
        var now = _time.GetUtcNow();
        Assert.Throws<ArgumentException>(() => s.AddBlock(new("203.0.113.50", "SEC-001", "x", now, now)));
    }

    [Fact]
    public void Rules_default_to_observe_and_persist_mode()
    {
        using (var s = Open())
        {
            Assert.Equal(RuleMode.Observe, s.GetRuleMode("SEC-001"));
            s.SetRuleMode("SEC-001", RuleMode.Enforce);
        }
        using var s2 = Open();
        Assert.Equal(RuleMode.Enforce, s2.GetRuleMode("SEC-001"));
        Assert.Equal(RuleMode.Observe, s2.GetRuleMode("SEC-002"));
    }

    [Fact]
    public void Purge_removes_events_older_than_retention()
    {
        using var s = Open(new StateStoreOptions { DatabasePath = Db, EventRetention = TimeSpan.FromDays(7) });
        var now = _time.GetUtcNow();
        s.AddEvent(Ev("old", now.AddDays(-8)));
        s.AddEvent(Ev("new", now.AddDays(-1)));
        Assert.Equal(1, s.Purge().EventsDeleted);
        Assert.Null(s.GetEvent("old"));
        Assert.NotNull(s.GetEvent("new"));
    }

    [Fact]
    public void Purge_caps_event_count_keeping_newest()
    {
        using var s = Open(new StateStoreOptions { DatabasePath = Db, MaxEvents = 10 });
        var now = _time.GetUtcNow();
        for (var i = 0; i < 25; i++) s.AddEvent(Ev($"E{i}", now.AddSeconds(-100 + i)));
        s.Purge();
        Assert.Equal(10, s.EventCount);
        Assert.NotNull(s.GetEvent("E24"));
        Assert.Null(s.GetEvent("E0"));
    }

    [Fact]
    public void Purge_bounds_database_size()
    {
        const long max = 256 * 1024;
        using var s = Open(new StateStoreOptions { DatabasePath = Db, MaxEvents = int.MaxValue, MaxDatabaseBytes = max });
        var now = _time.GetUtcNow();
        for (var i = 0; i < 5000; i++)
            s.AddEvent(new($"E{i:D5}", now.AddSeconds(-5000 + i), "iis", "http.request", Severity.Info, null, "203.0.113.77", new string('x', 200)));
        Assert.True(s.UsedBytes > max, "la prueba necesita superar el límite antes de purgar");
        s.Purge();
        Assert.True(s.UsedBytes <= max, $"UsedBytes={s.UsedBytes} excede {max}");
        Assert.NotNull(s.GetEvent("E04999"));   // se conserva lo más reciente
        Assert.True(s.EventCount > 0);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch { /* limpieza best-effort */ }
    }
}
