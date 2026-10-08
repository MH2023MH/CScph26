using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecurityAgent.Collectors.EventLog;
using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;
using SecurityAgent.StatusApi;
using SecurityAgent.Worker;

namespace CScph26.Tests;

/// <summary>Criterio de salida de la Fase 6: eventos crudos de Windows → collector → pipeline → reglas SEC-001/003/005.</summary>
public sealed class EndToEndTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cscph26-" + Guid.NewGuid().ToString("N"));
    private readonly FakeFirewall _fw = new();

    private ServiceProvider Build(string? rulesDir = null)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SecurityAgent:RulesDir"] = rulesDir ?? TestSupport.RulesDir,
            ["SecurityAgent:Store:DatabasePath"] = Path.Combine(_dir, "agent.db"),
            ["SecurityAgent:Collectors:EventLog:StartPolicy"] = "FromStart",
            ["SecurityAgent:Collectors:EventLog:Channels:0"] = "Security",
            ["SecurityAgent:Collectors:EventLog:Channels:1"] = "System",
        }).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IEventRecordSource>(new XmlFixtureEventSource(XmlFixtureEventSource.RawDir));
        services.AddSingleton<IFirewall>(_fw);
        services.AddSecurityAgent(config);
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task Sec001_Sec003_Sec005_fire_end_to_end_from_raw_windows_events()
    {
        using var sp = Build();
        var runner = sp.GetRequiredService<CollectorRunner>();
        var store = sp.GetRequiredService<IStateStore>();

        var processed = await runner.RunOnceAsync();

        Assert.Equal(16, processed);
        var alerts = store.ListAlerts(limit: 100);
        Assert.Single(alerts, a => a.RuleId == "SEC-001" && a.GroupKey == "203.0.113.50" && a.EventIds.Count == 8);
        Assert.Equal(2, alerts.Count(a => a.RuleId == "SEC-003"));
        Assert.Single(alerts, a => a.RuleId == "SEC-005" && a.GroupKey == "AppPoolDemo");
        Assert.Equal(4, alerts.Count);

        // observe: nada se ejecuta
        Assert.Empty(_fw.Blocked);
        Assert.Empty(store.ListActiveBlocks());
        Assert.All(alerts, a => Assert.Equal(RuleMode.Observe, a.Mode));

        // todo evento quedó persistido y citable
        Assert.NotNull(store.GetEvent("sec-100001"));
        Assert.Equal("UpdaterSvc", store.GetEvent("sys-5001")!.Target);

        // el latido avanzó y el estado refleja modo observe
        Assert.NotNull(sp.GetRequiredService<Heartbeat>().LastBeat);
        Assert.All(sp.GetRequiredService<StatusService>().GetStatus().Rules, r => Assert.Equal("observe", r.Mode));
    }

    [Fact]
    public async Task Second_cycle_does_not_reprocess_committed_events()
    {
        using var sp = Build();
        var runner = sp.GetRequiredService<CollectorRunner>();
        await runner.RunOnceAsync();
        var store = sp.GetRequiredService<IStateStore>();
        var before = store.ListAlerts(limit: 100).Count;
        Assert.Equal(0, await runner.RunOnceAsync());
        Assert.Equal(before, store.ListAlerts(limit: 100).Count);
    }

    [Fact]
    public void Invalid_rules_make_the_agent_fail_closed()
    {
        var bad = Path.Combine(_dir, "badrules");
        Directory.CreateDirectory(bad);
        File.WriteAllText(Path.Combine(bad, "allowlist.yaml"), "red_interna: [192.168.0.0/16]\n");
        File.WriteAllText(Path.Combine(bad, "SEC-X.yaml"), "id: SEC-X\nmodo: enforce-ya\nfuente: x\n");
        using var sp = Build(bad);
        Assert.Throws<RuleValidationException>(() => sp.GetRequiredService<RuleEngine>());
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch { }
    }
}
