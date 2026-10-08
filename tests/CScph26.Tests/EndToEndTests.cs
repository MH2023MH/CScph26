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

    private ServiceProvider Build(string? rulesDir = null, Dictionary<string, string?>? extra = null)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SecurityAgent:RulesDir"] = rulesDir ?? TestSupport.RulesDir,
            ["SecurityAgent:Store:DatabasePath"] = Path.Combine(_dir, "agent.db"),
            ["SecurityAgent:Collectors:EventLog:StartPolicy"] = "FromStart",
            ["SecurityAgent:Collectors:EventLog:Channels:0"] = "Security",
            ["SecurityAgent:Collectors:EventLog:Channels:1"] = "System",
        }.Concat(extra ?? new()).ToDictionary(k => k.Key, v => v.Value)).Build();
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
    public async Task Alerts_reach_the_external_log_destination_and_status_reports_it()
    {
        var share = Path.Combine(_dir, "share", "{date}.jsonl");
        using var sp = Build(extra: new()
        {
            ["SecurityAgent:LogShipping:Enabled"] = "true",
            ["SecurityAgent:LogShipping:File:Path"] = share,
        });
        await sp.GetRequiredService<CollectorRunner>().RunOnceAsync();

        var shipper = sp.GetRequiredService<LogShipperHolder>().Shipper;
        Assert.NotNull(shipper);
        Assert.True(await shipper!.ShipOnceAsync() > 0);
        var text = string.Join("\n", Directory.GetFiles(Path.Combine(_dir, "share")).SelectMany(File.ReadAllLines));
        Assert.Contains("\"rule_id\":\"SEC-001\"", text);
        Assert.Contains("\"rule_id\":\"SEC-003\"", text);
        Assert.Contains("agent_status", text);
    }

    [Fact]
    public void Without_a_destination_shipping_is_disabled_and_visible_in_status()
    {
        using var sp = Build();
        Assert.Null(sp.GetRequiredService<LogShipperHolder>().Shipper);
        Assert.Equal("disabled", sp.GetRequiredService<StatusService>().GetStatus().LogShipping);
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
