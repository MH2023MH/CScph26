using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;
using SecurityAgent.Responders.Notifications;

namespace CScph26.Tests;

public sealed class PipelineTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cscph26-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Simulated_rdp_attack_flows_event_to_alert_to_notification_without_blocking_in_observe()
    {
        using var store = new SqliteStateStore(new StateStoreOptions { DatabasePath = Path.Combine(_dir, "agent.db") });
        using var smtp = new FakeSmtpServer();
        using var hook = new FakeWebhook();
        var allow = Allowlist.LoadFile(Path.Combine(TestSupport.RulesDir, "allowlist.yaml"));
        var fw = new FakeFirewall();
        var dispatcher = new NotificationDispatcher(new IAlertNotifier[]
        {
            new SmtpNotifier(new SmtpOptions { Host = "127.0.0.1", Port = smtp.Port, UseSsl = false, From = "a@t.local", To = { "o@t.local" } }),
            new TeamsWebhookNotifier(new HttpClient(), new TeamsOptions { WebhookUrl = hook.Url }),
        });
        var pipeline = new SecurityPipeline(store, new RuleEngine(RuleLoader.LoadDirectory(TestSupport.RulesDir), allow),
            new ResponseExecutor(store, fw, allow), dispatcher);

        var alerts = new List<SecurityAgent.Core.Alerts.Alert>();
        foreach (var ev in TestSupport.LoadJsonFixture("eventlog-security.json", "eventlog.security"))
            alerts.AddRange(await pipeline.ProcessAsync(ev));

        Assert.Equal(3, alerts.Count);                                   // SEC-001 x1 + SEC-003 x2
        Assert.Contains(alerts, a => a.RuleId == "SEC-001" && a.GroupKey == "203.0.113.50");
        Assert.Empty(fw.Blocked);                                        // observe: ninguna acción
        Assert.Empty(store.ListActiveBlocks());
        Assert.Equal(3, store.ListAlerts().Count);
        Assert.Equal(11, store.QueryEvents(limit: 100).Count);           // todos los eventos persistidos
        Assert.Equal(3, smtp.Messages.Count);                            // una por alerta (correo)
        Assert.Equal(3, hook.Bodies.Count);                              // y por Teams
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch { }
    }
}
