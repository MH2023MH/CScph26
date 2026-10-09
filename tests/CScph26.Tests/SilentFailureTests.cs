using SecurityAgent.Collectors.EventLog;
using SecurityAgent.Collectors.Files;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;
using SecurityAdvisor;

namespace CScph26.Tests;

/// <summary>Un collector que no puede leer su fuente no debe fallar en silencio: el problema llega a la API de estado y al asesor.</summary>
public sealed class SilentFailureTests : StoreTestBase
{
    private sealed class BrokenSource : IEventRecordSource
    {
        public string? Error { get; set; } = "acceso denegado: simulado";
        public IReadOnlyList<RawEventRecord> Read(string channel, long afterRecordId, int max) => Array.Empty<RawEventRecord>();
        public long LatestRecordId(string channel) => 0;
        public string? LastError(string channel) => channel == "System" ? Error : null;
    }

    [Fact]
    public async Task Unreadable_channel_is_reported_once_and_cleared_when_it_recovers()
    {
        var src = new BrokenSource();
        var reports = new List<(string Key, string? Problem)>();
        var c = new EventLogCollector(src, Store, new EventLogCollectorOptions { StartPolicy = StartPolicy.FromStart, Channels = { "Security", "System" } },
            report: (k, p) => reports.Add((k, p)));

        await c.PollAsync();
        await c.PollAsync();                                   // mismo error: no se repite
        Assert.Equal(new[] { ("eventlog:System", (string?)"acceso denegado: simulado") }, reports);

        src.Error = null;
        await c.PollAsync();
        Assert.Equal(("eventlog:System", (string?)null), reports[^1]);
        Assert.Equal(2, reports.Count);
    }

    [Fact]
    public void Missing_watched_folder_is_reported()
    {
        var reports = new List<(string Key, string? Problem)>();
        using var c = new FileChangeCollector(new FileChangeCollectorOptions { Roots = { Path.Combine(Dir, "no-existe") } }, report: (k, p) => reports.Add((k, p)));
        var r = Assert.Single(reports);
        Assert.StartsWith("fs:", r.Key);
        Assert.Contains("no existe", r.Problem);

        reports.Clear();
        using var ok = new FileChangeCollector(new FileChangeCollectorOptions { Roots = { Dir } }, report: (k, p) => reports.Add((k, p)));
        Assert.Equal(("fs:" + Dir, (string?)null), Assert.Single(reports));     // carpeta válida: se informa como correcta (sin problema)
    }

    [Fact]
    public async Task Problems_travel_through_the_status_api_to_the_advisor_watcher()
    {
        await using var h = await AdvisorHarness.StartAsync(health: Health(out var health));
        health.Report("eventlog:System", "acceso denegado: simulado");

        var status = await h.Api.GetStatusAsync();
        Assert.Contains(status.Value!.Problems!, p => p.StartsWith("eventlog:System") && p.Contains("acceso denegado"));

        var beat = await new HeartbeatWatcher(h.Api).CheckAsync();
        Assert.Contains(beat.Warnings, w => w.Contains("no se puede leer") && w.Contains("eventlog:System"));
        Assert.False(beat.Healthy);

        health.Report("eventlog:System", null);
        Assert.Empty((await h.Api.GetStatusAsync()).Value!.Problems!);
    }

    private static AgentHealth Health(out AgentHealth h) => h = new AgentHealth();

    [Fact]
    public void Stats_command_summarizes_events_alerts_and_cursors()
    {
        Store.AddEvent(new("e1", DateTimeOffset.UtcNow, "eventlog.security", "4625", Severity.Info));
        Store.SetCursor("eventlog:Security", 42);
        var lines = Store.Diagnostics();
        Assert.Contains(lines, l => l.Contains("eventlog.security") && l.Contains("4625"));
        Assert.Contains(lines, l => l.Contains("eventlog:Security = 42"));
    }

    [Fact]
    public void Service_installed_event_4697_is_parsed_and_triggers_sec004()
    {
        const string xml = """
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4697</EventID><Level>0</Level>
            <TimeCreated SystemTime="2026-10-09T15:04:21.0000000Z"/><EventRecordID>777</EventRecordID><Channel>Security</Channel></System>
            <EventData><Data Name="SubjectUserName">runneradmin</Data><Data Name="ServiceName">CScph26CiSvc</Data><Data Name="ServiceFileName">C:\Windows\System32\cmd.exe</Data></EventData></Event>
            """;
        var ev = EventLogXmlParser.Parse(xml)!;
        Assert.Equal("4697", ev.Type);
        Assert.Equal("CScph26CiSvc", ev.Target);
        Assert.Equal("runneradmin", ev.Actor);
        Assert.Contains("cmd.exe", ev.Detail);

        var engine = new RuleEngine(RuleLoader.LoadDirectory(TestSupport.RulesDir), Allowlist.Empty);
        Assert.Contains(engine.Process(ev), h => h.Rule.Id == "SEC-004");
    }
}
