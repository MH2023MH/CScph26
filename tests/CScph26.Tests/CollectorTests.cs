using Microsoft.Extensions.Configuration;
using System.Text;
using SecurityAgent.Collectors;
using SecurityAgent.Collectors.EventLog;
using SecurityAgent.Collectors.Files;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.State;

namespace CScph26.Tests;

public abstract class StoreTestBase : IDisposable
{
    protected readonly string Dir = Path.Combine(Path.GetTempPath(), "cscph26-" + Guid.NewGuid().ToString("N"));
    protected readonly SqliteStateStore Store;

    protected StoreTestBase()
    {
        Directory.CreateDirectory(Dir);
        Store = new(new StateStoreOptions { DatabasePath = Path.Combine(Dir, "agent.db") });
    }

    public virtual void Dispose()
    {
        Store.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(Dir, true); } catch { }
    }
}

public class EventLogXmlParserTests
{
    private static List<SecurityEvent> Parse(string channel) =>
        System.Xml.Linq.XDocument.Load(Path.Combine(XmlFixtureEventSource.RawDir, channel + ".xml")).Root!.Elements()
            .Select(e => EventLogXmlParser.Parse(e.ToString())!).ToList();

    [Fact]
    public void Failed_logon_maps_ip_account_and_source()
    {
        var e = Parse("Security")[0];
        Assert.Equal("eventlog.security", e.Source);
        Assert.Equal("4625", e.Type);
        Assert.Equal("203.0.113.50", e.Ip);
        Assert.Equal("administrator", e.Actor);
        Assert.Equal("sec-100001", e.Id);
        Assert.Equal(DateTimeOffset.Parse("2026-10-08T03:10:01Z").AddTicks(1234567), e.Timestamp);
    }

    [Fact]
    public void Account_group_and_task_events_map_target_and_actor()
    {
        var evs = Parse("Security");
        var created = evs.Single(e => e.Type == "4720");
        Assert.Equal("svc_tmp$", created.Target);
        Assert.Equal("SYSTEM", created.Actor);
        var group = evs.Single(e => e.Type == "4732");
        Assert.Equal("Administrators", group.Target);
        Assert.Contains("S-1-5-21", group.Detail);
        var task = evs.Single(e => e.Type == "4698");
        Assert.Equal("\\Microsoft\\Windows\\Sync", task.Target);
        Assert.Null(task.Detail);                       // TaskContent no se propaga
    }

    [Fact]
    public void Service_and_app_pool_events_map_target()
    {
        var evs = Parse("System");
        var svc = evs.Single(e => e.Type == "7045");
        Assert.Equal("UpdaterSvc", svc.Target);
        Assert.Equal("C:\\Users\\Public\\upd.exe", svc.Detail);
        Assert.All(evs.Where(e => e.Type == "5002"), e => Assert.Equal("AppPoolDemo", e.Target));
        Assert.All(evs, e => Assert.Equal("eventlog.system", e.Source));
    }

    [Theory]
    [InlineData("")]
    [InlineData("<no-xml")]
    [InlineData("<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System></System></Event>")]
    [InlineData("<script>alert(1)</script>")]
    public void Garbage_is_ignored_without_throwing(string xml) => Assert.Null(EventLogXmlParser.Parse(xml));

    [Fact]
    public void Dash_or_invalid_ip_becomes_null()
    {
        var xml = System.IO.File.ReadAllText(Path.Combine(XmlFixtureEventSource.RawDir, "Security.xml"))
            .Replace("203.0.113.50", "-");
        var first = System.Xml.Linq.XDocument.Parse(xml).Root!.Elements().First().ToString();
        Assert.Null(EventLogXmlParser.Parse(first)!.Ip);
    }

    [Fact]
    public void Channel_to_source_mapping()
    {
        Assert.Equal("defender", EventLogXmlParser.SourceOf("Microsoft-Windows-Windows Defender/Operational"));
        Assert.Equal("sysmon", EventLogXmlParser.SourceOf("Microsoft-Windows-Sysmon/Operational"));
    }
}

public sealed class EventLogCollectorTests : StoreTestBase
{
    private EventLogCollector Make(StartPolicy policy) => new(new XmlFixtureEventSource(XmlFixtureEventSource.RawDir), Store,
        new EventLogCollectorOptions { StartPolicy = policy }.With("Security", "System"));

    [Fact]
    public async Task Reads_everything_once_then_nothing_after_commit()
    {
        var c = Make(StartPolicy.FromStart);
        var b1 = await c.PollAsync();
        Assert.Equal(16, b1.Events.Count);                            // 12 de Security + 4 de System
        Assert.Equal(12, b1.Events.Count(e => e.Source == "eventlog.security"));
    }

    [Fact]
    public async Task Cursor_advances_only_on_commit()
    {
        var c = Make(StartPolicy.FromStart);
        var b1 = await c.PollAsync();
        var again = await c.PollAsync();                 // sin commit: se vuelve a entregar
        Assert.Equal(b1.Events.Count, again.Events.Count);
        b1.Commit();
        Assert.Empty((await c.PollAsync()).Events);
        Assert.Equal(100012, Store.GetCursor("eventlog:Security"));
    }

    [Fact]
    public async Task FromLatest_skips_history_on_first_run()
    {
        var c = Make(StartPolicy.FromLatest);
        Assert.Empty((await c.PollAsync()).Events);
        Assert.Equal(100012, Store.GetCursor("eventlog:Security"));
    }
}

internal static class OptionsExt
{
    public static EventLogCollectorOptions With(this EventLogCollectorOptions o, params string[] channels)
    {
        o.Channels = channels.ToList();
        return o;
    }
}

public sealed class LogTailerTests : StoreTestBase
{
    private string File1 => Path.Combine(Dir, "log.txt");

    [Fact]
    public void Reads_only_new_complete_lines_and_survives_restart()
    {
        File.WriteAllText(File1, "a\nb\n");
        var t = new LogTailer(Store, new UTF8Encoding(false));
        var r1 = t.Read(File1, startAtEndIfNew: false);
        Assert.Equal(new[] { "a", "b" }, r1.Lines.Select(l => l.Text));
        t.Commit(r1);

        File.AppendAllText(File1, "c\npartial");
        var r2 = new LogTailer(Store, new UTF8Encoding(false)).Read(File1, false);      // otro tailer = reinicio del agente
        Assert.Equal(new[] { "c" }, r2.Lines.Select(l => l.Text));                       // 'partial' sin salto de línea espera
        new LogTailer(Store, new UTF8Encoding(false)).Commit(r2);

        File.AppendAllText(File1, " line\n");
        var r3 = new LogTailer(Store, new UTF8Encoding(false)).Read(File1, false);
        Assert.Equal(new[] { "partial line" }, r3.Lines.Select(l => l.Text));
    }

    [Fact]
    public void Uncommitted_read_is_repeated()
    {
        File.WriteAllText(File1, "a\n");
        var t = new LogTailer(Store, new UTF8Encoding(false));
        Assert.Single(t.Read(File1, false).Lines);
        Assert.Single(t.Read(File1, false).Lines);
    }

    [Fact]
    public void Truncation_restarts_from_the_beginning()
    {
        File.WriteAllText(File1, "one\ntwo\nthree\n");
        var t = new LogTailer(Store, new UTF8Encoding(false));
        t.Commit(t.Read(File1, false));
        File.WriteAllText(File1, "new\n");                 // rotado: más corto que el offset
        Assert.Equal(new[] { "new" }, t.Read(File1, false).Lines.Select(l => l.Text));
    }

    [Fact]
    public void StartAtEnd_ignores_history_but_picks_up_later_lines()
    {
        File.WriteAllText(File1, "old1\nold2\n");
        var t = new LogTailer(Store, new UTF8Encoding(false));
        var r = t.Read(File1, startAtEndIfNew: true);
        Assert.Empty(r.Lines);
        t.Commit(r);
        File.AppendAllText(File1, "fresh\n");
        Assert.Equal(new[] { "fresh" }, t.Read(File1, true).Lines.Select(l => l.Text));
    }

    [Fact]
    public void Reads_utf16_with_bom_like_sql_errorlog()
    {
        var enc = new UnicodeEncoding(false, true);
        File.WriteAllBytes(File1, enc.GetPreamble().Concat(enc.GetBytes("línea uno\r\nlínea dos\r\n")).ToArray());
        var t = new LogTailer(Store, enc);
        var r = t.Read(File1, false);
        Assert.Equal(new[] { "línea uno", "línea dos" }, r.Lines.Select(l => l.Text));
        t.Commit(r);
        using (var fs = new FileStream(File1, FileMode.Append)) fs.Write(enc.GetBytes("tres\r\n"));
        Assert.Equal(new[] { "tres" }, t.Read(File1, false).Lines.Select(l => l.Text));
    }

    [Fact]
    public void Can_read_a_file_another_process_keeps_open()
    {
        using var writer = new FileStream(File1, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
        writer.Write(Encoding.UTF8.GetBytes("x\n"));
        writer.Flush();
        Assert.Single(new LogTailer(Store, new UTF8Encoding(false)).Read(File1, false).Lines);
    }
}

public sealed class IisCollectorTests : StoreTestBase
{
    [Fact]
    public async Task New_log_file_is_parsed_into_http_events()
    {
        var root = Path.Combine(Dir, "iis");
        var c = new IisLogCollector(Store, new IisLogCollectorOptions { Root = root });
        var site = Path.Combine(root, "W3SVC1");
        Directory.CreateDirectory(site);
        File.Copy(TestSupport.FixturePath("iis-attack.log"), Path.Combine(site, "u_ex261008.log"));    // creado tras arrancar el agente

        var batch = await c.PollAsync();
        Assert.Equal(8, batch.Events.Count);
        Assert.All(batch.Events, e => { Assert.Equal("iis", e.Source); Assert.Equal("http.request", e.Type); });
        var traversal = Assert.Single(batch.Events, e => e.Target!.Contains("../"));
        Assert.Equal("203.0.113.77", traversal.Ip);
        Assert.StartsWith("GET 400", traversal.Detail);
        Assert.Contains(batch.Events, e => e.Detail!.Contains("sqlmap"));
        Assert.Equal(batch.Events.Count, batch.Events.Select(e => e.Id).Distinct().Count());

        batch.Commit();
        Assert.Empty((await c.PollAsync()).Events);

        File.AppendAllText(Path.Combine(site, "u_ex261008.log"), "2026-10-08 07:20:00 192.168.1.10 GET /x - 443 - 203.0.113.80 Mozilla/5.0 404 1\n");
        var next = await c.PollAsync();
        Assert.Equal("203.0.113.80", Assert.Single(next.Events).Ip);       // reanuda a mitad de archivo usando la cabecera #Fields
    }

    [Fact]
    public async Task Pre_existing_history_is_not_replayed()
    {
        var root = Path.Combine(Dir, "iis");
        var site = Path.Combine(root, "W3SVC1");
        Directory.CreateDirectory(site);
        var log = Path.Combine(site, "u_ex261008.log");
        File.Copy(TestSupport.FixturePath("iis-attack.log"), log);
        var c = new IisLogCollector(Store, new IisLogCollectorOptions { Root = root });     // el archivo ya existía al arrancar
        var b = await c.PollAsync();
        Assert.Empty(b.Events);
        b.Commit();
        File.AppendAllText(log, "2026-10-08 08:00:00 192.168.1.10 GET /new - 443 - 203.0.113.81 Mozilla/5.0 200 1\n");
        Assert.Single((await c.PollAsync()).Events);
    }

    [Fact]
    public void Parser_ignores_malformed_lines_and_requires_fields_directive()
    {
        var p = new IisLogParser();
        Assert.Null(p.Parse("2026-10-08 07:00:01 a b", "x", 0));                 // sin #Fields
        p.Parse("#Fields: date time c-ip cs-uri-stem", "x", 0);
        Assert.Null(p.Parse("2026-10-08 07:00:01 1.2.3.4", "x", 1));             // columnas de menos
        Assert.NotNull(p.Parse("2026-10-08 07:00:01 1.2.3.4 /ok", "x", 2));
    }
}

public sealed class SqlCollectorTests : StoreTestBase
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Failed_logins_become_events(bool utf16)
    {
        var path = Path.Combine(Dir, "ERRORLOG");
        var c = new SqlErrorLogCollector(Store, new SqlErrorLogCollectorOptions { Path = path, Utf16 = utf16 }, TimeZoneInfo.Utc);
        var text = File.ReadAllText(TestSupport.FixturePath("sql-errorlog.txt")).Replace("\n", "\r\n");
        Encoding enc = utf16 ? new UnicodeEncoding(false, true) : new UTF8Encoding(false);
        File.WriteAllBytes(path, enc.GetPreamble().Concat(enc.GetBytes(text)).ToArray());      // el archivo aparece después de arrancar el agente

        var batch = await c.PollAsync();
        Assert.Equal(5, batch.Events.Count);                                  // 5 'Login failed' (las líneas 'Error: 18456' se ignoran)
        var attacker = batch.Events.Where(e => e.Ip == "203.0.113.90").ToList();
        Assert.Equal(4, attacker.Count);
        Assert.All(attacker, e => { Assert.Equal("sql", e.Source); Assert.Equal("login.failed", e.Type); });
        Assert.Contains(batch.Events, e => e.Actor == "AppUser" && e.Ip == "192.168.1.20");
        Assert.Equal(DateTimeOffset.Parse("2026-10-08T08:00:01.10Z"), attacker[0].Timestamp);
    }
}

public sealed class FileChangeCollectorTests : StoreTestBase
{
    private FileChangeCollectorOptions Opts() => new() { Roots = { Dir }, Debounce = TimeSpan.FromMilliseconds(50) };

    [Theory]
    [InlineData("/apps/shop/web.config", true)]
    [InlineData("/apps/shop/appsettings.Production.json", true)]
    [InlineData("/apps/shop/bin/Shop.dll", true)]
    [InlineData("/apps/shop/readme.txt", false)]
    [InlineData("/apps/shop/logs/app.dll", false)]
    [InlineData("/apps/shop/data/agent.db", false)]
    [InlineData("/apps/shop/obj/x.dll", false)]
    public void ShouldTrack_filters_noise(string path, bool expected)
    {
        using var c = new FileChangeCollector(new FileChangeCollectorOptions());
        Assert.Equal(expected, c.ShouldTrack(path));
    }

    private static async Task<List<SecurityEvent>> WaitFor(FileChangeCollector c, Func<List<SecurityEvent>, bool> done)
    {
        var all = new List<SecurityEvent>();
        for (var i = 0; i < 60 && !done(all); i++)
        {
            await Task.Delay(100);
            all.AddRange((await c.PollAsync()).Events);
        }
        return all;
    }

    [Fact]
    public async Task Detects_creation_change_and_deletion_of_tracked_files()
    {
        using var c = new FileChangeCollector(Opts());
        var cfg = Path.Combine(Dir, "web.config");
        File.WriteAllText(cfg, "<configuration/>");
        File.WriteAllText(Path.Combine(Dir, "notes.txt"), "ruido");          // no relevante
        var created = await WaitFor(c, evs => evs.Any(e => e.Type == "file.created"));
        Assert.Contains(created, e => e.Type == "file.created" && e.Target == cfg);
        Assert.DoesNotContain(created, e => e.Target!.EndsWith("notes.txt"));

        await Task.Delay(200);
        File.AppendAllText(cfg, "<!-- tampered -->");
        var changed = await WaitFor(c, evs => evs.Any(e => e.Type == "file.changed"));
        Assert.Contains(changed, e => e.Type == "file.changed" && e.Target == cfg);

        File.Delete(cfg);
        var deleted = await WaitFor(c, evs => evs.Any(e => e.Type == "file.deleted"));
        Assert.Contains(deleted, e => e.Type == "file.deleted" && e.Target == cfg);
    }
}

public class OptionsBindingTests
{
    [Fact]
    public void Configured_lists_replace_defaults_instead_of_appending_to_them()
    {
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SecurityAgent:Collectors:EventLog:Channels:0"] = "Security",
            ["SecurityAgent:Collectors:Files:Include:0"] = "web.config",
        }).Build();
        var o = SecurityAgent.Worker.AgentComposition.BindOptions(config);
        Assert.Equal(new[] { "Security" }, o.Collectors.EventLog.EffectiveChannels);
        Assert.Equal(new[] { "web.config" }, o.Collectors.Files.EffectiveInclude);
        Assert.Equal(4, new EventLogCollectorOptions().EffectiveChannels.Count);   // sin configurar: valores por defecto
    }
}
