using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using SecurityAgent.Collectors.Files;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;
using SecurityAgent.Responders.Notifications;
using Xunit.Abstractions;

namespace CScph26.Tests;

/// <summary>
/// Carga y estabilidad (fase de endurecimiento): ráfagas de tráfico hostil, inundación de claves falsas, logs enormes y una
/// corrida sostenida. Los umbrales son holgados a propósito (los runners de CI varían mucho): detectan regresiones groseras
/// (algo pasa de O(1) a O(n), la memoria crece sin límite), no miden el rendimiento fino. Cada prueba imprime su medición.
/// La duración de la corrida sostenida se controla con LOAD_SOAK_SECONDS (por defecto 5).
/// </summary>
[Trait("Category", "Load")]
public sealed class LoadTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cscph26-load-" + Guid.NewGuid().ToString("N"));

    private SqliteStateStore NewStore(StateStoreOptions? o = null)
    {
        Directory.CreateDirectory(_dir);
        o ??= new StateStoreOptions();
        o.DatabasePath = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".db");
        return new SqliteStateStore(o);
    }

    private SecurityPipeline NewPipeline(SqliteStateStore store, FakeFirewall? fw = null)
    {
        var allow = new Allowlist(new[] { "192.168.0.0/16" });
        return new SecurityPipeline(store, new RuleEngine(RuleLoader.LoadDirectory(TestSupport.RulesDir), allow),
            new ResponseExecutor(store, fw ?? new FakeFirewall(), allow), new NotificationDispatcher(Array.Empty<IAlertNotifier>()));
    }

    private static SecurityEvent Http(long i, string ip, DateTimeOffset t, string target) =>
        new($"iis-load-{i}", t, "iis", "http.request", Severity.Info, null, ip, target, "GET 200 Mozilla/5.0");

    private static long UsedMb() { GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect(); return GC.GetTotalMemory(true) / (1024 * 1024); }

    [Fact]
    public async Task Pipeline_keeps_up_with_a_burst_of_mixed_normal_and_hostile_traffic()
    {
        using var store = NewStore();
        var pipeline = NewPipeline(store);
        var t0 = DateTimeOffset.UtcNow.AddHours(-1);
        const int n = 30_000;
        var sw = Stopwatch.StartNew();
        for (var start = 0; start < n; start += 500)
        {
            using var batch = store.BeginBatch();      // como el servicio real: una transacción por lote de un collector
            for (var i = start; i < Math.Min(n, start + 500); i++)
            {
                var hostile = i % 10 == 0;
                await pipeline.ProcessAsync(Http(i, $"203.0.{113 + i % 7}.{1 + i % 200}", t0.AddMilliseconds(i * 20),
                    hostile ? "/a/../../windows/win.ini?id=1' or 1=1--" : "/products/" + i % 500));
            }
        }
        sw.Stop();
        var rate = n / sw.Elapsed.TotalSeconds;
        output.WriteLine($"{n} eventos en {sw.Elapsed.TotalSeconds:0.0} s = {rate:0} eventos/s; alertas={store.ListAlerts(limit: 100_000).Count}; BD={store.UsedBytes / 1024} KB");
        Assert.True(rate > 300, $"rendimiento muy bajo: {rate:0} eventos/s");
        Assert.True(store.ListAlerts(limit: 100_000).Count > 0);
    }

    [Fact]
    public async Task Flood_of_spoofed_distinct_ips_and_users_stays_cheap_and_bounded()
    {
        using var store = NewStore();
        var pipeline = NewPipeline(store);
        var t0 = DateTimeOffset.UtcNow.AddHours(-1);
        const int n = 60_000;
        var before = UsedMb();
        var sw = Stopwatch.StartNew();
        for (var i = 0; i < n; i++)
            await pipeline.ProcessAsync(new SecurityEvent($"sec-flood-{i}", t0.AddMilliseconds(i), "eventlog.security", "4625", Severity.Media,
                $"user{i}", $"{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}.{1 + i % 250}"));
        sw.Stop();
        var after = UsedMb();
        output.WriteLine($"{n} claves distintas en {sw.Elapsed.TotalSeconds:0.0} s ({n / sw.Elapsed.TotalSeconds:0} ev/s); memoria {before} -> {after} MB");
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(180), "la inundación de claves falsas es demasiado lenta");
        Assert.True(after - before < 400, $"la memoria creció {after - before} MB");
    }

    [Fact]
    public async Task Large_iis_log_is_read_incrementally_with_bounded_memory()
    {
        var root = Path.Combine(_dir, "iis");
        Directory.CreateDirectory(root);
        using var store = NewStore();
        // El colector se crea ANTES de que exista el archivo: lo que ya existe al arrancar por primera vez se considera historia y se ignora.
        var collector = new IisLogCollector(store, new IisLogCollectorOptions { Root = root, MaxFileAge = TimeSpan.FromDays(3650) });
        var log = Path.Combine(root, "u_ex261008.log");
        const int lines = 300_000;
        using (var w = new StreamWriter(log, false, new UTF8Encoding(false)))
        {
            w.Write("#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status cs(User-Agent)\n");
            for (var i = 0; i < lines; i++)
                w.Write($"2026-10-08 07:{i / 3600 % 60:00}:{i % 60:00} 203.0.113.{1 + i % 200} GET /products/{i % 900} page={i} 200 Mozilla/5.0\n");
        }
        output.WriteLine($"archivo de prueba: {new FileInfo(log).Length / (1024 * 1024)} MB, {lines} líneas");

        var before = UsedMb();
        var total = 0;
        var polls = 0;
        var sw = Stopwatch.StartNew();
        while (polls++ < 400)
        {
            var batch = await collector.PollAsync();
            if (batch.Events.Count == 0) break;
            total += batch.Events.Count;
            batch.Commit();
        }
        sw.Stop();
        var after = UsedMb();
        output.WriteLine($"{total} eventos en {polls} lecturas, {sw.Elapsed.TotalSeconds:0.0} s ({total / sw.Elapsed.TotalSeconds:0} ev/s); memoria {before} -> {after} MB");
        Assert.Equal(lines, total);                                  // ni se pierde ni se repite una línea
        Assert.True(after - before < 150, $"la memoria creció {after - before} MB");
    }

    [Fact]
    public async Task Sustained_run_has_stable_memory_and_a_bounded_database()
    {
        var seconds = int.TryParse(Environment.GetEnvironmentVariable("LOAD_SOAK_SECONDS"), out var s) ? s : 5;
        using var store = NewStore(new StateStoreOptions { MaxEvents = 20_000, MaxEventsPerSource = 12_000, MaxAlerts = 2_000, MaxDatabaseBytes = 8L * 1024 * 1024 });
        var pipeline = NewPipeline(store);
        var t = DateTimeOffset.UtcNow.AddHours(-1);
        long i = 0, purges = 0;
        var baseline = -1L;
        var sw = Stopwatch.StartNew();
        var lastPurge = sw.Elapsed;
        while (sw.Elapsed < TimeSpan.FromSeconds(seconds))
        {
            using (store.BeginBatch())
            for (var k = 0; k < 500; k++, i++)
                await pipeline.ProcessAsync(Http(i, $"203.0.{113 + (int)(i % 5)}.{1 + (int)(i % 250)}", t.AddMilliseconds(i * 5),
                    i % 8 == 0 ? "/x/../../etc/passwd?a=1" : "/p/" + i % 300));
            if (sw.Elapsed - lastPurge > TimeSpan.FromSeconds(1)) { store.Purge(); purges++; lastPurge = sw.Elapsed; }
            if (baseline < 0 && sw.Elapsed > TimeSpan.FromSeconds(Math.Min(2, seconds / 2.0))) baseline = UsedMb();
        }
        store.Purge();
        var final = UsedMb();
        output.WriteLine($"{i} eventos en {sw.Elapsed.TotalSeconds:0.0} s ({i / sw.Elapsed.TotalSeconds:0} ev/s), {purges} purgas; memoria base {baseline} -> final {final} MB; " +
                         $"eventos={store.EventCount}; alertas={store.ListAlerts(limit: 100_000).Count}; BD={store.UsedBytes / 1024} KB");
        Assert.True(store.EventCount <= 20_000);
        Assert.True(store.UsedBytes <= 8L * 1024 * 1024 + 1024 * 1024, $"BD fuera de tope: {store.UsedBytes}");
        Assert.True(store.ListAlerts(limit: 100_000).Count <= 2_000);
        if (baseline >= 0) Assert.True(final - baseline < 120, $"la memoria sigue creciendo: {baseline} -> {final} MB");
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch { }
    }
}
