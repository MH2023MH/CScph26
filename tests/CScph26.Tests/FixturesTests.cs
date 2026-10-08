using System.Text.Json;
using System.Text.RegularExpressions;

namespace CScph26.Tests;

/// <summary>Valida que el banco de eventos simulados (Fase 2) existe y cubre lo que exige el roadmap.</summary>
public class FixturesTests
{
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "CScph26.sln"))) dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("No se encontro CScph26.sln");
    }

    private static string Fixture(string name) =>
        File.ReadAllText(Path.Combine(RepoRoot(), "tests", "fixtures", "events", name));

    private static IEnumerable<JsonElement> Events(string file) =>
        JsonDocument.Parse(Fixture(file)).RootElement.GetProperty("eventos").EnumerateArray().ToList();

    [Fact]
    public void Security_log_covers_4625_4720_4732()
    {
        var ids = Events("eventlog-security.json").Select(e => e.GetProperty("event_id").GetInt32()).ToHashSet();
        Assert.Contains(4625, ids);
        Assert.Contains(4720, ids);
        Assert.Contains(4732, ids);
    }

    [Fact]
    public void Security_log_has_rdp_burst_above_default_threshold()
    {
        var porIp = Events("eventlog-security.json")
            .Where(e => e.GetProperty("event_id").GetInt32() == 4625)
            .GroupBy(e => e.GetProperty("ip_origen").GetString());
        Assert.Contains(porIp, g => g.Key == "203.0.113.50" && g.Count() >= 8);
        // la red interna no genera rafaga
        Assert.All(porIp.Where(g => g.Key!.StartsWith("192.168.")), g => Assert.True(g.Count() < 8));
    }

    [Fact]
    public void System_log_covers_7045_4698_and_app_pool_failures()
    {
        var ids = Events("eventlog-system.json").Select(e => e.GetProperty("event_id").GetInt32()).ToHashSet();
        Assert.Contains(7045, ids);
        Assert.Contains(4698, ids);
        Assert.Contains(5002, ids);
    }

    [Fact]
    public void Iis_log_contains_attack_patterns()
    {
        var log = Fixture("iis-attack.log");
        Assert.Contains("../", log);
        Assert.Contains("sqlmap", log);
        Assert.True(Regex.Matches(log, @" 404 ").Count >= 5, "se esperan 404 masivos");
    }

    [Fact]
    public void Sql_errorlog_contains_repeated_failed_logins()
    {
        var failed = Regex.Matches(Fixture("sql-errorlog.txt"), @"Login failed for user .* \[CLIENT: 203\.0\.113\.90\]");
        Assert.True(failed.Count >= 4);
    }

    [Fact]
    public void Allowlist_protects_internal_range_and_never_lists_attacker_ips()
    {
        var allow = File.ReadAllText(Path.Combine(RepoRoot(), "rules", "allowlist.yaml"));
        Assert.Contains("192.168.0.0/16", allow);
        Assert.DoesNotContain("203.0.113.", allow);
    }
}
