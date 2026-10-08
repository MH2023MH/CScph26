using System.Text.Json;
using SecurityAgent.Core.Events;
using SecurityAgent.Responders;

namespace CScph26.Tests;

internal static class TestSupport
{
    public static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "CScph26.sln"))) dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("No se encontró CScph26.sln");
    }

    public static string RulesDir => Path.Combine(RepoRoot(), "rules");
    public static string FixturePathAbs(string name) => Path.Combine(RepoRoot(), "tests", "fixtures", name);
    public static string FixturePath(string name) => Path.Combine(RepoRoot(), "tests", "fixtures", "events", name);

    /// <summary>Convierte los JSON simulados al modelo común (los collectors reales de la Fase 6 harán lo propio con el log crudo).</summary>
    public static List<SecurityEvent> LoadJsonFixture(string file, string source)
    {
        var root = JsonDocument.Parse(File.ReadAllText(FixturePath(file))).RootElement.GetProperty("eventos");
        return root.EnumerateArray().Select(e =>
        {
            string? Str(string n) => e.TryGetProperty(n, out var v) ? v.GetString() : null;
            return new SecurityEvent(
                e.GetProperty("id").GetString()!,
                DateTimeOffset.Parse(e.GetProperty("tiempo").GetString()!, null, System.Globalization.DateTimeStyles.AssumeUniversal),
                source,
                e.GetProperty("event_id").GetInt32().ToString(),
                Severity.Info,
                Str("usuario"), Str("ip_origen"), Str("app_pool") ?? Str("servicio") ?? Str("tarea"));
        }).ToList();
    }
}

internal sealed class FakeFirewall : IFirewall
{
    public List<string> Blocked { get; } = new();
    public List<string> Unblocked { get; } = new();
    public bool FailUnblock { get; set; }
    public void BlockIp(string ip, string ruleName) => Blocked.Add(ip);
    public void UnblockIp(string ip)
    {
        if (FailUnblock) throw new InvalidOperationException("firewall no disponible");
        Unblocked.Add(ip);
    }
}

internal sealed class XmlFixtureEventSource(string dir) : SecurityAgent.Collectors.EventLog.IEventRecordSource
{
    public static string RawDir => Path.Combine(TestSupport.RepoRoot(), "tests", "fixtures", "events", "raw");

    private List<SecurityAgent.Collectors.EventLog.RawEventRecord> Load(string channel)
    {
        var path = Path.Combine(dir, channel.Replace('/', '_') + ".xml");
        if (!File.Exists(path)) return new();
        return System.Xml.Linq.XDocument.Load(path).Root!.Elements()
            .Select(e => e.ToString())
            .Select(x => new SecurityAgent.Collectors.EventLog.RawEventRecord(
                SecurityAgent.Collectors.EventLog.EventLogXmlParser.RecordIdOf(x) ?? 0, x))
            .OrderBy(r => r.RecordId).ToList();
    }

    public IReadOnlyList<SecurityAgent.Collectors.EventLog.RawEventRecord> Read(string channel, long afterRecordId, int max) =>
        Load(channel).Where(r => r.RecordId > afterRecordId).Take(max).ToList();

    public long LatestRecordId(string channel) => Load(channel).Select(r => r.RecordId).DefaultIfEmpty(0).Max();
}
