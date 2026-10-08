using System.Globalization;
using System.Text.RegularExpressions;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.Text;

namespace SecurityAgent.Collectors.Files;

/// <summary>Parser de ERRORLOG de SQL Server. Por ahora solo reconoce inicios de sesión fallidos (error 18456).</summary>
public sealed partial class SqlErrorLogParser(TimeZoneInfo? serverTimeZone = null)
{
    private readonly TimeZoneInfo _tz = serverTimeZone ?? TimeZoneInfo.Local;

    [GeneratedRegex(@"^(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?<proc>\S+)\s+(?<msg>.*)$")]
    private static partial Regex LineRx();

    [GeneratedRegex(@"^Login failed for user '(?<user>[^']*)'")]
    private static partial Regex FailedRx();

    [GeneratedRegex(@"\[CLIENT:\s*(?<ip>[^\]]+)\]")]
    private static partial Regex ClientRx();

    public SecurityEvent? Parse(string line, string idPrefix)
    {
        var m = LineRx().Match(line);
        if (!m.Success) return null;
        var f = FailedRx().Match(m.Groups["msg"].Value);
        if (!f.Success) return null;
        if (!DateTime.TryParse(m.Groups["ts"].Value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var local)) return null;

        var utc = TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(local, DateTimeKind.Unspecified), _tz);
        var ip = ClientRx().Match(m.Groups["msg"].Value) is { Success: true } c ? Sanitizer.CleanIp(c.Groups["ip"].Value) : null;   // "<local machine>" → null
        var msg = m.Groups["msg"].Value;
        var reasonAt = msg.IndexOf("Reason:", StringComparison.Ordinal);
        return new SecurityEvent($"{idPrefix}-{utc:yyyyMMddHHmmssff}", new DateTimeOffset(utc, TimeSpan.Zero), "sql", "login.failed",
            Severity.Info, f.Groups["user"].Value, ip, null, reasonAt >= 0 ? msg[reasonAt..] : null);
    }
}
