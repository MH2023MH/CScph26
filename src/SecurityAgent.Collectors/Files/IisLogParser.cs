using System.Globalization;
using SecurityAgent.Core.Events;

namespace SecurityAgent.Collectors.Files;

/// <summary>Parser de logs W3C de IIS. Las columnas se toman de la directiva #Fields, así que tolera configuraciones distintas.</summary>
public sealed class IisLogParser(Func<System.Net.IPAddress, bool>? isTrustedPeer = null)
{
    private string[]? _fields;

    public static string[]? ParseFieldsDirective(string line) =>
        line.StartsWith("#Fields:", StringComparison.Ordinal) ? line[8..].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries) : null;

    /// <summary>Lee la directiva #Fields de la cabecera de un archivo (necesario al reanudar a mitad de archivo).</summary>
    public static string[]? ReadFieldsFromHead(string path, int maxLines = 20)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var sr = new StreamReader(fs);
        for (var i = 0; i < maxLines && sr.ReadLine() is { } line; i++)
            if (ParseFieldsDirective(line) is { } f) return f;
        return null;
    }

    /// <summary>
    /// Tras cloudflared/Cloudflare, c-ip es la dirección del túnel y el cliente real viaja en la cabecera CF-Connecting-IP
    /// (debe registrarse como campo personalizado en IIS). Solo se confía en ella cuando el par es el propio servidor
    /// (loopback o una dirección propia): cloudflared corre en la misma máquina. Un equipo de la red interna, o cualquier otro
    /// par, puede escribir esa cabecera a mano para acusar a una IP ajena, así que no se le cree.
    /// </summary>
    public static string? ClientIp(string? cIp, string? cfConnectingIp, Func<System.Net.IPAddress, bool>? isTrustedPeer = null)
    {
        if (cIp is null || cfConnectingIp is null) return cIp;
        isTrustedPeer ??= DefaultTrustedPeer;
        if (!System.Net.IPAddress.TryParse(cIp, out var peer) || !isTrustedPeer(peer)) return cIp;
        return System.Net.IPAddress.TryParse(cfConnectingIp.Trim(), out var real) ? real.ToString() : cIp;
    }

    private static bool DefaultTrustedPeer(System.Net.IPAddress a) =>
        System.Net.IPAddress.IsLoopback(a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a) || SecurityAgent.Core.Rules.HostAddresses.Shared.IsOwn(a);

    public void SetFields(string[]? fields) { if (fields != null) _fields = fields; }

    /// <summary>Devuelve el evento, o null para directivas, líneas mal formadas o sin columnas conocidas.</summary>
    public SecurityEvent? Parse(string line, string idPrefix, long offset)
    {
        if (line.Length == 0) return null;
        if (line[0] == '#') { SetFields(ParseFieldsDirective(line)); return null; }
        if (_fields is null) return null;

        var parts = line.Split(' ');
        if (parts.Length != _fields.Length) return null;
        string? F(string name)
        {
            var i = Array.FindIndex(_fields, f => f.Equals(name, StringComparison.OrdinalIgnoreCase));
            return i < 0 || parts[i] == "-" ? null : parts[i];
        }

        var date = F("date");
        var time = F("time");
        if (date is null || time is null
            || !DateTimeOffset.TryParse($"{date}T{time}Z", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var ts))
            return null;

        var stem = F("cs-uri-stem");
        var query = F("cs-uri-query");
        var target = stem is null ? null : query is null ? stem : stem + "?" + query;
        var detail = $"{F("cs-method") ?? "?"} {F("sc-status") ?? "?"} {F("cs(User-Agent)") ?? "-"}";
        return new SecurityEvent($"{idPrefix}-{offset}", ts.ToUniversalTime(), "iis", "http.request", Severity.Info,
            F("cs-username"), ClientIp(F("c-ip"), F("CF-Connecting-IP"), isTrustedPeer), target, detail);
    }
}
