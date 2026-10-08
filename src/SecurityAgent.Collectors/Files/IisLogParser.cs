using System.Globalization;
using SecurityAgent.Core.Events;

namespace SecurityAgent.Collectors.Files;

/// <summary>Parser de logs W3C de IIS. Las columnas se toman de la directiva #Fields, así que tolera configuraciones distintas.</summary>
public sealed class IisLogParser
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
            var i = Array.IndexOf(_fields, name);
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
            F("cs-username"), F("c-ip"), target, detail);
    }
}
