using System.Net.Http.Headers;
using System.Text;

namespace SecurityAgent.Responders.LogShipping;

/// <summary>Destino de los logs fuera del servidor (principio 7). El destino real se decide en la Fase 7 (compuerta).</summary>
public interface ILogSink
{
    /// <summary>Envía líneas JSON. Debe lanzar si no pudo entregarlas todas (el cursor no avanza).</summary>
    Task SendAsync(IReadOnlyList<string> jsonLines, CancellationToken ct = default);
}

public sealed class HttpLogSinkOptions
{
    public string Url { get; set; } = "";
    /// <summary>Secreto: appsettings.Production.json (gitignored).</summary>
    public string? Token { get; set; }
}

/// <summary>POST de NDJSON (una línea JSON por registro). Sirve para Wazuh/Seq/Elastic o un receptor propio.</summary>
public sealed class HttpLogSink(HttpClient http, HttpLogSinkOptions options) : ILogSink
{
    public async Task SendAsync(IReadOnlyList<string> jsonLines, CancellationToken ct = default)
    {
        if (options.Url == "") throw new InvalidOperationException("HttpLogSink sin URL");
        using var req = new HttpRequestMessage(HttpMethod.Post, options.Url)
        {
            Content = new StringContent(string.Join('\n', jsonLines) + "\n", Encoding.UTF8, "application/x-ndjson")
        };
        if (!string.IsNullOrEmpty(options.Token)) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.Token);
        using var resp = await http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
    }
}

public sealed class FileLogSinkOptions
{
    /// <summary>Ruta (p. ej. recurso compartido \\logs-vm\cscph26\{date}.jsonl). {date} = yyyyMMdd UTC.</summary>
    public string Path { get; set; } = "";
}

/// <summary>Anexa JSONL a un archivo, típicamente un recurso compartido de otra máquina donde el agente solo puede añadir.</summary>
public sealed class FileLogSink(FileLogSinkOptions options, TimeProvider? time = null) : ILogSink
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    public async Task SendAsync(IReadOnlyList<string> jsonLines, CancellationToken ct = default)
    {
        if (options.Path == "") throw new InvalidOperationException("FileLogSink sin ruta");
        var path = options.Path.Replace("{date}", _time.GetUtcNow().ToString("yyyyMMdd"));
        var dir = System.IO.Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        await using var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
        await using var w = new StreamWriter(fs, new UTF8Encoding(false));
        foreach (var line in jsonLines) await w.WriteLineAsync(line.AsMemory(), ct);
        await w.FlushAsync(ct);
    }
}
