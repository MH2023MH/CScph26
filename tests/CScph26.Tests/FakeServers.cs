using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CScph26.Tests;

/// <summary>Servidor SMTP mínimo en memoria para probar el envío de correo sin red real.</summary>
internal sealed class FakeSmtpServer : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _cts = new();
    public List<string> Messages { get; } = new();
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public FakeSmtpServer()
    {
        _listener.Start();
        _ = Task.Run(AcceptLoop);
    }

    private async Task AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            try { _ = Task.Run(() => Handle(_listener.AcceptTcpClient())); }
            catch { return; }
            await Task.Yield();
        }
    }

    private void Handle(TcpClient client)
    {
        using var _ = client;
        using var stream = client.GetStream();
        using var reader = new StreamReader(stream, Encoding.ASCII);
        using var writer = new StreamWriter(stream, Encoding.ASCII) { NewLine = "\r\n", AutoFlush = true };
        writer.WriteLine("220 fake ESMTP");
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            var cmd = line.ToUpperInvariant();
            if (cmd.StartsWith("EHLO") || cmd.StartsWith("HELO")) writer.WriteLine("250 fake");
            else if (cmd.StartsWith("MAIL") || cmd.StartsWith("RCPT")) writer.WriteLine("250 OK");
            else if (cmd == "DATA")
            {
                writer.WriteLine("354 go ahead");
                var sb = new StringBuilder();
                while ((line = reader.ReadLine()) != null && line != ".") sb.AppendLine(line);
                lock (Messages) Messages.Add(sb.ToString());
                writer.WriteLine("250 queued");
            }
            else if (cmd == "QUIT") { writer.WriteLine("221 bye"); break; }
            else writer.WriteLine("250 OK");
        }
    }

    public void Dispose() { _cts.Cancel(); _listener.Stop(); }
}

/// <summary>Receptor HTTP que hace de webhook de Teams.</summary>
internal sealed class FakeWebhook : IDisposable
{
    private readonly HttpListener _http = new();
    public List<string> Bodies { get; } = new();
    public int StatusToReturn { get; set; } = 200;
    public string Url { get; }

    public FakeWebhook()
    {
        var port = ((IPEndPoint)GetFreePort()).Port;
        Url = $"http://127.0.0.1:{port}/hook/";
        _http.Prefixes.Add(Url);
        _http.Start();
        _ = Task.Run(async () =>
        {
            while (_http.IsListening)
            {
                try
                {
                    var ctx = await _http.GetContextAsync();
                    using var sr = new StreamReader(ctx.Request.InputStream);
                    var text = await sr.ReadToEndAsync();
                    lock (Bodies) Bodies.Add(text);
                    ctx.Response.StatusCode = StatusToReturn;
                    ctx.Response.Close();
                }
                catch { return; }
            }
        });
    }

    private static EndPoint GetFreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var ep = l.LocalEndpoint;
        l.Stop();
        return ep;
    }

    public void Dispose() => _http.Close();
}

/// <summary>Servidor HTTP que responde con JSON preparado (hace de Ollama en las pruebas).</summary>
internal sealed class FakeJsonServer : IDisposable
{
    private readonly HttpListener _http = new();
    public List<string> Requests { get; } = new();
    public Func<int, string> Response { get; set; } = _ => "{}";
    public string Url { get; }

    public FakeJsonServer()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        Url = $"http://127.0.0.1:{port}";
        _http.Prefixes.Add(Url + "/");
        _http.Start();
        _ = Task.Run(async () =>
        {
            var n = 0;
            while (_http.IsListening)
            {
                try
                {
                    var ctx = await _http.GetContextAsync();
                    using var sr = new StreamReader(ctx.Request.InputStream);
                    var body = await sr.ReadToEndAsync();
                    lock (Requests) Requests.Add(ctx.Request.HttpMethod + " " + ctx.Request.Url!.AbsolutePath + "\n" + body);
                    var bytes = Encoding.UTF8.GetBytes(Response(n++));
                    ctx.Response.ContentType = "application/json";
                    await ctx.Response.OutputStream.WriteAsync(bytes);
                    ctx.Response.Close();
                }
                catch { return; }
            }
        });
    }

    public void Dispose() => _http.Close();
}
