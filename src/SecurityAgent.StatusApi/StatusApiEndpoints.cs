using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.Rules;
using SecurityAgent.StatusContract;

namespace SecurityAgent.StatusApi;

public static class StatusApiEndpoints
{
    /// <summary>
    /// Registra la API de estado. Solo se mapean GET: no existe ninguna ruta de escritura.
    /// Orden de controles: cliente permitido (403) → token (401) → ruta.
    /// </summary>
    public static void MapStatusApi(this WebApplication app, StatusService service, StatusApiOptions options)
    {
        if (options.Validate() is { } problem)
            throw new InvalidOperationException($"StatusApi: {problem}; la API no arranca sin autenticación válida.");
        var clients = new Allowlist(options.EffectiveAllowedClients);
        var tokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(options.Token));
        var denials = new DenialLogLimiter();
        var log = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("StatusApi.Access");

        app.Use(async (ctx, next) =>
        {
            var remote = ctx.Connection.RemoteIpAddress;
            if (!clients.Matches(remote))
            {
                if (denials.ShouldLog(out var suppressed))
                    log.LogWarning("DENEGADO cliente {Remote} {Method} {Path}{Suppressed}", remote, Safe(ctx.Request.Method, 10), Safe(ctx.Request.Path.Value, 120), suppressed);
                await Write(ctx, StatusCodes.Status403Forbidden, new ErrorDto("cliente no permitido"));
                return;
            }
            var header = ctx.Request.Headers.Authorization.ToString();
            var presented = header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header[7..].Trim() : "";
            // Se comparan los resúmenes: FixedTimeEquals devuelve de inmediato si las longitudes difieren y filtraría la del token.
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(presented)), tokenHash))
            {
                if (denials.ShouldLog(out var suppressed))
                    log.LogWarning("TOKEN inválido de {Remote} {Method} {Path}{Suppressed}", remote, Safe(ctx.Request.Method, 10), Safe(ctx.Request.Path.Value, 120), suppressed);
                await Write(ctx, StatusCodes.Status401Unauthorized, new ErrorDto("no autorizado"));
                return;
            }
            await next();
            log.LogInformation("{Remote} {Method} {Path} -> {Status}", remote, Safe(ctx.Request.Method, 10), Safe(ctx.Request.Path.Value, 120), ctx.Response.StatusCode);
        });

        app.MapGet(StatusRoutes.Status, (HttpContext c) => Write(c, 200, service.GetStatus()));

        app.MapGet(StatusRoutes.Alerts, (HttpContext c) =>
        {
            var q = c.Request.Query;
            DateTimeOffset? since = null;
            if (q.TryGetValue("since", out var s))
            {
                if (!DateTimeOffset.TryParse(s, null, System.Globalization.DateTimeStyles.AssumeUniversal, out var parsed))
                    return Write(c, 400, new ErrorDto("parámetro 'since' inválido (use ISO 8601)"));
                since = parsed;
            }
            Severity? sev = null;
            if (q.TryGetValue("severity", out var sv))
            {
                if (!Enum.TryParse<Severity>(sv, true, out var parsedSev))
                    return Write(c, 400, new ErrorDto("parámetro 'severity' inválido (info|baja|media|alta|critica)"));
                sev = parsedSev;
            }
            var limit = int.TryParse(q["limit"], out var l) ? l : 50;
            return Write(c, 200, service.ListAlerts(since, q["rule"].FirstOrDefault(), sev, q["ip"].FirstOrDefault(), limit));
        });

        app.MapGet(StatusRoutes.Blocks, (HttpContext c) => Write(c, 200, service.ListBlocks()));

        app.MapGet(StatusRoutes.Rule, (HttpContext c, string id) =>
            service.GetRule(id) is { } r ? Write(c, 200, r) : Write(c, 404, new ErrorDto("regla no encontrada")));

        app.MapGet(StatusRoutes.Audit, (HttpContext c) => Write(c, 200, service.GetAudit()));

        app.MapGet(StatusRoutes.Event, (HttpContext c, string id) =>
            service.GetEvent(id) is { } e ? Write(c, 200, e) : Write(c, 404, new ErrorDto("no hay información para ese ID")));
    }

    /// <summary>Método y ruta los elige quien llama (aun sin autenticarse): se limpian antes de escribirlos en el registro.</summary>
    private static string Safe(string? text, int max) => SecurityAgent.Core.Text.Sanitizer.Clean(text, max) ?? "";

    /// <summary>
    /// Limita el registro de accesos denegados (un cliente permitido sin token podría llenar el Event Log).
    /// Hasta 20 por minuto; el resto se cuenta y se informa en la siguiente entrada.
    /// </summary>
    private sealed class DenialLogLimiter
    {
        private const int PerMinute = 20;
        private readonly object _gate = new();
        private long _windowStart = Environment.TickCount64;
        private int _logged;
        private int _suppressed;

        public bool ShouldLog(out string suffix)
        {
            lock (_gate)
            {
                var now = Environment.TickCount64;
                if (now - _windowStart >= 60_000) { _windowStart = now; _logged = 0; }
                if (_logged >= PerMinute) { _suppressed++; suffix = ""; return false; }
                _logged++;
                suffix = _suppressed > 0 ? $" (+{_suppressed} denegaciones más omitidas)" : "";
                _suppressed = 0;
                return true;
            }
        }
    }

    private static Task Write<T>(HttpContext ctx, int status, T body)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        return ctx.Response.WriteAsync(JsonSerializer.Serialize(body, StatusJson.Options));
    }
}
