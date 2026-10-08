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
        if (string.IsNullOrWhiteSpace(options.Token))
            throw new InvalidOperationException("StatusApi: falta el token; la API no arranca sin autenticación.");
        var clients = new Allowlist(options.AllowedClients);
        var tokenBytes = Encoding.UTF8.GetBytes(options.Token);
        var log = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("StatusApi.Access");

        app.Use(async (ctx, next) =>
        {
            var remote = ctx.Connection.RemoteIpAddress;
            if (!clients.Matches(remote))
            {
                log.LogWarning("DENEGADO cliente {Remote} {Method} {Path}", remote, ctx.Request.Method, ctx.Request.Path.Value);
                await Write(ctx, StatusCodes.Status403Forbidden, new ErrorDto("cliente no permitido"));
                return;
            }
            var header = ctx.Request.Headers.Authorization.ToString();
            var presented = header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header[7..].Trim() : "";
            if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(presented), tokenBytes))
            {
                log.LogWarning("TOKEN inválido de {Remote} {Method} {Path}", remote, ctx.Request.Method, ctx.Request.Path.Value);
                await Write(ctx, StatusCodes.Status401Unauthorized, new ErrorDto("no autorizado"));
                return;
            }
            await next();
            log.LogInformation("{Remote} {Method} {Path} -> {Status}", remote, ctx.Request.Method, ctx.Request.Path.Value, ctx.Response.StatusCode);
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

    private static Task Write<T>(HttpContext ctx, int status, T body)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        return ctx.Response.WriteAsync(JsonSerializer.Serialize(body, StatusJson.Options));
    }
}
