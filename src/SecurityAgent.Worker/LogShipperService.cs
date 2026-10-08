using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;
using SecurityAgent.Responders.LogShipping;

namespace SecurityAgent.Worker;

/// <summary>Contenedor para poder registrar en DI un envío de logs opcional (null = sin destino).</summary>
public sealed record LogShipperHolder(LogShipper? Shipper);

public sealed class LogShipperService(LogShipperHolder holder, AgentOptions options, AgentHealth health, SystemAlertPublisher publisher,
    ILogger<LogShipperService> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        var shipper = holder.Shipper;
        if (shipper is null)
        {
            health.LogShipping = "disabled";
            log.LogWarning("Envío de logs al exterior DESHABILITADO (sin destino configurado): un atacante con acceso podría borrar su rastro local (principio 7).");
            return;
        }
        var alerted = false;
        while (!stop.IsCancellationRequested)
        {
            var delay = options.LogShipping.Interval;
            try
            {
                var n = await shipper.ShipOnceAsync(stop);
                if (shipper.ConsecutiveFailures == 0)
                {
                    health.LogShipping = "ok";
                    alerted = false;
                    if (n > 0) continue;                     // con backlog se sigue enviando sin esperar
                }
                else
                {
                    health.LogShipping = "failing";
                    delay = TimeSpan.FromSeconds(Math.Min(300, options.LogShipping.Interval.TotalSeconds * Math.Pow(2, Math.Min(shipper.ConsecutiveFailures, 5))));
                    if (!alerted && shipper.ConsecutiveFailures >= options.LogShipping.AlertAfterFailures)
                    {
                        alerted = true;
                        await publisher.PublishAsync("SELF-LOGSHIPPING", Severity.Alta,
                            $"El envío de logs al destino externo falla desde hace {shipper.ConsecutiveFailures} intentos.", stop);
                    }
                }
                await Task.Delay(delay, stop);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception e)
            {
                log.LogError(e, "Error en el envío de logs");
                try { await Task.Delay(delay, stop); } catch (OperationCanceledException) { break; }
            }
        }
    }
}

public sealed class IntegrityService(IntegrityMonitor monitor, AgentOptions options, ILogger<IntegrityService> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        if (!options.Integrity.Enabled) return;
        while (!stop.IsCancellationRequested)
        {
            try { await monitor.CheckOnceAsync(stop); }
            catch (OperationCanceledException) { break; }
            catch (Exception e) { log.LogError(e, "Error verificando la integridad"); }
            try { await Task.Delay(options.Integrity.Interval, stop); } catch (OperationCanceledException) { break; }
        }
    }
}
