using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;

namespace SecurityAgent.Worker;

public sealed class CollectorService(CollectorRunner runner, AgentOptions options, ILogger<CollectorService> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        log.LogInformation("SecurityAgent iniciado con {Count} collector(es)", runner.CollectorCount);
        while (!stop.IsCancellationRequested)
        {
            try
            {
                // Con backlog se vuelve a leer enseguida; sin eventos se espera el intervalo.
                var n = await runner.RunOnceAsync(stop);
                if (n == 0) await Task.Delay(options.PollInterval, stop);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception e)
            {
                log.LogError(e, "Error en el ciclo de recolección");
                try { await Task.Delay(options.PollInterval, stop); } catch (OperationCanceledException) { break; }
            }
        }
    }
}

/// <summary>Mantenimiento periódico: retira bloqueos vencidos del firewall y purga la base (retención y tamaño acotados).</summary>
public sealed class MaintenanceService(IStateStore store, ResponseExecutor executor, AgentOptions options, ILogger<MaintenanceService> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        while (!stop.IsCancellationRequested)
        {
            try
            {
                var swept = executor.SweepExpired();
                var purged = store.Purge();
                if (swept > 0 || purged.EventsDeleted > 0)
                    log.LogInformation("Mantenimiento: {Swept} bloqueo(s) retirados, {Events} evento(s) purgados", swept, purged.EventsDeleted);
            }
            catch (Exception e) { log.LogError(e, "Error en el mantenimiento"); }
            try { await Task.Delay(options.MaintenanceInterval, stop); } catch (OperationCanceledException) { break; }
        }
    }
}
