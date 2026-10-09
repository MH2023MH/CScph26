using Microsoft.Extensions.Logging;
using SecurityAgent.Collectors;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;

namespace SecurityAgent.Worker;

/// <summary>Un ciclo de recolección: cada collector → pipeline → confirmar cursor. Un collector o evento defectuoso no detiene al resto.</summary>
public sealed class CollectorRunner(IEnumerable<ICollector> collectors, SecurityPipeline pipeline, IStateStore store, Heartbeat heartbeat, ILogger<CollectorRunner> log)
{
    private readonly IReadOnlyList<ICollector> _collectors = collectors.ToList();

    public int CollectorCount => _collectors.Count;

    /// <summary>Devuelve el número de eventos procesados.</summary>
    public async Task<int> RunOnceAsync(CancellationToken ct = default)
    {
        var processed = 0;
        foreach (var collector in _collectors)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var batch = await collector.PollAsync(ct);
                var failed = false;
                // Una sola transacción por lote (eventos, alertas y cursor): ver IStateStore.BeginBatch. Se confirma al salir, aun con error.
                using (store.BeginBatch())
                {
                    foreach (var ev in batch.Events)
                    {
                        try { await pipeline.ProcessAsync(ev, ct); processed++; }
                        catch (OperationCanceledException) { throw; }
                        catch (Exception e) { failed = true; log.LogError(e, "Fallo procesando evento {Id} de {Collector}", ev.Id, collector.Name); }
                        // Un lote grande puede tardar segundos: el latido se sigue dando mientras se procesa, no solo al final del ciclo.
                        if (processed % 200 == 0) heartbeat.Beat();
                    }
                    // Si algún evento falló NO se confirma el cursor: se reintenta en el próximo ciclo (entrega al menos una vez).
                    if (!failed) batch.Commit();
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception e) { log.LogError(e, "Fallo del collector {Collector}", collector.Name); }
        }
        heartbeat.Beat();
        return processed;
    }
}
