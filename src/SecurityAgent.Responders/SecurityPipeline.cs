using SecurityAgent.Core.Alerts;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;
using SecurityAgent.Core.Text;
using SecurityAgent.Responders.Notifications;

namespace SecurityAgent.Responders;

/// <summary>Camino de un evento: persistir → evaluar reglas → alerta/acción según modo → notificar.</summary>
public sealed class SecurityPipeline(IStateStore store, RuleEngine engine, ResponseExecutor executor, NotificationDispatcher dispatcher)
{
    public async Task<IReadOnlyList<Alert>> ProcessAsync(SecurityEvent ev, CancellationToken ct = default)
    {
        // Se guarda una copia sin secretos (consultas de URL, líneas de comandos); las reglas ven el evento original.
        store.AddEvent(SecretScrubber.Scrub(ev));
        var alerts = new List<Alert>();
        foreach (var hit in engine.Process(ev))
        {
            var alert = executor.Handle(hit);
            alerts.Add(alert);
            if (hit.Rule.Notify.Count > 0)
                await dispatcher.DispatchAsync(alert, hit.Rule.Notify, ct);
        }
        return alerts;
    }
}
