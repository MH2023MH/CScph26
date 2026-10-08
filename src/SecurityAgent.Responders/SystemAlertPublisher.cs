using SecurityAgent.Core.Alerts;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.State;
using SecurityAgent.Responders.Notifications;

namespace SecurityAgent.Responders;

/// <summary>Alertas propias del agente (integridad, envío de logs caído...) que no salen del motor de reglas.</summary>
public sealed class SystemAlertPublisher(IStateStore store, NotificationDispatcher dispatcher, TimeProvider? time = null)
{
    private static readonly string[] DefaultChannels = { Channels.Email, Channels.Teams };
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    public async Task<Alert> PublishAsync(string ruleId, Severity severity, string message, CancellationToken ct = default)
    {
        var alert = new Alert("ALR-" + Guid.NewGuid().ToString("N")[..12], ruleId, _time.GetUtcNow(), severity, null, message,
            Array.Empty<string>(), RuleMode.Observe, "notificación");
        store.AddAlert(alert);
        await dispatcher.DispatchAsync(alert, DefaultChannels, ct);
        return alert;
    }
}
