using Microsoft.Extensions.Logging;
using SecurityAgent.Core.Alerts;

namespace SecurityAgent.Responders.Notifications;

public sealed record DispatchResult(string Channel, bool Sent, string? Error);

/// <summary>
/// Envía una alerta por los canales pedidos por la regla. Un canal caído no impide los demás, y si algún canal
/// falla se intenta el correo (canal principal) aunque la regla no lo pidiera. Nunca lanza: devuelve el resultado.
/// </summary>
public sealed class NotificationDispatcher
{
    private readonly Dictionary<string, IAlertNotifier> _notifiers;
    private readonly ILogger? _log;

    public NotificationDispatcher(IEnumerable<IAlertNotifier> notifiers, ILogger? log = null)
    {
        _notifiers = notifiers.ToDictionary(n => n.Channel, StringComparer.Ordinal);
        _log = log;
    }

    public async Task<IReadOnlyList<DispatchResult>> DispatchAsync(Alert alert, IEnumerable<string> channels, CancellationToken ct = default)
    {
        var results = new List<DispatchResult>();
        foreach (var ch in channels.Distinct(StringComparer.Ordinal))
            results.Add(await TrySend(ch, alert, ct));

        if (results.Any(r => !r.Sent) && results.All(r => r.Channel != Channels.Email))
            results.Add(await TrySend(Channels.Email, alert, ct));
        return results;
    }

    private async Task<DispatchResult> TrySend(string channel, Alert alert, CancellationToken ct)
    {
        if (!_notifiers.TryGetValue(channel, out var n))
            return new DispatchResult(channel, false, "canal no configurado");
        try
        {
            await n.SendAsync(alert, ct);
            return new DispatchResult(channel, true, null);
        }
        catch (Exception e)
        {
            _log?.LogWarning(e, "Fallo al notificar {Alert} por {Channel}", alert.Id, channel);
            return new DispatchResult(channel, false, e.Message);
        }
    }
}
