using SecurityAgent.Core.Alerts;

namespace SecurityAgent.Responders.Notifications;

public static class Channels
{
    public const string Email = "correo";
    public const string Teams = "teams";
}

public interface IAlertNotifier
{
    /// <summary>Nombre del canal: "correo" | "teams".</summary>
    string Channel { get; }
    Task SendAsync(Alert alert, CancellationToken ct = default);
}
