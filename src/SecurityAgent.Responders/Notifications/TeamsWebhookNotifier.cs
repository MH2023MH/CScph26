using System.Text;
using System.Text.Json;
using SecurityAgent.Core.Alerts;

namespace SecurityAgent.Responders.Notifications;

public sealed class TeamsOptions
{
    /// <summary>Secreto (la URL del webhook equivale a una credencial): appsettings.Production.json, gitignored.</summary>
    public string WebhookUrl { get; set; } = "";
}

public sealed class TeamsWebhookNotifier(HttpClient http, TeamsOptions options) : IAlertNotifier
{
    public string Channel => Channels.Teams;

    public async Task SendAsync(Alert alert, CancellationToken ct = default)
    {
        if (options.WebhookUrl == "") throw new InvalidOperationException("Webhook de Teams sin configurar");
        var payload = new Dictionary<string, object>
        {
            ["@type"] = "MessageCard",
            ["@context"] = "https://schema.org/extensions",
            ["summary"] = AlertText.Subject(alert),
            ["title"] = AlertText.Subject(alert),
            ["text"] = AlertText.Body(alert).Replace("\n", "<br>"),
        };
        using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        using var resp = await http.PostAsync(options.WebhookUrl, content, ct);
        resp.EnsureSuccessStatusCode();
    }
}
