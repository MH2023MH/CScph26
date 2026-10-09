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
            ["text"] = EscapeMarkdown(AlertText.Body(alert)).Replace("\n", "<br>"),
        };
        using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        using var resp = await http.PostAsync(options.WebhookUrl, content, ct);
        resp.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// El campo "text" de Teams interpreta Markdown y HTML básico, y el cuerpo de la alerta lleva texto que controla el atacante
    /// (usuario, ruta, clave de grupo): sin escapar, podría insertar un enlace falso de "inicie sesión" en un aviso de seguridad.
    /// </summary>
    public static string EscapeMarkdown(string text)
    {
        var sb = new StringBuilder(text.Length + 16);
        foreach (var ch in text)
        {
            switch (ch)
            {
                case '<': sb.Append("&lt;"); break;
                case '>': sb.Append("&gt;"); break;
                case '&': sb.Append("&amp;"); break;
                case '\\': case '`': case '*': case '_': case '[': case ']': case '(': case ')': case '#': case '~': case '|': case '!':
                    sb.Append('\\').Append(ch); break;
                default: sb.Append(ch); break;
            }
        }
        return sb.ToString();
    }
}
