using System.Net;
using System.Net.Mail;
using SecurityAgent.Core.Alerts;

namespace SecurityAgent.Responders.Notifications;

public sealed class SmtpOptions
{
    public string Host { get; set; } = "";
    public int Port { get; set; } = 587;
    public bool UseSsl { get; set; } = true;
    public string? User { get; set; }
    /// <summary>Secreto: va en appsettings.Production.json (gitignored), nunca en git (principio 9).</summary>
    public string? Password { get; set; }
    public string From { get; set; } = "";
    public List<string> To { get; set; } = new();
}

public sealed class SmtpNotifier(SmtpOptions options) : IAlertNotifier
{
    public string Channel => Channels.Email;

    public async Task SendAsync(Alert alert, CancellationToken ct = default)
    {
        if (options.Host == "" || options.To.Count == 0) throw new InvalidOperationException("SMTP sin configurar (host/destinatarios)");
        using var client = new SmtpClient(options.Host, options.Port) { EnableSsl = options.UseSsl, Timeout = 15_000 };
        if (!string.IsNullOrEmpty(options.User)) client.Credentials = new NetworkCredential(options.User, options.Password);
        using var msg = new MailMessage { From = new MailAddress(options.From), Subject = AlertText.Subject(alert), Body = AlertText.Body(alert) };
        foreach (var to in options.To) msg.To.Add(to);
        await client.SendMailAsync(msg, ct);
    }
}
