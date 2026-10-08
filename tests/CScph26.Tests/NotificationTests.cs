using SecurityAgent.Core.Alerts;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.State;
using SecurityAgent.Responders.Notifications;

namespace CScph26.Tests;

public class NotificationTests
{
    private static Alert SampleAlert(string group = "203.0.113.50") => new("ALR-0123456789ab", "SEC-001",
        DateTimeOffset.Parse("2026-10-08T03:10:15Z"), Severity.Alta, group, $"SEC-001 brute force for '{group}'",
        new[] { "SIM-4625-001" }, RuleMode.Observe, "observe only");

    private static string DecodeBody(string raw)
    {
        var split = raw.IndexOf("\n\n", StringComparison.Ordinal);
        var headers = raw[..split];
        var body = raw[(split + 2)..].Trim();
        return headers.Contains("base64", StringComparison.OrdinalIgnoreCase)
            ? System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(string.Concat(body.Split('\n').Select(l => l.Trim()))))
            : body;
    }

    [Fact]
    public async Task Smtp_sends_alert_to_simulated_server()
    {
        using var smtp = new FakeSmtpServer();
        var notifier = new SmtpNotifier(new SmtpOptions { Host = "127.0.0.1", Port = smtp.Port, UseSsl = false, From = "agent@test.local", To = { "ops@test.local" } });
        await notifier.SendAsync(SampleAlert());
        var raw = Assert.Single(smtp.Messages);
        Assert.Contains("ops@test.local", raw);
        Assert.Contains("SEC-001", raw);                          // asunto
        Assert.Contains("ALR-0123456789ab", DecodeBody(raw));     // cuerpo (puede venir en base64)
    }

    [Fact]
    public async Task Teams_posts_json_to_simulated_webhook()
    {
        using var hook = new FakeWebhook();
        var notifier = new TeamsWebhookNotifier(new HttpClient(), new TeamsOptions { WebhookUrl = hook.Url });
        await notifier.SendAsync(SampleAlert());
        var body = Assert.Single(hook.Bodies);
        Assert.Contains("MessageCard", body);
        Assert.Contains("SEC-001", body);
    }

    [Fact]
    public async Task Dispatcher_falls_back_to_email_when_teams_fails()
    {
        using var smtp = new FakeSmtpServer();
        using var hook = new FakeWebhook { StatusToReturn = 500 };
        var d = new NotificationDispatcher(new IAlertNotifier[]
        {
            new SmtpNotifier(new SmtpOptions { Host = "127.0.0.1", Port = smtp.Port, UseSsl = false, From = "a@t.local", To = { "o@t.local" } }),
            new TeamsWebhookNotifier(new HttpClient(), new TeamsOptions { WebhookUrl = hook.Url }),
        });

        var results = await d.DispatchAsync(SampleAlert(), new[] { Channels.Teams });

        Assert.Contains(results, r => r.Channel == Channels.Teams && !r.Sent);
        Assert.Contains(results, r => r.Channel == Channels.Email && r.Sent);
        Assert.Single(smtp.Messages);
    }

    [Fact]
    public async Task Dispatcher_sends_both_channels_when_both_work()
    {
        using var smtp = new FakeSmtpServer();
        using var hook = new FakeWebhook();
        var d = new NotificationDispatcher(new IAlertNotifier[]
        {
            new SmtpNotifier(new SmtpOptions { Host = "127.0.0.1", Port = smtp.Port, UseSsl = false, From = "a@t.local", To = { "o@t.local" } }),
            new TeamsWebhookNotifier(new HttpClient(), new TeamsOptions { WebhookUrl = hook.Url }),
        });
        var results = await d.DispatchAsync(SampleAlert(), new[] { Channels.Email, Channels.Teams });
        Assert.All(results, r => Assert.True(r.Sent));
        Assert.Equal(2, results.Count);
        Assert.Single(smtp.Messages);
        Assert.Single(hook.Bodies);
    }

    [Fact]
    public async Task Dispatcher_never_throws_and_reports_unconfigured_channels()
    {
        var d = new NotificationDispatcher(Array.Empty<IAlertNotifier>());
        var results = await d.DispatchAsync(SampleAlert(), new[] { Channels.Teams });
        Assert.All(results, r => Assert.False(r.Sent));
    }

    [Fact]
    public void Notification_text_strips_hostile_control_characters()
    {
        var body = AlertText.Body(SampleAlert("evil\r\nBcc: attacker@x.com‮"));
        Assert.DoesNotContain("\r", body);
        Assert.False(body.Contains('\u202E'));   // Contains(char): la comparación por cultura ignora los caracteres invisibles
        Assert.DoesNotContain("\nBcc:", body);
    }
}
