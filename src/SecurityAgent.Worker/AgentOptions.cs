using SecurityAgent.Collectors.EventLog;
using SecurityAgent.Collectors.Files;
using SecurityAgent.Core.State;
using SecurityAgent.Responders.Notifications;
using SecurityAgent.StatusApi;

namespace SecurityAgent.Worker;

public sealed class CollectorsOptions
{
    public EventLogCollectorOptions EventLog { get; set; } = new();
    public IisLogCollectorOptions Iis { get; set; } = new();
    public SqlErrorLogCollectorOptions Sql { get; set; } = new();
    public FileChangeCollectorOptions Files { get; set; } = new();

    public const string DefaultAppsRoot = @"D:\Apps";
}

/// <summary>Sección "SecurityAgent" de la configuración. Los secretos (SMTP, webhook, token) van en appsettings.Production.json, fuera de git.</summary>
public sealed class AgentOptions
{
    public string RulesDir { get; set; } = "rules";          // relativo al binario
    public StateStoreOptions Store { get; set; } = new();
    public SmtpOptions Smtp { get; set; } = new();
    public TeamsOptions Teams { get; set; } = new();
    public StatusApiOptions StatusApi { get; set; } = new();
    public CollectorsOptions Collectors { get; set; } = new();
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(5);
    public TimeSpan MaintenanceInterval { get; set; } = TimeSpan.FromMinutes(10);

    public string ResolveRulesDir() =>
        Path.IsPathRooted(RulesDir) ? RulesDir : Path.Combine(AppContext.BaseDirectory, RulesDir);
}
