using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SecurityAgent.Collectors;
using SecurityAgent.Collectors.EventLog;
using SecurityAgent.Collectors.Files;
using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;
using SecurityAgent.Responders.Notifications;
using SecurityAgent.StatusApi;

namespace SecurityAgent.Worker;

public static class AgentComposition
{
    public static AgentOptions BindOptions(IConfiguration config) =>
        config.GetSection("SecurityAgent").Get<AgentOptions>() ?? new AgentOptions();

    public static IServiceCollection AddSecurityAgent(this IServiceCollection s, IConfiguration config)
    {
        var o = BindOptions(config);
        s.AddSingleton(o);
        s.AddSingleton(TimeProvider.System);
        s.AddSingleton(new Heartbeat());

        s.AddSingleton<SqliteStateStore>(_ => new SqliteStateStore(o.Store));
        s.AddSingleton<IStateStore>(sp => sp.GetRequiredService<SqliteStateStore>());

        // Falla cerrada: reglas o lista blanca inválidas impiden arrancar (mejor no iniciar que iniciar sin protección ni exclusiones).
        s.AddSingleton(_ => Allowlist.LoadFile(Path.Combine(o.ResolveRulesDir(), "allowlist.yaml")));
        s.AddSingleton<IReadOnlyList<Rule>>(_ => RuleLoader.LoadDirectory(o.ResolveRulesDir()));
        s.AddSingleton(sp => new RuleEngine(sp.GetRequiredService<IReadOnlyList<Rule>>(), sp.GetRequiredService<Allowlist>()));

        s.TryAddSingleton<IFirewall, WindowsFirewall>();
        s.AddSingleton(sp => new ResponseExecutor(sp.GetRequiredService<IStateStore>(), sp.GetRequiredService<IFirewall>(),
            sp.GetRequiredService<Allowlist>(), sp.GetRequiredService<TimeProvider>()));

        s.AddSingleton<HttpClient>();
        s.AddSingleton<IEnumerable<IAlertNotifier>>(sp =>
        {
            var list = new List<IAlertNotifier>();
            if (o.Smtp.Host != "") list.Add(new SmtpNotifier(o.Smtp));
            if (o.Teams.WebhookUrl != "") list.Add(new TeamsWebhookNotifier(sp.GetRequiredService<HttpClient>(), o.Teams));
            return list;
        });
        s.AddSingleton(sp => new NotificationDispatcher(sp.GetRequiredService<IEnumerable<IAlertNotifier>>(),
            sp.GetRequiredService<ILoggerFactory>().CreateLogger("Notifications")));
        s.AddSingleton<SecurityPipeline>();

        if (OperatingSystem.IsWindows())
            s.TryAddSingleton<IEventRecordSource>(_ => OperatingSystem.IsWindows()
                ? new WindowsEventRecordSource()
                : throw new PlatformNotSupportedException());
        s.AddSingleton<IEnumerable<ICollector>>(sp => BuildCollectors(sp, o));

        s.AddSingleton(sp => new StatusService(sp.GetRequiredService<IStateStore>(), sp.GetRequiredService<IReadOnlyList<Rule>>(),
            sp.GetRequiredService<Heartbeat>(), sp.GetRequiredService<TimeProvider>()));
        s.AddSingleton<CollectorRunner>();
        s.AddHostedService<CollectorService>();
        s.AddHostedService<MaintenanceService>();
        return s;
    }

    private static List<ICollector> BuildCollectors(IServiceProvider sp, AgentOptions o)
    {
        var store = sp.GetRequiredService<IStateStore>();
        var lf = sp.GetRequiredService<ILoggerFactory>();
        var list = new List<ICollector>();

        if (sp.GetService<IEventRecordSource>() is { } source)
            list.Add(new EventLogCollector(source, store, o.Collectors.EventLog, lf.CreateLogger("EventLog")));
        else
            lf.CreateLogger("Composition").LogWarning("Sin acceso al Event Log (solo Windows): collector de eventos deshabilitado");

        if (Directory.Exists(o.Collectors.Iis.Root))
            list.Add(new IisLogCollector(store, o.Collectors.Iis, lf.CreateLogger("Iis")));
        if (!string.IsNullOrEmpty(o.Collectors.Sql.Path))
            list.Add(new SqlErrorLogCollector(store, o.Collectors.Sql, log: lf.CreateLogger("Sql")));
        if (o.Collectors.Files.Roots.Count == 0) o.Collectors.Files.Roots.Add(CollectorsOptions.DefaultAppsRoot);
        list.Add(new FileChangeCollector(o.Collectors.Files, sp.GetRequiredService<TimeProvider>(), lf.CreateLogger("Files")));
        return list;
    }
}
