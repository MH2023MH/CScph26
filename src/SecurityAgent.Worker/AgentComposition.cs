using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SecurityAgent.Collectors;
using SecurityAgent.Collectors.Audits;
using SecurityAgent.Collectors.EventLog;
using SecurityAgent.Collectors.Files;
using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;
using SecurityAgent.Responders.LogShipping;
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
        s.AddSingleton(_ => DeployWindows.LoadFile(Path.Combine(o.ResolveRulesDir(), "deploy-windows.yaml")));
        s.AddSingleton(sp => new RuleEngine(sp.GetRequiredService<IReadOnlyList<Rule>>(), sp.GetRequiredService<Allowlist>(), sp.GetRequiredService<DeployWindows>()));

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
        s.AddSingleton(new AgentHealth());
        s.AddSingleton(sp => new SystemAlertPublisher(sp.GetRequiredService<IStateStore>(), sp.GetRequiredService<NotificationDispatcher>(),
            sp.GetRequiredService<TimeProvider>()));
        s.AddSingleton<IntegrityMonitor>();
        s.AddSingleton(sp => new LogShipperHolder(BuildShipper(sp, o)));

        if (OperatingSystem.IsWindows())
            s.TryAddSingleton<IEventRecordSource>(_ => OperatingSystem.IsWindows()
                ? new WindowsEventRecordSource()
                : throw new PlatformNotSupportedException());
        s.AddSingleton<IEnumerable<ICollector>>(sp => BuildCollectors(sp, o));

        s.AddSingleton(sp => new StatusService(sp.GetRequiredService<IStateStore>(), sp.GetRequiredService<IReadOnlyList<Rule>>(),
            sp.GetRequiredService<Heartbeat>(), sp.GetRequiredService<TimeProvider>(), null, sp.GetRequiredService<AgentHealth>()));
        s.TryAddSingleton<ICertificateSource>(_ => new X509StoreCertificateSource());
        s.AddSingleton<IEnumerable<IAudit>>(sp => BuildAudits(sp, o));
        s.AddSingleton<AuditRunner>();
        s.AddSingleton<CollectorRunner>();
        s.AddHostedService<CollectorService>();
        s.AddHostedService<MaintenanceService>();
        s.AddHostedService<IntegrityService>();
        s.AddHostedService<AuditScheduler>();
        s.AddHostedService<LogShipperService>();
        return s;
    }

    /// <summary>null = sin destino configurado (envío deshabilitado y visible como tal en la API de estado).</summary>
    private static LogShipper? BuildShipper(IServiceProvider sp, AgentOptions o)
    {
        var cfg = o.LogShipping;
        if (!cfg.Enabled) return null;
        ILogSink? sink = cfg.Http.Url != "" ? new HttpLogSink(sp.GetRequiredService<HttpClient>(), cfg.Http)
                       : cfg.File.Path != "" ? new FileLogSink(cfg.File, sp.GetRequiredService<TimeProvider>())
                       : null;
        if (sink is null) return null;
        var monitor = sp.GetRequiredService<IntegrityMonitor>();
        var health = sp.GetRequiredService<AgentHealth>();
        return new LogShipper(sp.GetRequiredService<IStateStore>(), sink, cfg.Shipper, sp.GetRequiredService<TimeProvider>(),
            sp.GetRequiredService<ILoggerFactory>().CreateLogger("LogShipper"),
            () => new Dictionary<string, string?>
            {
                ["version"] = typeof(AgentComposition).Assembly.GetName().Version?.ToString(),
                ["manifest_sha256"] = monitor.ManifestSha256,
                ["integrity"] = health.Integrity,
            });
    }

    private static List<IAudit> BuildAudits(IServiceProvider sp, AgentOptions o)
    {
        var time = sp.GetRequiredService<TimeProvider>();
        var list = new List<IAudit>
        {
            new CertificateAudit(sp.GetRequiredService<ICertificateSource>(), o.Audits.Certificates, time),
            new BackupAudit(o.Audits.Backups, time),
        };
        if (o.Audits.Hardening)
        {
            if (sp.GetService<IHardeningProbe>() is { } probe) list.Add(new HardeningAudit(probe));
            else if (OperatingSystem.IsWindows()) list.Add(new HardeningAudit(new WindowsHardeningProbe()));
        }
        return list;
    }

    private static List<ICollector> BuildCollectors(IServiceProvider sp, AgentOptions o)
    {
        var store = sp.GetRequiredService<IStateStore>();
        var lf = sp.GetRequiredService<ILoggerFactory>();
        var list = new List<ICollector>();
        var health = sp.GetRequiredService<AgentHealth>();

        if (sp.GetService<IEventRecordSource>() is { } source)
            list.Add(new EventLogCollector(source, store, o.Collectors.EventLog, lf.CreateLogger("EventLog"), health.Report));
        else
            lf.CreateLogger("Composition").LogWarning("Sin acceso al Event Log (solo Windows): collector de eventos deshabilitado");

        if (Directory.Exists(o.Collectors.Iis.Root))
            list.Add(new IisLogCollector(store, o.Collectors.Iis, lf.CreateLogger("Iis")));
        if (!string.IsNullOrEmpty(o.Collectors.Sql.Path))
            list.Add(new SqlErrorLogCollector(store, o.Collectors.Sql, log: lf.CreateLogger("Sql")));
        if (o.Collectors.Files.Roots.Count == 0) o.Collectors.Files.Roots.Add(CollectorsOptions.DefaultAppsRoot);
        list.Add(new FileChangeCollector(o.Collectors.Files, sp.GetRequiredService<TimeProvider>(), lf.CreateLogger("Files"), health.Report));
        return list;
    }
}
