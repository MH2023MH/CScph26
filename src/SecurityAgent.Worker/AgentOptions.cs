using SecurityAgent.Collectors.Audits;
using SecurityAgent.Collectors.EventLog;
using SecurityAgent.Collectors.Files;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;
using SecurityAgent.Responders.LogShipping;
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

public sealed class IntegrityOptions
{
    public bool Enabled { get; set; } = true;
    public TimeSpan Interval { get; set; } = TimeSpan.FromMinutes(15);
    /// <summary>Clave HMAC con la que se firma el manifiesto (secreto: appsettings.Production.json). Vacía = manifiesto sin firma.</summary>
    public string HmacKey { get; set; } = "";
    public byte[]? KeyBytes => HmacKey == "" ? null : System.Text.Encoding.UTF8.GetBytes(HmacKey);
}

public sealed class LogShippingOptions
{
    /// <summary>Apagado hasta que se decida el destino (Fase 7, compuerta). Con Enabled=false el estado queda "disabled" y es visible en la API.</summary>
    public bool Enabled { get; set; } = false;
    public HttpLogSinkOptions Http { get; set; } = new();
    public FileLogSinkOptions File { get; set; } = new();
    public LogShipperOptions Shipper { get; set; } = new();
    public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(10);
    /// <summary>Fallos seguidos tras los cuales se emite una alerta de "envío de logs caído".</summary>
    public int AlertAfterFailures { get; set; } = 10;
}

public sealed class AuditsOptions
{
    public bool Enabled { get; set; } = true;
    public CertificateAuditOptions Certificates { get; set; } = new();
    public BackupAuditOptions Backups { get; set; } = new();
    public bool Hardening { get; set; } = true;
    /// <summary>Espera tras arrancar antes de la primera pasada.</summary>
    public TimeSpan StartDelay { get; set; } = TimeSpan.FromSeconds(30);
}

public sealed class ResourceLimitsOptions
{
    public bool Enabled { get; set; } = true;
    public bool LowPriority { get; set; } = true;
    /// <summary>Tope de memoria del proceso (MB). 0 = sin tope.</summary>
    public int MaxMemoryMb { get; set; } = 512;
    /// <summary>Tope de CPU (% del total de la máquina, tope duro). 0 = sin tope.</summary>
    public int MaxCpuPercent { get; set; } = 25;
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
    public IntegrityOptions Integrity { get; set; } = new();
    public LogShippingOptions LogShipping { get; set; } = new();
    public ResourceLimitsOptions Limits { get; set; } = new();
    public BlockLimits BlockLimits { get; set; } = new();
    public AuditsOptions Audits { get; set; } = new();
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(5);
    public TimeSpan MaintenanceInterval { get; set; } = TimeSpan.FromMinutes(10);

    public string ResolveRulesDir() =>
        Path.IsPathRooted(RulesDir) ? RulesDir : Path.Combine(AppContext.BaseDirectory, RulesDir);
}
