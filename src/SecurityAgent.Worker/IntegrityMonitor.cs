using Microsoft.Extensions.Logging;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.Integrity;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;

namespace SecurityAgent.Worker;

/// <summary>Verifica la integridad de binarios, reglas y configuración (principio 8) y alerta solo cuando el resultado cambia.</summary>
public sealed class IntegrityMonitor(AgentOptions options, SystemAlertPublisher publisher, AgentHealth health, ILogger<IntegrityMonitor> log)
{
    private string? _lastFingerprint;
    public string? ManifestSha256 { get; private set; }
    public string Root { get; init; } = AppContext.BaseDirectory;

    public async Task<IntegrityReport> CheckOnceAsync(CancellationToken ct = default)
    {
        var report = IntegrityVerifier.Verify(Root, options.Integrity.KeyBytes);
        ManifestSha256 = report.ManifestSha256;
        health.Integrity = report.Ok ? "ok" : "violated";

        var fp = report.Fingerprint();
        if (fp != _lastFingerprint)
        {
            var first = _lastFingerprint is null;
            _lastFingerprint = fp;
            if (!report.Ok)
            {
                log.LogError("INTEGRIDAD: {Detail}", report.Describe());
                await publisher.PublishAsync("SELF-INTEGRITY", Severity.Critica, "Integridad del agente comprometida: " + report.Describe(), ct);
            }
            else if (!first)
            {
                await publisher.PublishAsync("SELF-INTEGRITY", Severity.Info, "Integridad del agente restaurada.", ct);
            }
        }
        return report;
    }
}
