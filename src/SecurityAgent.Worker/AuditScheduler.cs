using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecurityAgent.Collectors.Audits;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;

namespace SecurityAgent.Worker;

/// <summary>Ejecuta una auditoría, guarda su resultado para la API de estado y alerta solo cuando el resultado empeora o cambia.</summary>
public sealed class AuditRunner(IStateStore store, SystemAlertPublisher publisher, TimeProvider time, ILogger<AuditRunner> log)
{
    private readonly Dictionary<string, string> _lastAlerted = new();

    public async Task<AuditOutcome> RunAsync(IAudit audit, CancellationToken ct = default)
    {
        AuditOutcome outcome;
        try { outcome = await audit.RunAsync(ct); }
        catch (OperationCanceledException) { throw; }
        catch (Exception e)
        {
            log.LogError(e, "Falló la auditoría {Kind}", audit.Kind);
            outcome = new AuditOutcome(AuditStatus.Error, $"La auditoría falló: {e.GetType().Name}", Array.Empty<string>());
        }

        store.SetAudit(new AuditEntry(audit.Kind, outcome.Status, time.GetUtcNow(), outcome.Summary));

        var bad = outcome.Status is AuditStatus.Warn or AuditStatus.Fail;
        if (bad && (!_lastAlerted.TryGetValue(audit.Kind, out var fp) || fp != outcome.Fingerprint))
        {
            _lastAlerted[audit.Kind] = outcome.Fingerprint;
            await publisher.PublishAsync(audit.AlertRuleId, outcome.Status == AuditStatus.Fail ? Severity.Alta : Severity.Media,
                $"Auditoría {audit.Kind}: {outcome.Summary}", ct);
        }
        else if (!bad)
        {
            _lastAlerted.Remove(audit.Kind);     // recuperado: si vuelve a fallar, se alerta de nuevo
        }
        return outcome;
    }
}

public sealed class AuditScheduler(IEnumerable<IAudit> audits, AuditRunner runner, AgentOptions options, TimeProvider time,
    ILogger<AuditScheduler> log) : BackgroundService
{
    private readonly IReadOnlyList<IAudit> _audits = audits.ToList();

    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        if (!options.Audits.Enabled || _audits.Count == 0) return;
        try { await Task.Delay(options.Audits.StartDelay, stop); } catch (OperationCanceledException) { return; }

        var next = _audits.ToDictionary(a => a.Kind, _ => time.GetUtcNow());
        while (!stop.IsCancellationRequested)
        {
            foreach (var a in _audits.Where(a => next[a.Kind] <= time.GetUtcNow()))
            {
                try { await runner.RunAsync(a, stop); }
                catch (OperationCanceledException) { return; }
                catch (Exception e) { log.LogError(e, "Error ejecutando la auditoría {Kind}", a.Kind); }
                next[a.Kind] = time.GetUtcNow() + a.Interval;
            }
            try { await Task.Delay(TimeSpan.FromSeconds(30), stop); } catch (OperationCanceledException) { return; }
        }
    }
}
