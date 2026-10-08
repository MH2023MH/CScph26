using SecurityAgent.Core.State;

namespace SecurityAgent.Collectors.Audits;

public sealed class BackupTarget
{
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public string Pattern { get; set; } = "*";
    public int MaxAgeHours { get; set; } = 26;
    public long MinSizeBytes { get; set; } = 1;
}

public sealed class BackupAuditOptions
{
    /// <summary>Dónde deja sus archivos cada respaldo (decisión pendiente: se necesita saber cómo/dónde se respalda).</summary>
    public List<BackupTarget> Targets { get; set; } = new();
    public TimeSpan Interval { get; set; } = TimeSpan.FromHours(1);
}

/// <summary>Comprueba que cada respaldo configurado produjo un archivo reciente y no vacío.</summary>
public sealed class BackupAudit(BackupAuditOptions options, TimeProvider? time = null) : IAudit
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    public string Kind => AuditKinds.Backups;
    public string AlertRuleId => "SEC-009";
    public TimeSpan Interval => options.Interval;

    public Task<AuditOutcome> RunAsync(CancellationToken ct = default)
    {
        if (options.Targets.Count == 0)
            return Task.FromResult(new AuditOutcome(AuditStatus.NotConfigured, "No hay respaldos configurados para vigilar (Audits:Backups:Targets).", Array.Empty<string>()));

        var now = _time.GetUtcNow();
        var findings = new List<string>();
        foreach (var t in options.Targets)
        {
            if (!Directory.Exists(t.Path)) { findings.Add($"{t.Name}: la carpeta {t.Path} no existe o no es accesible"); continue; }
            FileInfo? newest;
            try
            {
                newest = new DirectoryInfo(t.Path).EnumerateFiles(t.Pattern, SearchOption.AllDirectories)
                    .OrderByDescending(f => f.LastWriteTimeUtc).FirstOrDefault();
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            { findings.Add($"{t.Name}: no se pudo leer {t.Path} ({e.GetType().Name})"); continue; }

            if (newest is null) { findings.Add($"{t.Name}: no hay archivos '{t.Pattern}' en {t.Path}"); continue; }
            var age = now - new DateTimeOffset(newest.LastWriteTimeUtc, TimeSpan.Zero);
            if (age > TimeSpan.FromHours(t.MaxAgeHours))
                findings.Add($"{t.Name}: el respaldo más reciente ({newest.Name}) tiene {age.TotalHours:0} h (máximo {t.MaxAgeHours} h)");
            else if (newest.Length < t.MinSizeBytes)
                findings.Add($"{t.Name}: el respaldo más reciente ({newest.Name}) está vacío o es demasiado pequeño ({newest.Length} bytes)");
        }
        return Task.FromResult(findings.Count == 0
            ? new AuditOutcome(AuditStatus.Ok, $"{options.Targets.Count} respaldo(s) al día.", findings)
            : new AuditOutcome(AuditStatus.Fail, string.Join(" | ", findings), findings));
    }
}
