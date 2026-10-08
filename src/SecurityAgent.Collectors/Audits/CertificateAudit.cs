using System.Security.Cryptography.X509Certificates;
using SecurityAgent.Core.State;

namespace SecurityAgent.Collectors.Audits;

public sealed record CertInfo(string Subject, string Thumbprint, DateTimeOffset NotAfter, bool HasPrivateKey, string Store);

public interface ICertificateSource
{
    IReadOnlyList<CertInfo> List();
}

/// <summary>Lee los almacenes de certificados del equipo (LocalMachine\My y WebHosting, donde IIS toma sus certificados).</summary>
public sealed class X509StoreCertificateSource(IEnumerable<string>? stores = null) : ICertificateSource
{
    private readonly string[] _stores = (stores ?? new[] { "My", "WebHosting" }).ToArray();

    public IReadOnlyList<CertInfo> List()
    {
        var list = new List<CertInfo>();
        foreach (var name in _stores)
        {
            try
            {
                using var store = new X509Store(name, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                foreach (var c in store.Certificates)
                    list.Add(new CertInfo(c.Subject, c.Thumbprint, new DateTimeOffset(c.NotAfter.ToUniversalTime(), TimeSpan.Zero), c.HasPrivateKey, name));
            }
            catch (Exception e) when (e is System.Security.Cryptography.CryptographicException or PlatformNotSupportedException or IOException)
            { /* almacén inexistente o inaccesible: se omite */ }
        }
        return list;
    }
}

public sealed class CertificateAuditOptions
{
    public int WarnDays { get; set; } = 30;
    public int FailDays { get; set; } = 7;
    /// <summary>Certificados vencidos hace más de estos días se consideran abandonados y se ignoran.</summary>
    public int IgnoreExpiredAfterDays { get; set; } = 30;
    public TimeSpan Interval { get; set; } = TimeSpan.FromHours(24);
}

public sealed class CertificateAudit(ICertificateSource source, CertificateAuditOptions options, TimeProvider? time = null) : IAudit
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    public string Kind => AuditKinds.Certificates;
    public string AlertRuleId => "SEC-009";
    public TimeSpan Interval => options.Interval;

    public Task<AuditOutcome> RunAsync(CancellationToken ct = default)
    {
        var now = _time.GetUtcNow();
        var findings = new List<string>();
        var worst = AuditStatus.Ok;
        var considered = 0;
        foreach (var c in source.List().Where(c => c.HasPrivateKey))        // certificados de servidor: los que tienen clave privada
        {
            var days = (c.NotAfter - now).TotalDays;
            if (days < -options.IgnoreExpiredAfterDays) continue;
            considered++;
            if (days < 0) { findings.Add($"VENCIDO: {c.Subject} ({c.Thumbprint}, almacén {c.Store}) venció el {c.NotAfter:yyyy-MM-dd}"); worst = AuditStatus.Fail; }
            else if (days < options.FailDays) { findings.Add($"vence en {days:0} día(s): {c.Subject} ({c.Thumbprint})"); worst = AuditStatus.Fail; }
            else if (days < options.WarnDays) { findings.Add($"vence en {days:0} día(s): {c.Subject} ({c.Thumbprint})"); if (worst == AuditStatus.Ok) worst = AuditStatus.Warn; }
        }
        var summary = findings.Count == 0 ? $"{considered} certificado(s) de servidor revisados; ninguno vence en menos de {options.WarnDays} días."
                                          : string.Join(" | ", findings);
        return Task.FromResult(new AuditOutcome(worst, summary, findings));
    }
}
