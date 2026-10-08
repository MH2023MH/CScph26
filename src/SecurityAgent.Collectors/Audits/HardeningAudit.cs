using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Win32;
using SecurityAgent.Core.State;

namespace SecurityAgent.Collectors.Audits;

/// <param name="Passed">true = cumple, false = incumple, null = no se pudo determinar.</param>
public sealed record HardeningCheck(string Name, bool? Passed, string Detail);

public interface IHardeningProbe
{
    IReadOnlyList<HardeningCheck> Run();
}

/// <summary>
/// Controles mínimos de configuración que detectan regresiones entre evaluaciones CIS-CAT (no las sustituye).
/// Cada fallo es "warn" (no una emergencia); lo que no se puede determinar se informa pero no alerta.
/// </summary>
public sealed class HardeningAudit(IHardeningProbe probe, TimeSpan? interval = null) : IAudit
{
    public string Kind => AuditKinds.Hardening;
    public string AlertRuleId => "AUDIT-HARDENING";
    public TimeSpan Interval => interval ?? TimeSpan.FromHours(24);

    public Task<AuditOutcome> RunAsync(CancellationToken ct = default)
    {
        var checks = probe.Run();
        var failed = checks.Where(c => c.Passed == false).Select(c => $"{c.Name}: {c.Detail}").ToList();
        var unknown = checks.Count(c => c.Passed == null);
        var summary = failed.Count == 0
            ? $"{checks.Count(c => c.Passed == true)} control(es) cumplen; {unknown} sin determinar."
            : $"{failed.Count} control(es) incumplen: " + string.Join(" | ", failed);
        return Task.FromResult(new AuditOutcome(failed.Count == 0 ? AuditStatus.Ok : AuditStatus.Warn, summary, failed));
    }
}

/// <summary>Sondeo real en Windows (registro + auditpol). Escrito sin poder ejecutarse en Windows: validar en la Fase 8.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsHardeningProbe : IHardeningProbe
{
    public IReadOnlyList<HardeningCheck> Run()
    {
        var list = new List<HardeningCheck>();
        foreach (var profile in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
            list.Add(RegistryEquals($"Firewall de Windows activo ({profile})",
                $@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}", "EnableFirewall", 1));
        list.Add(RegistryEquals("RDP exige NLA", @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", 1));
        list.Add(RegistryEquals("SMBv1 deshabilitado (servidor)", @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 0, missingIsUnknown: true));
        list.Add(RegistryNotEquals("Defender no desactivado por directiva", @"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", 1));
        list.Add(AuditLogonFailures());
        return list;
    }

    private static HardeningCheck RegistryEquals(string name, string key, string value, int expected, bool missingIsUnknown = false)
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(key);
            var v = k?.GetValue(value);
            if (v is null) return new(name, missingIsUnknown ? null : false, $"valor {value} no definido");
            return new(name, Convert.ToInt32(v) == expected, $"{value}={v}, esperado {expected}");
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        { return new(name, null, "sin acceso al registro"); }
    }

    private static HardeningCheck RegistryNotEquals(string name, string key, string value, int forbidden)
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(key);
            var v = k?.GetValue(value);
            return v is null ? new(name, true, "sin directiva") : new(name, Convert.ToInt32(v) != forbidden, $"{value}={v}");
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        { return new(name, null, "sin acceso al registro"); }
    }

    /// <summary>Sin auditoría de fallos de inicio de sesión, SEC-001 queda ciego. Se consulta por GUID de subcategoría (independiente del idioma).</summary>
    private static HardeningCheck AuditLogonFailures()
    {
        const string name = "Auditoría de fallos de inicio de sesión (4625)";
        try
        {
            var psi = new ProcessStartInfo("auditpol.exe") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            foreach (var a in new[] { "/get", "/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}", "/r" }) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi);
            if (p is null || !p.WaitForExit(10_000)) return new(name, null, "auditpol no respondió");
            var text = p.StandardOutput.ReadToEnd();
            if (text.Contains("Failure", StringComparison.OrdinalIgnoreCase) || text.Contains("erróneo", StringComparison.OrdinalIgnoreCase))
                return new(name, true, "auditoría de fallos activa");
            if (text.Contains("No Auditing", StringComparison.OrdinalIgnoreCase) || text.Contains("Sin auditor", StringComparison.OrdinalIgnoreCase))
                return new(name, false, "sin auditoría de inicios de sesión");
            return new(name, null, "salida de auditpol no reconocida");
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        { return new(name, null, "no se pudo ejecutar auditpol"); }
    }
}
