using System.Diagnostics;
using System.Net;

namespace SecurityAgent.Responders;

/// <summary>
/// Bloqueo vía Windows Firewall (netsh advfirewall). Solo reglas propias con prefijo fijo,
/// nunca toca reglas de otras apps. Los argumentos se pasan por lista (sin shell) y la IP se valida estrictamente.
/// </summary>
public sealed class WindowsFirewall : IFirewall
{
    public const string RulePrefix = "CScph26-block-";

    public static string RuleName(string ip) => RulePrefix + ip;

    private static string Validate(string ip) =>
        IPAddress.TryParse(ip, out var a) ? a.ToString() : throw new ArgumentException($"IP inválida: '{ip}'", nameof(ip));

    public static string[] BuildAddArgs(string ip)
    {
        ip = Validate(ip);
        return new[] { "advfirewall", "firewall", "add", "rule", $"name={RuleName(ip)}", "dir=in", "action=block", $"remoteip={ip}", "enable=yes" };
    }

    public static string[] BuildDeleteArgs(string ip)
    {
        ip = Validate(ip);
        return new[] { "advfirewall", "firewall", "delete", "rule", $"name={RuleName(ip)}" };
    }

    public static string[] BuildShowArgs(string ip)
    {
        ip = Validate(ip);
        return new[] { "advfirewall", "firewall", "show", "rule", $"name={RuleName(ip)}" };
    }

    public void BlockIp(string ip, string ruleName)
    {
        var (code, output) = RunNetsh(BuildAddArgs(ip));
        if (code != 0) throw new InvalidOperationException($"netsh falló ({code}): {output.Trim()}");
    }

    /// <summary>Idempotente: si la regla no existe (ya retirada) no es un error.</summary>
    public void UnblockIp(string ip)
    {
        if (RunNetsh(BuildShowArgs(ip)).Code != 0) return;       // netsh devuelve 1 si no hay reglas con ese nombre
        var (code, output) = RunNetsh(BuildDeleteArgs(ip));
        if (code != 0) throw new InvalidOperationException($"netsh falló ({code}): {output.Trim()}");
    }

    private static (int Code, string Output) RunNetsh(string[] args)
    {
        var psi = new ProcessStartInfo("netsh") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("No se pudo iniciar netsh");
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(15_000)) { p.Kill(); throw new TimeoutException("netsh no respondió"); }
        return (p.ExitCode, stdout.Result + stderr.Result);
    }
}
