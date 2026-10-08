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

    public void BlockIp(string ip, string ruleName) => RunNetsh(BuildAddArgs(ip));

    public void UnblockIp(string ip) => RunNetsh(BuildDeleteArgs(ip));

    private static void RunNetsh(string[] args)
    {
        var psi = new ProcessStartInfo("netsh") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("No se pudo iniciar netsh");
        p.WaitForExit(15_000);
        if (!p.HasExited) { p.Kill(); throw new TimeoutException("netsh no respondió"); }
        if (p.ExitCode != 0) throw new InvalidOperationException($"netsh falló ({p.ExitCode}): {p.StandardOutput.ReadToEnd()}");
    }
}
