using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Text;
using SecurityAdvisor.Api;
using SecurityAgent.StatusContract;

namespace SecurityAdvisor.Safety;

public sealed class RedactionOptions
{
    /// <summary>Enmascara el último octeto de las IP antes de que lleguen al modelo (útil si se usara una API externa).</summary>
    public bool MaskIps { get; set; } = false;
    /// <summary>Sustituye cuentas de usuario por un seudónimo estable.</summary>
    public bool PseudonymizeUsers { get; set; } = false;
}

/// <summary>
/// Filtra datos sensibles ANTES de entregarlos al modelo (decisión abierta de §10: qué datos no deben llegar al modelo).
/// Cubre los campos estructurados (IP, actor, clave de grupo) y también el texto libre (mensaje, motivo, detalle, objeto,
/// acción), donde la misma IP o cuenta suele repetirse. Límite conocido: en texto libre solo se seudonimizan las cuentas
/// que el propio registro declara (actor o clave de grupo); un nombre que aparezca solo dentro de un mensaje no se detecta.
/// </summary>
public sealed partial class Redactor(RedactionOptions options)
{
    public string? Ip(string? ip)
    {
        if (ip is null || !options.MaskIps) return ip;
        var parts = ip.Split('.');
        return parts.Length == 4 ? string.Join('.', parts[0], parts[1], parts[2], "x") : "ip-oculta";
    }

    public string? User(string? user)
    {
        if (user is null || !options.PseudonymizeUsers) return user;
        return "usuario-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(user)))[..6].ToLowerInvariant();
    }

    /// <summary>Texto libre: enmascara cualquier IP literal y reemplaza las cuentas conocidas del registro por su seudónimo.</summary>
    public string? Text(string? text, params string?[] knownUsers)
    {
        if (text is null || (!options.MaskIps && !options.PseudonymizeUsers)) return text;
        if (options.PseudonymizeUsers)
            foreach (var u in knownUsers.Where(u => !string.IsNullOrWhiteSpace(u)).Cast<string>().Distinct(StringComparer.OrdinalIgnoreCase).OrderByDescending(u => u.Length))
                text = text.Replace(u, User(u), StringComparison.OrdinalIgnoreCase);
        if (options.MaskIps)
        {
            text = Ipv6CandidateRx().Replace(text, m => MaskIpv6(m.Value));
            text = Ipv4Rx().Replace(text, m => Ip(m.Value)!);
        }
        return text;
    }

    public AlertDto Apply(AlertDto a)
    {
        var user = IsIp(a.GroupKey) ? null : a.GroupKey;
        return a with
        {
            GroupKey = IsIp(a.GroupKey) ? Ip(a.GroupKey) : User(a.GroupKey),
            Message = Text(a.Message, user)!,
            ActionTaken = Text(a.ActionTaken, user),
        };
    }

    public BlockDto Apply(BlockDto b) => b with { Ip = Ip(b.Ip)!, Reason = Text(b.Reason)! };

    public EventDto Apply(EventDto e) => e with
    {
        Actor = User(e.Actor), Ip = Ip(e.Ip),
        Target = Text(e.Target, e.Actor), Detail = Text(e.Detail, e.Actor),
    };

    public RuleDetailDto Apply(RuleDetailDto r) => r with { RecentAlerts = r.RecentAlerts.Select(Apply).ToList() };

    public EventDetailDto Apply(EventDetailDto d) => d with
    {
        Event = d.Event is { } e ? Apply(e) : null,
        Alert = d.Alert is { } a ? Apply(a) : null,
    };

    private string MaskIpv6(string candidate)
    {
        // El texto trae puntuación pegada ("2001:db8::1."): se prueba sin ella y se conserva.
        var core = candidate.TrimEnd('.', ':');
        var tail = candidate[core.Length..];
        return core.Contains(':') && System.Net.IPAddress.TryParse(core, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? "ip-oculta" + tail
            : candidate;
    }

    [GeneratedRegex(@"(?<![\w:.])[0-9A-Fa-f:.]{3,45}(?![\w:])", RegexOptions.CultureInvariant)]
    private static partial Regex Ipv6CandidateRx();

    [GeneratedRegex(@"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", RegexOptions.CultureInvariant)]
    private static partial Regex Ipv4Rx();

    private static bool IsIp(string? s) => s != null && System.Net.IPAddress.TryParse(s, out _);
}
