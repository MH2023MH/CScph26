using System.Security.Cryptography;
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

/// <summary>Filtra datos sensibles ANTES de entregarlos al modelo (decisión abierta de §10: qué datos no deben llegar al modelo).</summary>
public sealed class Redactor(RedactionOptions options)
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

    public AlertDto Apply(AlertDto a) => a with { GroupKey = IsIp(a.GroupKey) ? Ip(a.GroupKey) : User(a.GroupKey) };
    public BlockDto Apply(BlockDto b) => b with { Ip = Ip(b.Ip)! };
    public EventDto Apply(EventDto e) => e with { Actor = User(e.Actor), Ip = Ip(e.Ip) };

    private static bool IsIp(string? s) => s != null && System.Net.IPAddress.TryParse(s, out _);
}
