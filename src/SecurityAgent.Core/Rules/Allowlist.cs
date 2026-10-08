using System.Net;
using System.Net.Sockets;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace SecurityAgent.Core.Rules;

/// <summary>Lista blanca (principio 2): direcciones que jamás se bloquean. Acepta IPs sueltas y CIDR.</summary>
public sealed class Allowlist
{
    private readonly List<(byte[] Net, int Prefix)> _ranges = new();

    public Allowlist(IEnumerable<string> entries)
    {
        foreach (var raw in entries)
        {
            var e = raw.Trim();
            var parts = e.Split('/', 2);
            if (!IPAddress.TryParse(parts[0], out var ip))
                throw new RuleValidationException($"Entrada inválida en la lista blanca: '{raw}'");
            var bits = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            var prefix = bits;
            if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > bits))
                throw new RuleValidationException($"Prefijo inválido en la lista blanca: '{raw}'");
            _ranges.Add((ip.GetAddressBytes(), prefix));
        }
    }

    public static Allowlist Empty => new(Array.Empty<string>());

    public static Allowlist LoadFile(string path)
    {
        var de = new DeserializerBuilder().WithNamingConvention(UnderscoredNamingConvention.Instance).Build();
        var groups = de.Deserialize<Dictionary<string, List<string>?>>(File.ReadAllText(path)) ?? new();
        return new Allowlist(groups.Values.Where(v => v != null).SelectMany(v => v!));
    }

    /// <summary>Pertenencia estricta (para control de acceso): solo true si la IP está en algún rango.</summary>
    public bool Matches(IPAddress? addr)
    {
        if (addr is null) return false;
        if (addr.IsIPv4MappedToIPv6) addr = addr.MapToIPv4();
        var bytes = addr.GetAddressBytes();
        foreach (var (net, prefix) in _ranges)
            if (net.Length == bytes.Length && Matches(net, bytes, prefix)) return true;
        return false;
    }

    /// <summary>true si la IP está protegida. Una IP ilegible se considera protegida (fallar hacia no bloquear).</summary>
    public bool IsAllowed(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip) || !IPAddress.TryParse(ip.Trim(), out var addr)) return true;
        if (addr.IsIPv4MappedToIPv6) addr = addr.MapToIPv4();
        var bytes = addr.GetAddressBytes();
        foreach (var (net, prefix) in _ranges)
        {
            if (net.Length != bytes.Length) continue;
            if (Matches(net, bytes, prefix)) return true;
        }
        return false;
    }

    private static bool Matches(byte[] net, byte[] ip, int prefix)
    {
        var full = prefix / 8;
        for (var i = 0; i < full; i++) if (net[i] != ip[i]) return false;
        var rem = prefix % 8;
        if (rem == 0) return true;
        var mask = (byte)(0xFF << (8 - rem));
        return (net[full] & mask) == (ip[full] & mask);
    }
}
