using System.Net;
using System.Net.NetworkInformation;

namespace SecurityAgent.Core.Rules;

/// <summary>
/// Direcciones que pertenecen al propio servidor o a la infraestructura de la que depende (puerta de enlace, DNS, DHCP).
/// Bloquear cualquiera de ellas aislaría al servidor, así que el responder nunca lo hace (principio 2), y la IP de
/// origen de un par local es la única de la que se acepta la cabecera CF-Connecting-IP. La lista se lee del sistema
/// y se refresca cada pocos minutos (cambia con DHCP).
/// </summary>
public sealed class HostAddresses(Func<(IEnumerable<IPAddress> Own, IEnumerable<IPAddress> Infrastructure)>? source = null, TimeSpan? ttl = null)
{
    public static HostAddresses Shared { get; } = new();

    private readonly Func<(IEnumerable<IPAddress> Own, IEnumerable<IPAddress> Infrastructure)> _source = source ?? ReadFromSystem;
    private readonly long _ttlMs = (long)(ttl ?? TimeSpan.FromMinutes(5)).TotalMilliseconds;
    private readonly object _gate = new();
    private HashSet<string> _own = new();
    private HashSet<string> _infra = new();
    private long _loadedAt = long.MinValue;

    public bool IsOwn(IPAddress? a) { Refresh(); lock (_gate) return a != null && _own.Contains(Key(a)); }

    /// <summary>true si es una dirección del propio servidor, su puerta de enlace, un servidor DNS o DHCP.</summary>
    public bool IsProtected(IPAddress? a)
    {
        Refresh();
        lock (_gate) return a != null && (_own.Contains(Key(a)) || _infra.Contains(Key(a)));
    }

    private void Refresh()
    {
        lock (_gate)
        {
            var now = Environment.TickCount64;
            if (_loadedAt != long.MinValue && now - _loadedAt < _ttlMs) return;
            _loadedAt = now;
            try
            {
                var (own, infra) = _source();
                _own = own.Select(Key).ToHashSet();
                _infra = infra.Select(Key).ToHashSet();
            }
            catch (Exception e) when (e is NetworkInformationException or PlatformNotSupportedException or InvalidOperationException)
            {
                // Sin lectura de red se conserva lo último conocido; nunca se interrumpe la detección.
            }
        }
    }

    /// <summary>Clave canónica: IPv4 asignada a IPv6 se normaliza y se ignora el identificador de ámbito.</summary>
    private static string Key(IPAddress a)
    {
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        return Convert.ToHexString(a.GetAddressBytes());
    }

    private static (IEnumerable<IPAddress>, IEnumerable<IPAddress>) ReadFromSystem()
    {
        var own = new List<IPAddress>();
        var infra = new List<IPAddress>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            var props = nic.GetIPProperties();
            own.AddRange(props.UnicastAddresses.Select(u => u.Address));
            infra.AddRange(props.GatewayAddresses.Select(g => g.Address));
            infra.AddRange(props.DnsAddresses);
            infra.AddRange(props.DhcpServerAddresses);
        }
        return (own, infra);
    }
}
