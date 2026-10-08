namespace SecurityAgent.StatusApi;

public sealed class StatusApiOptions
{
    /// <summary>Token Bearer. Si está vacío la API se niega a arrancar (falla cerrada).</summary>
    public string Token { get; set; } = "";

    /// <summary>Direcciones donde escucha Kestrel. Por defecto solo loopback; se ajusta a la IP interna del servidor.</summary>
    public string Listen { get; set; } = "http://127.0.0.1:8750";

    /// <summary>Clientes permitidos (CIDR/IP). Cualquier otro recibe 403.</summary>
    public List<string> AllowedClients { get; set; } = new() { "127.0.0.1", "::1", "192.168.0.0/16" };
}
