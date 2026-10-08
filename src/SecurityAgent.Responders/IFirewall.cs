namespace SecurityAgent.Responders;

/// <summary>Abstracción del firewall local. Implementación real: <see cref="WindowsFirewall"/>.</summary>
public interface IFirewall
{
    void BlockIp(string ip, string ruleName);
    void UnblockIp(string ip);
}
