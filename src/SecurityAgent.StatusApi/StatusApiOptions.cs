using SecurityAgent.Core.Rules;

namespace SecurityAgent.StatusApi;

public sealed class StatusApiOptions
{
    public const int MinTokenLength = 32;

    /// <summary>Clientes permitidos si no se configura ninguno: el propio servidor y la red interna provisional.</summary>
    public static readonly string[] DefaultAllowedClients = { "127.0.0.1", "::1", "192.168.0.0/16" };

    /// <summary>Token Bearer (mínimo 32 caracteres, aleatorio). Si falta o es débil la API no arranca (falla cerrada); el monitor sigue.</summary>
    public string Token { get; set; } = "";

    /// <summary>Direcciones donde escucha Kestrel. Por defecto solo loopback; se ajusta a la IP interna del servidor.</summary>
    public string Listen { get; set; } = "http://127.0.0.1:8750";

    /// <summary>
    /// Clientes permitidos (CIDR/IP); cualquier otro recibe 403. Vacío = <see cref="DefaultAllowedClients"/>.
    /// Si se configura, REEMPLAZA los valores por defecto (el binder de configuración añade a las listas, por eso no vienen prellenados).
    /// </summary>
    public List<string> AllowedClients { get; set; } = new();

    public IReadOnlyList<string> EffectiveAllowedClients => AllowedClients.Count > 0 ? AllowedClients : DefaultAllowedClients;

    /// <summary>Devuelve el motivo por el que la API no debe arrancar, o null si la configuración es válida.</summary>
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Token)) return "falta el token (StatusApi:Token)";
        if (Token.Contains("CAMBIAR", StringComparison.OrdinalIgnoreCase)) return "el token es el valor de ejemplo; genere uno aleatorio";
        if (Token.Length < MinTokenLength) return $"el token es demasiado corto (mínimo {MinTokenLength} caracteres)";
        try { _ = new Allowlist(EffectiveAllowedClients); }
        catch (RuleValidationException e) { return $"StatusApi:AllowedClients inválido: {e.Message}"; }
        return null;
    }
}
