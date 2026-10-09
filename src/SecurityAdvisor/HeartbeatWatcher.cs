using SecurityAdvisor.Api;

namespace SecurityAdvisor;

public enum HeartbeatLevel { Ok, Stale, Unreachable, Unauthorized }

public sealed record HeartbeatStatus(HeartbeatLevel Level, double? AgeSeconds, IReadOnlyList<string> Warnings)
{
    public bool Healthy => Level == HeartbeatLevel.Ok && Warnings.Count == 0;
    public string Describe() => Level switch
    {
        HeartbeatLevel.Ok when Warnings.Count == 0 => "Sistema 1 reportando con normalidad.",
        HeartbeatLevel.Ok => "Sistema 1 reportando, pero: " + string.Join("; ", Warnings),
        HeartbeatLevel.Stale => $"ATENCIÓN: el sistema 1 lleva {AgeSeconds:0} s sin latir; podría haberse detenido.",
        HeartbeatLevel.Unauthorized => "No puedo vigilar al sistema 1: la API rechazó el token o el cliente.",
        _ => "ATENCIÓN: no consigo comunicarme con el sistema 1; podría estar caído o inalcanzable."
    };
}

/// <summary>
/// Verificación cruzada: el sistema 2 comprueba que el sistema 1 sigue latiendo. Es un aviso adicional, no el único:
/// el propio sistema 1 emite sus alertas críticas por su canal (la IA no es el vigilante principal).
/// </summary>
public sealed class HeartbeatWatcher(StatusApiClient api, double staleAfterSeconds = 120)
{
    public async Task<HeartbeatStatus> CheckAsync(CancellationToken ct = default)
    {
        var r = await api.GetStatusAsync(ct);
        if (!r.Ok)
            return new HeartbeatStatus(r.StatusCode is 401 or 403 ? HeartbeatLevel.Unauthorized : HeartbeatLevel.Unreachable, null, Array.Empty<string>());

        var s = r.Value!;
        var warnings = new List<string>();
        if (s.Integrity == "violated") warnings.Add("la integridad del agente está violada");
        if (s.LogShipping == "failing") warnings.Add("el envío de logs al exterior está fallando");
        if (s.LogShipping == "disabled") warnings.Add("el envío de logs al exterior está deshabilitado");
        foreach (var p in s.Problems ?? Array.Empty<string>()) warnings.Add("una fuente no se puede leer — " + p);
        if (s.HeartbeatAgeSeconds is null || s.HeartbeatAgeSeconds > staleAfterSeconds)
            return new HeartbeatStatus(HeartbeatLevel.Stale, s.HeartbeatAgeSeconds, warnings);
        return new HeartbeatStatus(HeartbeatLevel.Ok, s.HeartbeatAgeSeconds, warnings);
    }
}
