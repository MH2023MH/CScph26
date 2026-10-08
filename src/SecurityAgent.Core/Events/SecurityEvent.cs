namespace SecurityAgent.Core.Events;

public enum Severity { Info = 0, Baja = 1, Media = 2, Alta = 3, Critica = 4 }

/// <summary>Modelo común de evento (§3): tiempo, fuente, tipo, actor, IP, objeto, severidad.</summary>
/// <param name="Id">Identificador estable; es el que cita el sistema 2 (principio 13).</param>
/// <param name="Source">Fuente: eventlog.security, iis, sql, fs, defender, ...</param>
/// <param name="Type">Tipo normalizado: p. ej. "4625", "7045", "http.request".</param>
/// <param name="Actor">Usuario o cuenta involucrada (texto externo: no confiable).</param>
/// <param name="Ip">IP de origen en texto, si existe.</param>
/// <param name="Target">Objeto afectado: archivo, servicio, App Pool, etc. (texto externo: no confiable).</param>
/// <param name="Detail">Dato adicional libre (método+estado+agente HTTP, ruta del ejecutable, etc.). Texto externo: no confiable.</param>
public sealed record SecurityEvent(
    string Id,
    DateTimeOffset Timestamp,
    string Source,
    string Type,
    Severity Severity,
    string? Actor = null,
    string? Ip = null,
    string? Target = null,
    string? Detail = null);
