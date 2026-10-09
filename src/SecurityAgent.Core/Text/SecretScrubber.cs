using System.Text.RegularExpressions;
using SecurityAgent.Core.Events;

namespace SecurityAgent.Core.Text;

/// <summary>
/// Quita secretos evidentes (contraseñas, tokens, claves, credenciales en URL o en línea de comandos) del texto que se
/// PERSISTE y se expone (agent.db, API de estado, envío de logs, alertas). Las reglas se evalúan antes, sobre el evento
/// original, así que enmascarar aquí no esconde un ataque a la detección. Es una red de seguridad por patrones, no una garantía.
/// </summary>
public static partial class SecretScrubber
{
    public const string Mask = "***";

    // contraseñas: en una cadena de conexión pueden llevar espacios (Password=P@ss w0rd;), así que si más adelante hay un ';' el valor llega hasta él
    [GeneratedRegex(@"(?<k>[\w.\-]*(?:pass(?:word|wd|phrase)?|pwd)[\w.\-]*)(?<sep>[""']?\s*[=:]\s*)(?<v>""[^""]*""|'[^']*'|[^;&""']*(?=;)|[^\s&;,""']+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex PasswordRx();

    // clave=valor / clave: valor con otros nombres típicos de secreto (consultas de URL, JSON plano, cabeceras)
    [GeneratedRegex(@"(?<k>[\w.\-]*(?:secret|token|api[-_]?key|auth(?:orization)?|credential|signature|session[-_]?id|access[-_]?key|private[-_]?key|connection[-_]?string)[\w.\-]*)(?<sep>[""']?\s*[=:]\s*)(?!(?:bearer|basic)\s)(?<v>""[^""]*""|'[^']*'|[^\s&;,""']+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex KeyValueRx();

    // interruptores de línea de comandos: -p x, -Password x, /pwd:x, --token=x
    [GeneratedRegex(@"(?<f>(?:^|\s)(?:--?|/)(?:p|pw|pwd|pass|passwd|password|secret|token|apikey|api-key)(?:\s+|[:=]))(?<v>""[^""]*""|'[^']*'|\S+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex SwitchRx();

    // credenciales incrustadas en una URL: esquema://usuario:clave@host
    [GeneratedRegex(@"(?<p>[a-z][a-z0-9+.\-]*://[^\s/:@]+:)(?<v>[^\s/@]+)(?=@)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex UrlUserInfoRx();

    // Authorization: Bearer xxxxx / Basic xxxxx
    [GeneratedRegex(@"(?<p>\b(?:bearer|basic)\s+)(?<v>[A-Za-z0-9._~+/=\-]{8,})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex BearerRx();

    public static string? Scrub(string? text)
    {
        if (string.IsNullOrEmpty(text)) return text;
        try
        {
            text = UrlUserInfoRx().Replace(text, m => m.Groups["p"].Value + Mask);
            text = BearerRx().Replace(text, m => m.Groups["p"].Value + Mask);
            text = PasswordRx().Replace(text, m => m.Groups["k"].Value + m.Groups["sep"].Value + Mask);
            text = KeyValueRx().Replace(text, m => m.Groups["k"].Value + m.Groups["sep"].Value + Mask);
            text = SwitchRx().Replace(text, m => m.Groups["f"].Value + Mask);
            return text;
        }
        catch (RegexMatchTimeoutException)
        {
            return Mask + " (texto omitido: demasiado complejo para depurar)";   // ante la duda, no persistir el texto original
        }
    }

    /// <summary>Copia del evento apta para persistir y exponer. Actor e IP no se tocan: son los datos de atribución.</summary>
    public static SecurityEvent Scrub(SecurityEvent ev) => ev with { Target = Scrub(ev.Target), Detail = Scrub(ev.Detail) };
}
