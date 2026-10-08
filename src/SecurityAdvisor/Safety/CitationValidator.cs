using System.Text.RegularExpressions;

namespace SecurityAdvisor.Safety;

/// <summary>
/// Principio 13: toda afirmación cita un ID que existe en los datos consultados. Extrae de la respuesta los
/// identificadores con forma de ID (alertas, reglas, eventos, IP) y comprueba que figuren en la evidencia.
/// </summary>
public static partial class CitationValidator
{
    // ALR-<12 hex> | regla SEC-001, SEC-007-404, SELF-INTEGRITY, AUDIT-HARDENING | eventos sec-100001, sys-5001, def-…, sysmon-…, iis-…, sql-…, fs-… | IPv4
    [GeneratedRegex(@"\b(?:ALR-[0-9a-f]{12}|SEC-\d{3}(?:-[A-Z0-9]+)?|SELF-[A-Z]+|AUDIT-[A-Z]+|(?:sec|sys|def|sysmon)-\d+|iis-[\w]+-[\w]+-\d+|sql-\d{10,}-?\d*|fs-\d+-\d+|(?:\d{1,3}\.){3}\d{1,3})\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex IdRx();

    public static IReadOnlySet<string> ExtractIds(string? text) =>
        text is null ? new HashSet<string>() : IdRx().Matches(text).Select(m => m.Value).ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>IDs citados que no están en la evidencia ni en la pregunta del usuario (que son suyos y no inventados).</summary>
    public static IReadOnlyList<string> Unverified(string answer, IEnumerable<string> evidence, string userQuestion)
    {
        var allowed = new HashSet<string>(evidence, StringComparer.OrdinalIgnoreCase);
        allowed.UnionWith(ExtractIds(userQuestion));
        return ExtractIds(answer).Where(id => !allowed.Contains(id)).OrderBy(x => x, StringComparer.Ordinal).ToList();
    }
}
