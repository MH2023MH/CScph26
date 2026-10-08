using System.Globalization;
using System.Net;
using System.Text;

namespace SecurityAgent.Core.Text;

/// <summary>
/// Limpieza de texto de origen externo (principio 12). Quita caracteres de control, saltos de línea y
/// caracteres invisibles/bidireccionales, colapsa espacios y acota la longitud. No sustituye al delimitado
/// de datos que hace el sistema 2: reduce la superficie, no la elimina.
/// </summary>
public static class Sanitizer
{
    public const int DefaultMax = 200;

    public static string? Clean(string? text, int max = DefaultMax)
    {
        if (text is null) return null;
        var sb = new StringBuilder(Math.Min(text.Length, max + 1));
        var lastSpace = true;
        foreach (var rune in text.EnumerateRunes())
        {
            var cat = Rune.GetUnicodeCategory(rune);
            var isSpace = rune.Value is ' ' or '\t' or '\r' or '\n' || cat == UnicodeCategory.SpaceSeparator;
            if (isSpace) { if (!lastSpace) sb.Append(' '); lastSpace = true; continue; }
            if (cat is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate
                or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned
                or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator) continue;
            sb.Append(rune.ToString());
            lastSpace = false;
            if (sb.Length > max) break;
        }
        var s = sb.ToString().TrimEnd();
        return s.Length > max ? s[..max] + "…" : s;
    }

    /// <summary>Devuelve la IP normalizada o null si no es una IP válida (nunca texto libre).</summary>
    public static string? CleanIp(string? ip) =>
        ip != null && IPAddress.TryParse(ip.Trim(), out var a) ? a.ToString() : null;
}
