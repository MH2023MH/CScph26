using System.Globalization;
using System.Text;

namespace SecurityAdvisor.Safety;

/// <summary>
/// Limpia lo que se muestra al usuario. Un registro hostil puede hacer que el modelo repita secuencias de control
/// (ESC, cambios de título del terminal, retroceso) o marcas bidireccionales que disfrazan el texto en la consola.
/// Se conservan los saltos de línea y tabulaciones; se descarta el resto de caracteres de control y de formato.
/// </summary>
public static class OutputSanitizer
{
    public static string Clean(string? text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        var sb = new StringBuilder(text.Length);
        foreach (var rune in text.EnumerateRunes())
        {
            if (rune.Value is '\n' or '\t') { sb.Append((char)rune.Value); continue; }
            if (rune.Value == '\r') continue;
            var cat = Rune.GetUnicodeCategory(rune);
            if (cat is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate
                or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator or UnicodeCategory.PrivateUse) continue;
            sb.Append(rune.ToString());
        }
        return sb.ToString();
    }
}
