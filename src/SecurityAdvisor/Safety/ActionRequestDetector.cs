using System.Text.RegularExpressions;

namespace SecurityAdvisor.Safety;

/// <summary>Detecta órdenes de acción ("bloquea esa IP", "puedes desactivar la regla") que este asistente nunca ejecuta.</summary>
public static partial class ActionRequestDetector
{
    [GeneratedRegex(@"^\W*(?:(?:por favor|porfa|oye|hola|ahora|entonces)[\s,]+)*(?:(?:puedes|podr[ií]as|quiero que|necesito que|te pido que|haz que|ordena|manda)\s+(?:por favor\s+)?)?(?:bloque[aeo]r?|desbloque[aeo]r?|ban[eé]a|elimina[r]?|borra[r]?|ejecuta[r]?|corre|apaga[r]?|reinicia[r]?|desactiva[r]?|activa[r]?|habilita[r]?|deshabilita[r]?|cambia[r]?|modifica[r]?|crea[r]?|agrega[r]?|a[ñn]ade|quita[r]?|detén|det[eé]n|inicia[r]?|instala[r]?|desinstala[r]?|pasa[r]?\b.*\b(?:enforce|observe)|pon(?:er)?)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ActionRx();

    public static bool IsActionRequest(string question) => ActionRx().IsMatch(question);
}
