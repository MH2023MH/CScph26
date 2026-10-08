using System.Security.Cryptography;

namespace SecurityAdvisor.Safety;

/// <summary>
/// Entrega al modelo los resultados de las herramientas como DATOS delimitados (principio 12). El delimitador lleva un
/// código aleatorio por llamada que el contenido hostil no puede conocer, y cualquier aparición de la palabra reservada
/// dentro de los datos se neutraliza para que no pueda "cerrar" el bloque.
/// </summary>
public static class EvidenceBox
{
    private const string Marker = "DATOS_EXTERNOS";

    public static string Wrap(string toolName, string json)
    {
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant();
        var safe = json.Replace(Marker, "DATOS_EXTERNOS(escapado)", StringComparison.OrdinalIgnoreCase)
                       .Replace("<<", "‹‹").Replace(">>", "››");
        return $"<<{Marker} herramienta=\"{toolName}\" codigo=\"{nonce}\">>\n{safe}\n<<FIN_{Marker} codigo=\"{nonce}\">>";
    }
}
