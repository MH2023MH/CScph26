using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecurityAgent.Core.Integrity;

/// <summary>Manifiesto de integridad (principio 8): SHA-256 de binarios, reglas y configuración, con firma HMAC opcional.</summary>
public sealed class IntegrityManifest
{
    public int Version { get; set; } = 1;
    public DateTimeOffset Created { get; set; }
    /// <summary>Ruta relativa (con '/') → SHA-256 en hexadecimal minúsculas.</summary>
    public SortedDictionary<string, string> Files { get; set; } = new(StringComparer.Ordinal);
    /// <summary>HMAC-SHA256 (hex) del contenido canónico; null si no se firmó.</summary>
    public string? Hmac { get; set; }

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    /// <summary>Patrones de archivos protegidos por defecto.</summary>
    public static readonly string[] DefaultPatterns = { "*.dll", "*.exe", "*.yaml", "*.json" };
    /// <summary>Carpetas que cambian legítimamente (datos y logs del propio agente) y por tanto no se protegen.</summary>
    public static readonly string[] DefaultExcludeDirs = { "data", "logs" };
    public const string FileName = "integrity.manifest.json";

    public static IEnumerable<string> EnumerateProtected(string root, IEnumerable<string>? patterns = null, IEnumerable<string>? excludeDirs = null)
    {
        var pats = (patterns ?? DefaultPatterns).ToArray();
        var excl = new HashSet<string>(excludeDirs ?? DefaultExcludeDirs, StringComparer.OrdinalIgnoreCase);
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            var rel = Relative(root, file);
            var segments = rel.Split('/');
            if (segments[..^1].Any(excl.Contains)) continue;
            if (rel.Equals(FileName, StringComparison.OrdinalIgnoreCase)) continue;
            if (pats.Any(p => FileNameMatches(p, segments[^1]))) yield return rel;
        }
    }

    public static IntegrityManifest Create(string root, byte[]? hmacKey = null, DateTimeOffset? now = null,
        IEnumerable<string>? patterns = null, IEnumerable<string>? excludeDirs = null)
    {
        var m = new IntegrityManifest { Created = now ?? DateTimeOffset.UtcNow };
        foreach (var rel in EnumerateProtected(root, patterns, excludeDirs))
            m.Files[rel] = HashFile(Path.Combine(root, rel.Replace('/', Path.DirectorySeparatorChar)));
        if (hmacKey is { Length: > 0 }) m.Hmac = ComputeHmac(m, hmacKey);
        return m;
    }

    public static string HashFile(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
    }

    public static string Canonical(IntegrityManifest m) =>
        string.Join('\n', m.Files.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => $"{kv.Key}:{kv.Value}"));   // orden explícito: el deserializador no conserva el comparador

    public static string ComputeHmac(IntegrityManifest m, byte[] key) =>
        Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(Canonical(m)))).ToLowerInvariant();

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static IntegrityManifest FromJson(string json) =>
        JsonSerializer.Deserialize<IntegrityManifest>(json, Json) ?? throw new InvalidDataException("Manifiesto vacío");

    /// <summary>Huella del archivo de manifiesto en sí; se envía fuera del servidor para detectar su reemplazo.</summary>
    public static string Sha256OfText(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    private static string Relative(string root, string file) =>
        Path.GetRelativePath(root, file).Replace('\\', '/').Replace(Path.DirectorySeparatorChar, '/');

    private static bool FileNameMatches(string pattern, string name)
    {
        if (!pattern.StartsWith('*')) return name.Equals(pattern, StringComparison.OrdinalIgnoreCase);
        return name.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase);
    }
}

public sealed record IntegrityReport(
    bool ManifestPresent,
    bool SignatureValid,
    IReadOnlyList<string> Modified,
    IReadOnlyList<string> Missing,
    IReadOnlyList<string> Unexpected,
    string? ManifestSha256)
{
    public bool Ok => ManifestPresent && SignatureValid && Modified.Count == 0 && Missing.Count == 0 && Unexpected.Count == 0;

    /// <summary>Resumen estable de las violaciones (para alertar solo cuando cambian).</summary>
    public string Fingerprint() => Ok ? "ok"
        : $"{(ManifestPresent ? "m" : "M")}{(SignatureValid ? "s" : "S")}|{string.Join(",", Modified)}|{string.Join(",", Missing)}|{string.Join(",", Unexpected)}";

    public string Describe()
    {
        if (!ManifestPresent) return "No existe el manifiesto de integridad.";
        var parts = new List<string>();
        if (!SignatureValid) parts.Add("la firma del manifiesto NO es válida");
        if (Modified.Count > 0) parts.Add("modificados: " + string.Join(", ", Modified.Take(10)));
        if (Missing.Count > 0) parts.Add("ausentes: " + string.Join(", ", Missing.Take(10)));
        if (Unexpected.Count > 0) parts.Add("no esperados: " + string.Join(", ", Unexpected.Take(10)));
        return parts.Count == 0 ? "íntegro" : string.Join("; ", parts);
    }
}

public static class IntegrityVerifier
{
    public static IntegrityReport Verify(string root, byte[]? hmacKey = null, string? manifestPath = null,
        IEnumerable<string>? patterns = null, IEnumerable<string>? excludeDirs = null)
    {
        manifestPath ??= Path.Combine(root, IntegrityManifest.FileName);
        if (!File.Exists(manifestPath))
            return new IntegrityReport(false, false, Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>(), null);

        var text = File.ReadAllText(manifestPath);
        IntegrityManifest manifest;
        try { manifest = IntegrityManifest.FromJson(text); }
        catch (Exception e) when (e is System.Text.Json.JsonException or InvalidDataException)
        {
            return new IntegrityReport(true, false, Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>(), IntegrityManifest.Sha256OfText(text));
        }

        // Con clave configurada la firma es obligatoria: un manifiesto sin firma o con firma distinta se rechaza.
        var signatureValid = hmacKey is not { Length: > 0 }
            || (manifest.Hmac is not null && CryptographicFixedEquals(manifest.Hmac, IntegrityManifest.ComputeHmac(manifest, hmacKey)));

        var modified = new List<string>();
        var missing = new List<string>();
        foreach (var (rel, expected) in manifest.Files)
        {
            var full = Path.Combine(root, rel.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(full)) { missing.Add(rel); continue; }
            if (!IntegrityManifest.HashFile(full).Equals(expected, StringComparison.OrdinalIgnoreCase)) modified.Add(rel);
        }
        var unexpected = IntegrityManifest.EnumerateProtected(root, patterns, excludeDirs)
            .Where(rel => !manifest.Files.ContainsKey(rel)).OrderBy(x => x, StringComparer.Ordinal).ToList();

        return new IntegrityReport(true, signatureValid, modified, missing, unexpected, IntegrityManifest.Sha256OfText(text));
    }

    private static bool CryptographicFixedEquals(string a, string b) =>
        System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(a.ToLowerInvariant()), System.Text.Encoding.UTF8.GetBytes(b.ToLowerInvariant()));
}
