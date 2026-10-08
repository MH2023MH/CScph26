using System.Globalization;
using System.Text.RegularExpressions;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.State;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace SecurityAgent.Core.Rules;

public sealed class RuleValidationException(string message) : Exception(message);

public static class RuleLoader
{
    // ---- DTOs del YAML (§5) ----
    private sealed class RuleDto
    {
        public string? Id { get; set; }
        public string? Nombre { get; set; }
        public string? Modo { get; set; }
        public object? Fuente { get; set; }
        public CondicionDto? Condicion { get; set; }
        public string? Severidad { get; set; }
        public List<string>? Excluir { get; set; }
        public RespuestaDto? Respuesta { get; set; }
        public string? Runbook { get; set; }
    }

    private sealed class CondicionDto
    {
        public object? EventId { get; set; }
        public string? AgruparPor { get; set; }
        public int Umbral { get; set; }
        public string? Ventana { get; set; }
        public List<FiltroDto>? Filtros { get; set; }
        public List<FiltroDto>? Excepto { get; set; }
    }

    private sealed class FiltroDto
    {
        public string? Campo { get; set; }
        public List<string>? Contiene { get; set; }
        public string? Regex { get; set; }
        public string? Igual { get; set; }
    }

    private sealed class RespuestaDto
    {
        public string? Accion { get; set; }
        public string? Duracion { get; set; }
        public List<string>? Notificar { get; set; }
    }

    private static readonly IDeserializer Yaml = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .Build();   // estricto: una clave desconocida (typo) es error

    public static IReadOnlyList<Rule> LoadDirectory(string dir)
    {
        var rules = new List<Rule>();
        foreach (var file in Directory.GetFiles(dir, "*.yaml").OrderBy(f => f, StringComparer.Ordinal))
        {
            if (Path.GetFileName(file) is var fn && (fn.Equals("allowlist.yaml", StringComparison.OrdinalIgnoreCase) || fn.Equals("deploy-windows.yaml", StringComparison.OrdinalIgnoreCase))) continue;
            rules.Add(ParseYaml(File.ReadAllText(file), Path.GetFileName(file)));
        }
        var dup = rules.GroupBy(r => r.Id).FirstOrDefault(g => g.Count() > 1);
        if (dup != null) throw new RuleValidationException($"ID de regla duplicado: {dup.Key}");
        return rules;
    }

    public static Rule ParseYaml(string yaml, string origin = "<memoria>")
    {
        RuleDto dto;
        try { dto = Yaml.Deserialize<RuleDto>(yaml) ?? throw new RuleValidationException($"{origin}: archivo vacío"); }
        catch (YamlDotNet.Core.YamlException e) { throw new RuleValidationException($"{origin}: YAML inválido: {e.Message}"); }

        void Fail(string msg) => throw new RuleValidationException($"{origin}: {msg}");

        if (string.IsNullOrWhiteSpace(dto.Id)) Fail("falta 'id'");
        var sources = new HashSet<string>(StringComparer.Ordinal);
        switch (dto.Fuente)
        {
            case string fs when !string.IsNullOrWhiteSpace(fs): sources.Add(fs.Trim()); break;
            case IEnumerable<object> fl:
                foreach (var o in fl) if (o?.ToString() is { Length: > 0 } t) sources.Add(t.Trim());
                break;
        }
        if (sources.Count == 0) Fail("falta 'fuente'");
        var c = dto.Condicion ?? new CondicionDto();
        if (dto.Condicion == null) Fail("falta 'condicion'");

        var mode = (dto.Modo ?? "observe").Trim().ToLowerInvariant() switch
        {
            "observe" => RuleMode.Observe,
            "enforce" => RuleMode.Enforce,
            var m => throw new RuleValidationException($"{origin}: modo inválido '{m}' (observe|enforce)")
        };

        var types = new HashSet<string>(StringComparer.Ordinal);
        switch (c.EventId)
        {
            case string s when !string.IsNullOrWhiteSpace(s): types.Add(s.Trim()); break;
            case IEnumerable<object> list:
                foreach (var o in list) if (o?.ToString() is { Length: > 0 } t) types.Add(t.Trim());
                break;
        }
        if (types.Count == 0) Fail("condicion.event_id vacío");

        var group = (c.AgruparPor ?? "ninguno").Trim().ToLowerInvariant() switch
        {
            "ninguno" or "none" => GroupBy.None,
            "ip_origen" => GroupBy.Ip,
            "usuario" => GroupBy.Actor,
            "objeto" => GroupBy.Target,
            var g => throw new RuleValidationException($"{origin}: agrupar_por inválido '{g}'")
        };
        if (c.Umbral < 1) Fail("condicion.umbral debe ser >= 1");
        var window = ParseDuration(c.Ventana, origin, "condicion.ventana");

        var sevText = (dto.Severidad ?? "media").Trim().Replace('í', 'i');
        if (!Enum.TryParse<Severity>(sevText, true, out var severity)) Fail($"severidad inválida '{dto.Severidad}'");

        var excludeAllow = dto.Excluir?.Contains("lista_blanca") ?? false;
        var excludeWindows = dto.Excluir?.Contains("ventanas_deploy") ?? false;
        if (dto.Excluir != null && dto.Excluir.Any(x => x is not ("lista_blanca" or "ventanas_deploy"))) Fail("'excluir' solo admite 'lista_blanca' y 'ventanas_deploy'");
        var filters = (c.Filtros ?? new()).Select(f => ParseFilter(f, origin, "condicion.filtros")).ToList();
        var except = (c.Excepto ?? new()).Select(f => ParseFilter(f, origin, "condicion.excepto")).ToList();

        string? action = dto.Respuesta?.Accion;
        TimeSpan? blockDuration = null;
        if (action != null)
        {
            if (!RuleActions.Known.Contains(action)) Fail($"respuesta.accion desconocida '{action}'");
            if (action == RuleActions.BlockIp)
            {
                if (group != GroupBy.Ip) Fail("firewall.block_ip exige agrupar_por: ip_origen");
                blockDuration = ParseDuration(dto.Respuesta!.Duracion, origin, "respuesta.duracion");
                if (!excludeAllow) Fail("una regla que bloquea IPs debe declarar excluir: [lista_blanca] (principio 2)");
            }
        }
        var notify = dto.Respuesta?.Notificar ?? new List<string>();
        if (notify.Any(n => n is not ("correo" or "teams"))) Fail("respuesta.notificar solo admite correo|teams");

        return new Rule(dto.Id!.Trim(), dto.Nombre ?? dto.Id!, mode, string.Join(",", sources.OrderBy(x => x)), types, group, c.Umbral, window,
            severity, excludeAllow, action, blockDuration, notify, dto.Runbook, sources, filters, except, excludeWindows);
    }

    private static EventFilter ParseFilter(FiltroDto f, string origin, string where)
    {
        void Fail(string msg) => throw new RuleValidationException($"{origin}: {where}: {msg}");
        var field = (f.Campo ?? "").Trim().ToLowerInvariant();
        if (!EventFilter.Fields.Contains(field)) Fail($"campo inválido '{f.Campo}' ({string.Join("|", EventFilter.Fields)})");
        var contains = (f.Contiene ?? new()).Where(x => !string.IsNullOrEmpty(x)).ToList();
        var kinds = (contains.Count > 0 ? 1 : 0) + (f.Regex != null ? 1 : 0) + (f.Igual != null ? 1 : 0);
        if (kinds == 0) Fail("cada filtro necesita 'contiene', 'regex' o 'igual'");
        if (f.Igual != null && (contains.Count > 0 || f.Regex != null)) Fail("'igual' no se combina con 'contiene'/'regex'");
        Regex? rx = null;
        if (f.Regex != null)
        {
            try { rx = new Regex(f.Regex, RegexOptions.IgnoreCase | RegexOptions.NonBacktracking | RegexOptions.CultureInvariant); }
            catch (Exception e) when (e is ArgumentException or NotSupportedException) { Fail($"regex inválida o no admitida (sin retroceso): {e.Message}"); }
        }
        return new EventFilter(field, contains, rx, f.Igual);
    }

    /// <summary>Formato: entero + unidad s|m|h|d (p. ej. 30s, 5m, 1h, 2d).</summary>
    public static TimeSpan ParseDuration(string? text, string origin = "", string field = "duración")
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length < 2
            || !int.TryParse(text[..^1], NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n <= 0)
            throw new RuleValidationException($"{origin}: {field} inválida '{text}' (use p. ej. 30s, 5m, 1h, 2d)");
        return text[^1] switch
        {
            's' => TimeSpan.FromSeconds(n),
            'm' => TimeSpan.FromMinutes(n),
            'h' => TimeSpan.FromHours(n),
            'd' => TimeSpan.FromDays(n),
            _ => throw new RuleValidationException($"{origin}: {field} con unidad inválida '{text}'")
        };
    }
}
