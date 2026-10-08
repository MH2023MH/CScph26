using System.Globalization;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace SecurityAgent.Core.Rules;

/// <summary>
/// Ventanas de deploy conocidas (decisión abierta de §10). Los cambios de archivos dentro de una ventana no disparan SEC-006.
/// Sin ventanas configuradas, todo cambio fuera de lo normal alerta.
/// </summary>
public sealed class DeployWindows
{
    public sealed record Recurring(IReadOnlySet<DayOfWeek> Days, TimeSpan From, TimeSpan To);
    public sealed record OneOff(DateTimeOffset From, DateTimeOffset To, string? Reason);

    private readonly IReadOnlyList<Recurring> _recurring;
    private readonly IReadOnlyList<OneOff> _oneOff;
    private readonly TimeZoneInfo _tz;

    public DeployWindows(IEnumerable<Recurring>? recurring = null, IEnumerable<OneOff>? oneOff = null, TimeZoneInfo? zone = null)
    {
        _recurring = (recurring ?? Array.Empty<Recurring>()).ToList();
        _oneOff = (oneOff ?? Array.Empty<OneOff>()).ToList();
        _tz = zone ?? TimeZoneInfo.Local;
    }

    public static DeployWindows None => new();

    public bool IsInWindow(DateTimeOffset when)
    {
        if (_oneOff.Any(w => when >= w.From && when <= w.To)) return true;
        var local = TimeZoneInfo.ConvertTime(when, _tz);
        var t = local.TimeOfDay;
        foreach (var w in _recurring)
        {
            if (w.To > w.From)
            {
                if (w.Days.Contains(local.DayOfWeek) && t >= w.From && t <= w.To) return true;
            }
            else   // cruza la medianoche: 22:00–02:00 pertenece al día en que empieza
            {
                if (w.Days.Contains(local.DayOfWeek) && t >= w.From) return true;
                if (w.Days.Contains(local.AddDays(-1).DayOfWeek) && t <= w.To) return true;
            }
        }
        return false;
    }

    // ---- YAML ----
    private sealed class FileDto
    {
        public string? ZonaHoraria { get; set; }
        public List<RecurDto>? Recurrentes { get; set; }
        public List<OneOffDto>? Puntuales { get; set; }
    }
    private sealed class RecurDto { public List<string>? Dias { get; set; } public string? Desde { get; set; } public string? Hasta { get; set; } }
    private sealed class OneOffDto { public string? Desde { get; set; } public string? Hasta { get; set; } public string? Motivo { get; set; } }

    private static readonly Dictionary<string, DayOfWeek> Days = new(StringComparer.OrdinalIgnoreCase)
    {
        ["lun"] = DayOfWeek.Monday, ["mar"] = DayOfWeek.Tuesday, ["mie"] = DayOfWeek.Wednesday, ["jue"] = DayOfWeek.Thursday,
        ["vie"] = DayOfWeek.Friday, ["sab"] = DayOfWeek.Saturday, ["dom"] = DayOfWeek.Sunday,
        ["mon"] = DayOfWeek.Monday, ["tue"] = DayOfWeek.Tuesday, ["wed"] = DayOfWeek.Wednesday, ["thu"] = DayOfWeek.Thursday,
        ["fri"] = DayOfWeek.Friday, ["sat"] = DayOfWeek.Saturday, ["sun"] = DayOfWeek.Sunday,
    };

    public static DeployWindows LoadFile(string path) => File.Exists(path) ? ParseYaml(File.ReadAllText(path)) : None;

    public static DeployWindows ParseYaml(string yaml)
    {
        var de = new DeserializerBuilder().WithNamingConvention(UnderscoredNamingConvention.Instance).Build();
        FileDto dto;
        try { dto = de.Deserialize<FileDto>(yaml) ?? new FileDto(); }
        catch (YamlDotNet.Core.YamlException e) { throw new RuleValidationException("deploy-windows.yaml inválido: " + e.Message); }

        TimeZoneInfo? zone = null;
        if (!string.IsNullOrWhiteSpace(dto.ZonaHoraria))
        {
            try { zone = TimeZoneInfo.FindSystemTimeZoneById(dto.ZonaHoraria); }
            catch (Exception e) when (e is TimeZoneNotFoundException or InvalidTimeZoneException)
            { throw new RuleValidationException($"deploy-windows.yaml: zona horaria desconocida '{dto.ZonaHoraria}'"); }
        }

        var recurring = new List<Recurring>();
        foreach (var r in dto.Recurrentes ?? new())
        {
            if (r.Dias is not { Count: > 0 }) throw new RuleValidationException("deploy-windows.yaml: ventana recurrente sin 'dias'");
            var days = new HashSet<DayOfWeek>();
            foreach (var d in r.Dias)
                days.Add(Days.TryGetValue(d.Trim(), out var dow) ? dow : throw new RuleValidationException($"deploy-windows.yaml: día inválido '{d}'"));
            if (!TimeSpan.TryParseExact(r.Desde, @"hh\:mm", CultureInfo.InvariantCulture, out var from)
                || !TimeSpan.TryParseExact(r.Hasta, @"hh\:mm", CultureInfo.InvariantCulture, out var to))
                throw new RuleValidationException("deploy-windows.yaml: 'desde'/'hasta' deben tener formato HH:mm");
            recurring.Add(new Recurring(days, from, to));
        }

        var oneOff = new List<OneOff>();
        foreach (var o in dto.Puntuales ?? new())
        {
            if (!DateTimeOffset.TryParse(o.Desde, CultureInfo.InvariantCulture, DateTimeStyles.None, out var from)
                || !DateTimeOffset.TryParse(o.Hasta, CultureInfo.InvariantCulture, DateTimeStyles.None, out var to) || to <= from)
                throw new RuleValidationException("deploy-windows.yaml: ventana puntual con fechas inválidas (use ISO 8601 con zona, hasta > desde)");
            oneOff.Add(new OneOff(from, to, o.Motivo));
        }
        return new DeployWindows(recurring, oneOff, zone);
    }
}
