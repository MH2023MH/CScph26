using System.Text.Json;
using System.Text.RegularExpressions;

namespace SecurityAdvisor.Evaluation;

/// <summary>Un caso del conjunto de prueba: qué consultas debe usar el asistente y qué debe contener la respuesta.</summary>
public sealed class EvalCase
{
    public string Question { get; set; } = "";
    /// <summary>Herramientas que DEBE haber llamado (al menos estas). Vacío = no se exige ninguna.</summary>
    public List<string> ExpectTools { get; set; } = new();
    /// <summary>Patrones (regex) que deben aparecer en la respuesta: IDs que se deben citar, frases obligatorias...</summary>
    public List<string> MustMatch { get; set; } = new();
    /// <summary>Patrones que NO pueden aparecer (p. ej. un ID inventado).</summary>
    public List<string> MustNotMatch { get; set; } = new();
    /// <summary>La respuesta debe declarar que no hay información.</summary>
    public bool ExpectNoInformation { get; set; }
    /// <summary>El caso intenta provocar una acción prohibida: ninguna herramienta distinta de las seis puede haberse solicitado.</summary>
    public bool Adversarial { get; set; }
}

public sealed record EvalFailure(string Question, string Reason);

public sealed record EvalReport(int Total, int Passed, IReadOnlyList<EvalFailure> Failures)
{
    public double Score => Total == 0 ? 0 : (double)Passed / Total;
}

public static class EvalRunner
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };

    public static List<EvalCase> Load(string path) =>
        JsonSerializer.Deserialize<List<EvalCase>>(File.ReadAllText(path), Json) ?? throw new InvalidDataException("conjunto de prueba vacío");

    public static async Task<EvalReport> RunAsync(AdvisorAgent agent, IEnumerable<EvalCase> cases, CancellationToken ct = default)
    {
        var failures = new List<EvalFailure>();
        var total = 0;
        foreach (var c in cases)
        {
            total++;
            var a = await agent.AskAsync(c.Question, ct);
            void Fail(string why) => failures.Add(new EvalFailure(c.Question, why));

            var missingTools = c.ExpectTools.Except(a.ToolsCalled).ToList();
            if (missingTools.Count > 0) Fail("no usó las consultas esperadas: " + string.Join(", ", missingTools));
            foreach (var p in c.MustMatch)
                if (!Regex.IsMatch(a.Text, p, RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)) Fail($"falta '{p}' en la respuesta");
            foreach (var p in c.MustNotMatch)
                if (Regex.IsMatch(a.Text, p, RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)) Fail($"aparece '{p}' en la respuesta");
            if (c.ExpectNoInformation && !a.Text.Contains(AdvisorAgent.NoInfoPrefix, StringComparison.OrdinalIgnoreCase)) Fail("debía responder 'No hay información'");
            if (c.Adversarial && a.Violations.Count > 0) Fail("el modelo cometió violaciones: " + string.Join("; ", a.Violations));
            if (failures.Count > 0 && failures[^1].Question == c.Question) continue;
        }
        var failedQuestions = failures.Select(f => f.Question).Distinct().Count();
        return new EvalReport(total, total - failedQuestions, failures);
    }
}
