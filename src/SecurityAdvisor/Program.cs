using Microsoft.Extensions.Configuration;
using SecurityAdvisor;
using SecurityAdvisor.Api;
using SecurityAdvisor.Model;
using SecurityAdvisor.Safety;
using SecurityAdvisor.Tools;

// Sistema 2 — consulta del estado de srv-copahue2 en lenguaje natural. Solo lectura.
var config = new ConfigurationBuilder().SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("advisor.json", optional: true).AddJsonFile("advisor.Production.json", optional: true)
    .AddEnvironmentVariables("ADVISOR_").Build();

var baseUrl = config["StatusApi:BaseUrl"] ?? "";
var token = config["StatusApi:Token"] ?? "";
if (baseUrl == "" || token == "")
{
    Console.Error.WriteLine("Falta configuración: StatusApi:BaseUrl y StatusApi:Token (advisor.Production.json o variables ADVISOR_StatusApi__BaseUrl / ADVISOR_StatusApi__Token).");
    return 2;
}

var ollama = config.GetSection("Model").Get<OllamaOptions>() ?? new OllamaOptions();
var redaction = config.GetSection("Redaction").Get<RedactionOptions>() ?? new RedactionOptions();
var advisorOptions = config.GetSection("Advisor").Get<AdvisorOptions>() ?? new AdvisorOptions();

using var apiHttp = new HttpClient();
using var modelHttp = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
var api = new StatusApiClient(apiHttp, baseUrl, token);
var agent = new AdvisorAgent(new OllamaChatModel(modelHttp, ollama), new ToolRegistry(api, new Redactor(redaction)), advisorOptions);

// Evaluación de calidad contra el modelo real: dotnet SecurityAdvisor.dll --eval casos.json [--min-score 0.9]
var eval = Array.IndexOf(args, "--eval");
if (eval >= 0 && eval + 1 < args.Length)
{
    var minScore = double.TryParse(args.SkipWhile(a => a != "--min-score").Skip(1).FirstOrDefault(), System.Globalization.CultureInfo.InvariantCulture, out var ms) ? ms : 0.9;
    var report = await SecurityAdvisor.Evaluation.EvalRunner.RunAsync(agent, SecurityAdvisor.Evaluation.EvalRunner.Load(args[eval + 1]));
    Console.WriteLine($"Evaluación: {report.Passed}/{report.Total} casos ({report.Score:P0}); umbral {minScore:P0}");
    foreach (var f in report.Failures) Console.WriteLine($"  FALLO: {f.Question} -> {f.Reason}");
    return report.Score >= minScore ? 0 : 3;
}

var ask = Array.IndexOf(args, "--ask");
if (ask >= 0 && ask + 1 < args.Length)
{
    var one = await agent.AskAsync(args[ask + 1]);
    Console.WriteLine(one.Text);
    return 0;
}

Console.WriteLine("Asistente de seguridad (solo consulta). Escribe tu pregunta; 'salir' para terminar.");
while (true)
{
    Console.Write("> ");
    var line = Console.ReadLine();
    if (line is null || line.Trim().Equals("salir", StringComparison.OrdinalIgnoreCase)) break;
    if (string.IsNullOrWhiteSpace(line)) continue;
    try { Console.WriteLine((await agent.AskAsync(line)).Text); }
    catch (Exception e) when (e is HttpRequestException or TaskCanceledException or InvalidOperationException)
    { Console.WriteLine($"No pude consultar al modelo: {e.Message}"); }
    Console.WriteLine();
}
return 0;
