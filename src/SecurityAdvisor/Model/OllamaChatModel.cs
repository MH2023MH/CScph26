using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecurityAdvisor.Model;

public sealed class OllamaOptions
{
    public string Endpoint { get; set; } = "http://localhost:11434";
    /// <summary>Nombre del modelo en Ollama. Se elige cuando se defina el hardware (§10).</summary>
    public string Name { get; set; } = "";
    public double Temperature { get; set; } = 0;
    public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(5);
}

/// <summary>Modelo local vía Ollama (/api/chat con llamadas a herramientas). Los datos no salen del equipo.</summary>
public sealed class OllamaChatModel(HttpClient http, OllamaOptions options) : ILanguageModel
{
    public async Task<ModelTurn> NextAsync(IReadOnlyList<ChatMessage> messages, IReadOnlyList<ToolSpec> tools, CancellationToken ct = default)
    {
        if (options.Name == "") throw new InvalidOperationException("Falta el nombre del modelo (Advisor:Model:Name).");
        var body = new JsonObject
        {
            ["model"] = options.Name,
            ["stream"] = false,
            ["options"] = new JsonObject { ["temperature"] = options.Temperature },
            ["messages"] = new JsonArray(messages.Select(ToJson).ToArray()),
            ["tools"] = new JsonArray(tools.Select(t => (JsonNode)new JsonObject
            {
                ["type"] = "function",
                ["function"] = new JsonObject
                {
                    ["name"] = t.Name,
                    ["description"] = t.Description,
                    ["parameters"] = JsonNode.Parse(t.ParametersJsonSchema),
                }
            }).ToArray()),
        };
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(options.Timeout);
        using var resp = await http.PostAsync(options.Endpoint.TrimEnd('/') + "/api/chat",
            new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"), cts.Token);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(cts.Token));
        var msg = doc.RootElement.GetProperty("message");
        var calls = new List<ToolCall>();
        if (msg.TryGetProperty("tool_calls", out var tc) && tc.ValueKind == JsonValueKind.Array)
            foreach (var c in tc.EnumerateArray())
            {
                var fn = c.GetProperty("function");
                var args = fn.TryGetProperty("arguments", out var a) ? a.Clone() : JsonDocument.Parse("{}").RootElement.Clone();
                if (args.ValueKind == JsonValueKind.String)   // algunos modelos devuelven los argumentos como texto JSON
                    try { args = JsonDocument.Parse(args.GetString()!).RootElement.Clone(); } catch (JsonException) { args = JsonDocument.Parse("{}").RootElement.Clone(); }
                calls.Add(new ToolCall(fn.GetProperty("name").GetString() ?? "", args));
            }
        var text = msg.TryGetProperty("content", out var content) ? content.GetString() : null;
        return new ModelTurn(string.IsNullOrWhiteSpace(text) ? null : text, calls);
    }

    private static JsonNode ToJson(ChatMessage m)
    {
        var o = new JsonObject { ["role"] = m.Role, ["content"] = m.Content ?? "" };
        if (m.ToolName != null) o["tool_name"] = m.ToolName;
        if (m.ToolCalls is { Count: > 0 })
            o["tool_calls"] = new JsonArray(m.ToolCalls.Select(c => (JsonNode)new JsonObject
            {
                ["function"] = new JsonObject { ["name"] = c.Name, ["arguments"] = JsonNode.Parse(c.Arguments.GetRawText()) }
            }).ToArray());
        return o;
    }
}
