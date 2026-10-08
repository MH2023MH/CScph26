using System.Text.Json;

namespace SecurityAdvisor.Model;

public sealed record ToolCall(string Name, JsonElement Arguments);

/// <param name="Role">system | user | assistant | tool</param>
public sealed record ChatMessage(string Role, string? Content, IReadOnlyList<ToolCall>? ToolCalls = null, string? ToolName = null);

/// <summary>Respuesta del modelo: texto final o petición de herramientas.</summary>
public sealed record ModelTurn(string? Text, IReadOnlyList<ToolCall> ToolCalls)
{
    public static ModelTurn Say(string text) => new(text, Array.Empty<ToolCall>());
    public static ModelTurn Call(params ToolCall[] calls) => new(null, calls);
}

public sealed record ToolSpec(string Name, string Description, string ParametersJsonSchema);

public interface ILanguageModel
{
    Task<ModelTurn> NextAsync(IReadOnlyList<ChatMessage> messages, IReadOnlyList<ToolSpec> tools, CancellationToken ct = default);
}
