namespace SecurityAgent.Core.State;

/// <summary>Estado de las funciones de autoprotección; lo actualizan los servicios y lo expone la API de estado.</summary>
public sealed class AgentHealth
{
    /// <summary>disabled | ok | failing</summary>
    public volatile string LogShipping = "disabled";
    /// <summary>unknown | ok | violated</summary>
    public volatile string Integrity = "unknown";

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _problems = new();

    /// <summary>Un collector que no puede leer su fuente NO debe fallar en silencio: queda aquí y se ve en la API de estado.</summary>
    public void Report(string key, string? problem)
    {
        if (problem is null) _problems.TryRemove(key, out _);
        else _problems[key] = problem;
    }

    public IReadOnlyList<string> Problems() => _problems.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => $"{kv.Key}: {kv.Value}").ToList();
}
