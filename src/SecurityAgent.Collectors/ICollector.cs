using SecurityAgent.Core.Events;

namespace SecurityAgent.Collectors;

/// <summary>
/// Lote leído por un collector. <see cref="Commit"/> avanza el cursor persistente y debe llamarse
/// solo después de procesar los eventos (entrega al menos una vez: un fallo a mitad de camino re-lee, no pierde).
/// </summary>
public sealed record CollectorBatch(IReadOnlyList<SecurityEvent> Events, Action Commit)
{
    public static CollectorBatch Empty { get; } = new(Array.Empty<SecurityEvent>(), () => { });
}

public interface ICollector
{
    string Name { get; }
    Task<CollectorBatch> PollAsync(CancellationToken ct = default);
}
