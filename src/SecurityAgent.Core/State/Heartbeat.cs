namespace SecurityAgent.Core.State;

/// <summary>Latido del agente: el Worker lo actualiza en cada ciclo; la API de estado lo expone.</summary>
public sealed class Heartbeat
{
    private long _last;
    public DateTimeOffset StartedAt { get; }

    public Heartbeat(TimeProvider? time = null)
    {
        _time = time ?? TimeProvider.System;
        StartedAt = _time.GetUtcNow();
    }

    private readonly TimeProvider _time;

    public void Beat() => Interlocked.Exchange(ref _last, _time.GetUtcNow().ToUnixTimeMilliseconds());

    public DateTimeOffset? LastBeat => Interlocked.Read(ref _last) is var v and > 0 ? DateTimeOffset.FromUnixTimeMilliseconds(v) : null;
}
