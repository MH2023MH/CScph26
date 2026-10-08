namespace SecurityAgent.Core.State;

/// <summary>Límites del State Store; todo el crecimiento de agent.db queda acotado por estos valores.</summary>
public sealed class StateStoreOptions
{
    public string DatabasePath { get; set; } = @"D:\Apps\SecurityAgent\data\agent.db";

    /// <summary>Los eventos más viejos que esto se purgan.</summary>
    public TimeSpan EventRetention { get; set; } = TimeSpan.FromDays(30);

    /// <summary>Máximo de eventos conservados (se borran los más antiguos).</summary>
    public int MaxEvents { get; set; } = 500_000;

    /// <summary>Máximo de alertas conservadas.</summary>
    public int MaxAlerts { get; set; } = 50_000;

    /// <summary>Tamaño máximo aproximado de datos en agent.db (bytes).</summary>
    public long MaxDatabaseBytes { get; set; } = 256L * 1024 * 1024;
}
