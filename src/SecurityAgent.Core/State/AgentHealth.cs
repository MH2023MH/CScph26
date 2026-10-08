namespace SecurityAgent.Core.State;

/// <summary>Estado de las funciones de autoprotección; lo actualizan los servicios y lo expone la API de estado.</summary>
public sealed class AgentHealth
{
    /// <summary>disabled | ok | failing</summary>
    public volatile string LogShipping = "disabled";
    /// <summary>unknown | ok | violated</summary>
    public volatile string Integrity = "unknown";
}
