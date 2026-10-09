using SecurityAgent.Core.Events;

namespace SecurityAgent.Core.Rules;

/// <summary>
/// Evalúa eventos contra reglas (umbral / ventana / agrupación). Determinista y sin efectos:
/// solo produce <see cref="RuleHit"/>; ejecutar acciones es responsabilidad del ResponseExecutor.
/// El reloj es el timestamp de los eventos, por lo que funciona igual con eventos simulados.
/// </summary>
public sealed class RuleEngine
{
    private const int MaxTrackedKeys = 20_000;

    private readonly IReadOnlyList<Rule> _rules;
    private readonly Allowlist _allowlist;
    private readonly DeployWindows _deployWindows;
    private readonly Dictionary<(string RuleId, string Key), Queue<(DateTimeOffset Ts, string Id)>> _windows = new();
    private readonly object _gate = new();

    public RuleEngine(IEnumerable<Rule> rules, Allowlist allowlist, DeployWindows? windows = null)
    {
        _rules = rules.ToList();
        _allowlist = allowlist;
        _deployWindows = windows ?? DeployWindows.None;
    }

    public IReadOnlyList<Rule> Rules => _rules;

    public IReadOnlyList<RuleHit> Process(SecurityEvent ev)
    {
        var hits = new List<RuleHit>();
        lock (_gate)
        {
            foreach (var rule in _rules)
            {
                if (!rule.AllSources.Contains(ev.Source) || !rule.EventTypes.Contains(ev.Type)) continue;
                if (rule.ExcludeAllowlist && ev.Ip != null && _allowlist.IsAllowed(ev.Ip)) continue;
                if (rule.ExcludeDeployWindows && _deployWindows.IsInWindow(ev.Timestamp)) continue;
                if (rule.AllFilters.Any(f => !f.Matches(ev))) continue;            // todos los filtros deben cumplirse
                if (rule.AllExcept.Any(f => f.Matches(ev))) continue;              // y ninguna excepción

                var key = rule.GroupBy switch
                {
                    GroupBy.Ip => ev.Ip,
                    GroupBy.Actor => ev.Actor,
                    GroupBy.Target => ev.Target,
                    _ => "*"
                };
                if (string.IsNullOrEmpty(key)) continue;   // sin valor de agrupación no se puede atribuir

                var wk = (rule.Id, key);
                if (!_windows.TryGetValue(wk, out var q)) _windows[wk] = q = new();
                while (q.Count > 0 && ev.Timestamp - q.Peek().Ts > rule.Window) q.Dequeue();
                q.Enqueue((ev.Timestamp, ev.Id));

                if (q.Count >= rule.Threshold)
                {
                    hits.Add(new RuleHit(rule, key, q.Select(x => x.Id).ToList(), ev.Timestamp));
                    q.Clear();   // una alerta por ráfaga
                }
            }
            if (_windows.Count > MaxTrackedKeys) Compact(ev.Timestamp);
        }
        return hits;
    }

    /// <summary>Claves (regla, grupo) con una ventana abierta. Acotado por <see cref="MaxTrackedKeys"/>.</summary>
    public int TrackedKeys { get { lock (_gate) return _windows.Count; } }

    private void Compact(DateTimeOffset now)
    {
        var windowOf = _rules.ToDictionary(r => r.Id, r => r.Window);
        foreach (var k in _windows.Keys.ToList())
        {
            var q = _windows[k];
            while (q.Count > 0 && now - q.Peek().Ts > windowOf[k.RuleId]) q.Dequeue();
            if (q.Count == 0) _windows.Remove(k);
        }
        if (_windows.Count <= MaxTrackedKeys) return;

        // Todas siguen vigentes (p. ej. un atacante inventa claves distintas: nombres de usuario, IP falsas). Tope duro: se descartan
        // las de menos actividad hasta quedar al 90 %, de modo que esta limpieza ocurre cada ~2 000 claves y no en cada evento.
        var evict = _windows.Count - MaxTrackedKeys * 9 / 10;
        foreach (var kv in _windows.OrderBy(kv => kv.Value.Count).ThenBy(kv => kv.Value.Peek().Ts).Take(evict).ToList())
            _windows.Remove(kv.Key);
    }
}
