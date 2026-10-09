using SecurityAgent.Core.Alerts;
using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;
using SecurityAgent.Core.Text;

namespace SecurityAgent.Responders;

/// <summary>Topes de seguridad del responder: un atacante que sigue enviando tráfico no debe poder inundar el firewall con reglas.</summary>
public sealed record BlockLimits
{
    public int MaxNewPerMinute { get; init; } = 20;
    public int MaxActive { get; init; } = 500;
}

/// <summary>
/// Convierte aciertos de regla en alertas y, solo en modo enforce, en acciones.
/// El modo efectivo sale de <see cref="RuleModes.Effective"/> (doble llave: archivo + aprobación persistida).
/// </summary>
public sealed class ResponseExecutor
{
    private readonly IStateStore _store;
    private readonly IFirewall _firewall;
    private readonly Allowlist _allowlist;
    private readonly TimeProvider _time;
    private readonly BlockLimits _limits;
    private readonly AgentHealth? _health;
    private readonly Queue<DateTimeOffset> _recentBlocks = new();
    private readonly object _gate = new();

    public ResponseExecutor(IStateStore store, IFirewall firewall, Allowlist allowlist, TimeProvider? time = null,
        BlockLimits? limits = null, AgentHealth? health = null)
    {
        _store = store;
        _firewall = firewall;
        _allowlist = allowlist;
        _time = time ?? TimeProvider.System;
        _limits = limits ?? new BlockLimits();
        _health = health;
    }

    public RuleMode EffectiveMode(Rule rule) => RuleModes.Effective(rule, _store);

    public Alert Handle(RuleHit hit)
    {
        var rule = hit.Rule;
        var mode = EffectiveMode(rule);
        string? action = null;

        if (rule.Action == RuleActions.BlockIp)
        {
            if (mode == RuleMode.Observe)
                action = $"observe: no se ejecutó {RuleActions.BlockIp} sobre {hit.Ip}";
            else
                action = TryBlock(hit, rule);
        }
        else if (rule.Action == RuleActions.Notify)
        {
            action = mode == RuleMode.Observe ? "observe: solo alerta" : "notificación";
        }

        var alert = new Alert(
            Id: "ALR-" + Guid.NewGuid().ToString("N")[..12],
            RuleId: rule.Id,
            Timestamp: hit.Timestamp,
            Severity: rule.Severity,
            GroupKey: hit.GroupKey == "*" ? null : SecretScrubber.Scrub(hit.GroupKey),
            Message: $"{rule.Id} {rule.Name}: {hit.EventIds.Count} evento(s) en {rule.Window.TotalMinutes:0.##} min" +
                     (hit.GroupKey == "*" ? "" : $" para '{SecretScrubber.Scrub(hit.GroupKey)}'"),
            EventIds: hit.EventIds,
            Mode: mode,
            ActionTaken: action);
        _store.AddAlert(alert);
        return alert;
    }

    private string TryBlock(RuleHit hit, Rule rule)
    {
        var ip = hit.Ip!;
        // Defensa en profundidad: aunque la regla ya excluye la lista blanca, el responder la vuelve a verificar.
        if (_allowlist.IsAllowed(ip))
            return $"omitido: {ip} está protegida (lista blanca, dirección especial o del propio servidor/red) o no es una IP válida";
        ip = System.Net.IPAddress.Parse(ip.Trim()).ToString();
        var now = _time.GetUtcNow();
        var expires = now + (rule.BlockDuration ?? throw new InvalidOperationException("Bloqueo sin duración"));

        lock (_gate)
        {
            var active = _store.ListActiveBlocks();
            if (active.FirstOrDefault(b => b.Ip == ip) is { } existing)
                return $"{ip} ya estaba bloqueada hasta {existing.ExpiresAt:u}";      // sin otro netsh por cada acierto
            if (active.Count >= _limits.MaxActive)
                return $"omitido: se alcanzó el máximo de {_limits.MaxActive} bloqueos activos; revisar si hay un ataque distribuido o una regla demasiado sensible";
            while (_recentBlocks.Count > 0 && now - _recentBlocks.Peek() >= TimeSpan.FromMinutes(1)) _recentBlocks.Dequeue();
            if (_recentBlocks.Count >= _limits.MaxNewPerMinute)
                return $"omitido: más de {_limits.MaxNewPerMinute} bloqueos nuevos en un minuto; se limita para no saturar el firewall";
            _recentBlocks.Enqueue(now);
        }
        try
        {
            _firewall.BlockIp(ip, rule.Id);
        }
        catch (Exception e)
        {
            return $"error al bloquear {ip}: {e.Message}";
        }
        _store.AddBlock(new BlockEntry(ip, rule.Id, rule.Name, now, expires));
        return $"bloqueo de {ip} hasta {expires:u}";
    }

    /// <summary>Rollback manual de un bloqueo (comando de desbloqueo). Devuelve true si existía.</summary>
    public bool Unblock(string ip)
    {
        _firewall.UnblockIp(ip);
        return _store.RemoveBlock(ip);
    }

    /// <summary>Retira del firewall los bloqueos vencidos. Si el firewall falla se conserva el registro para reintentar.</summary>
    public int SweepExpired()
    {
        var removed = 0;
        var failed = 0;
        string? firstError = null;
        foreach (var b in _store.ListExpiredBlocks())
        {
            try { _firewall.UnblockIp(b.Ip); }
            catch (Exception e) { failed++; firstError ??= $"{b.Ip}: {e.Message}"; continue; }
            _store.RemoveBlock(b.Ip);
            removed++;
        }
        // Un bloqueo vencido que no se puede retirar sigue activo en el firewall: debe verse, no perderse en silencio.
        _health?.Report("firewall-sweep", failed > 0 ? $"no se pudo retirar del firewall el bloqueo vencido de {failed} IP(s); se reintenta en cada mantenimiento ({firstError})" : null);
        return removed;
    }
}
