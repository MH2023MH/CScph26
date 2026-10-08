using SecurityAgent.Core.Alerts;
using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;

namespace SecurityAgent.Responders;

/// <summary>
/// Convierte aciertos de regla en alertas y, solo en modo enforce, en acciones.
/// Modo efectivo = el archivo de la regla dice 'enforce' Y la aprobación persistida (State Store) también.
/// Doble llave deliberada (principio 1): editar un YAML no basta para empezar a bloquear.
/// </summary>
public sealed class ResponseExecutor
{
    private readonly IStateStore _store;
    private readonly IFirewall _firewall;
    private readonly Allowlist _allowlist;
    private readonly TimeProvider _time;

    public ResponseExecutor(IStateStore store, IFirewall firewall, Allowlist allowlist, TimeProvider? time = null)
    {
        _store = store;
        _firewall = firewall;
        _allowlist = allowlist;
        _time = time ?? TimeProvider.System;
    }

    public RuleMode EffectiveMode(Rule rule) =>
        rule.FileMode == RuleMode.Enforce && _store.GetRuleMode(rule.Id) == RuleMode.Enforce ? RuleMode.Enforce : RuleMode.Observe;

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
            GroupKey: hit.GroupKey == "*" ? null : hit.GroupKey,
            Message: $"{rule.Id} {rule.Name}: {hit.EventIds.Count} evento(s) en {rule.Window.TotalMinutes:0.##} min" +
                     (hit.GroupKey == "*" ? "" : $" para '{hit.GroupKey}'"),
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
            return $"omitido: {ip} está en la lista blanca o no es una IP válida";
        var now = _time.GetUtcNow();
        var expires = now + (rule.BlockDuration ?? throw new InvalidOperationException("Bloqueo sin duración"));
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
        foreach (var b in _store.ListExpiredBlocks())
        {
            try { _firewall.UnblockIp(b.Ip); }
            catch { continue; }
            _store.RemoveBlock(b.Ip);
            removed++;
        }
        return removed;
    }
}
