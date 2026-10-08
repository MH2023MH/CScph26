using SecurityAgent.Core.State;

namespace SecurityAgent.Core.Rules;

public static class RuleModes
{
    /// <summary>
    /// Modo efectivo = el archivo de la regla dice 'enforce' Y la aprobación persistida también.
    /// Doble llave deliberada (principio 1): editar un YAML no basta para empezar a bloquear.
    /// </summary>
    public static RuleMode Effective(Rule rule, IStateStore store) =>
        rule.FileMode == RuleMode.Enforce && store.GetRuleMode(rule.Id) == RuleMode.Enforce ? RuleMode.Enforce : RuleMode.Observe;
}
