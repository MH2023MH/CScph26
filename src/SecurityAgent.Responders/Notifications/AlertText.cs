using SecurityAgent.Core.Alerts;
using SecurityAgent.Core.Text;

namespace SecurityAgent.Responders.Notifications;

/// <summary>Texto de una notificación. Todo campo que pueda venir del exterior se sanea antes de salir.</summary>
public static class AlertText
{
    public static string Subject(Alert a) => $"[CScph26][{a.Severity}] {Sanitizer.Clean(a.RuleId, 40)} ({a.Mode})";

    public static string Body(Alert a) =>
        $"Alerta: {a.Id}\n" +
        $"Regla: {Sanitizer.Clean(a.RuleId, 40)}\n" +
        $"Severidad: {a.Severity}\n" +
        $"Modo: {a.Mode}\n" +
        $"Hora (UTC): {a.Timestamp.UtcDateTime:u}\n" +
        $"Detalle: {Sanitizer.Clean(a.Message, 400)}\n" +
        $"Acción: {Sanitizer.Clean(a.ActionTaken, 300) ?? "ninguna"}\n" +
        $"Eventos: {string.Join(", ", a.EventIds.Take(20).Select(e => Sanitizer.Clean(e, 60)))}\n";
}
