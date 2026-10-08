using System.Globalization;
using System.Xml.Linq;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.Text;

namespace SecurityAgent.Collectors.EventLog;

/// <summary>
/// Convierte el XML de un evento de Windows (EventRecord.ToXml()) al modelo común.
/// Convención de campos: Actor = cuenta que actúa o es objetivo del intento (4625: cuenta probada; 472x/473x/4698: quien ejecuta);
/// Target = objeto afectado (cuenta creada, grupo, servicio, tarea, App Pool, amenaza); Detail = dato adicional (ruta del ejecutable...).
/// </summary>
public static class EventLogXmlParser
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    public static string SourceOf(string channel) => channel switch
    {
        "Security" => "eventlog.security",
        "System" => "eventlog.system",
        "Application" => "eventlog.application",
        "Microsoft-Windows-Windows Defender/Operational" => "defender",
        "Microsoft-Windows-Sysmon/Operational" => "sysmon",
        _ => "eventlog." + channel.ToLowerInvariant().Replace(' ', '_').Replace('/', '.')
    };

    /// <summary>Devuelve null si el XML no es un evento válido (se ignora, nunca lanza por datos hostiles).</summary>
    public static SecurityEvent? Parse(string xml, string? channelHint = null)
    {
        XDocument doc;
        try { doc = XDocument.Parse(xml); }
        catch (System.Xml.XmlException) { return null; }

        var sys = doc.Root?.Element(Ns + "System");
        if (sys is null) return null;
        var eventId = sys.Element(Ns + "EventID")?.Value?.Trim();
        var time = sys.Element(Ns + "TimeCreated")?.Attribute("SystemTime")?.Value;
        var recordId = sys.Element(Ns + "EventRecordID")?.Value?.Trim();
        var channel = sys.Element(Ns + "Channel")?.Value?.Trim() ?? channelHint;
        if (string.IsNullOrEmpty(eventId) || string.IsNullOrEmpty(channel) || string.IsNullOrEmpty(recordId)
            || !DateTimeOffset.TryParse(time, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var ts))
            return null;

        var named = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var positional = new List<string>();
        foreach (var d in doc.Root!.Element(Ns + "EventData")?.Elements(Ns + "Data") ?? Enumerable.Empty<XElement>())
        {
            var name = d.Attribute("Name")?.Value;
            var value = d.Value;
            if (name is null) positional.Add(value);
            else named[name] = value;
        }
        string? N(params string[] keys) => keys.Select(k => named.GetValueOrDefault(k)).FirstOrDefault(v => !string.IsNullOrWhiteSpace(v) && v != "-");

        string? actor, target = null, detail = null;
        switch (eventId)
        {
            case "4625":   // logon fallido
            case "4624":
                actor = N("TargetUserName");
                detail = N("LogonType") is { } lt ? $"logon_type={lt}" : null;
                break;
            case "4720":   // cuenta creada
                actor = N("SubjectUserName");
                target = N("TargetUserName");
                break;
            case "4732":   // miembro agregado a grupo local
            case "4728":
            case "4756":
                actor = N("SubjectUserName");
                target = N("TargetUserName");                  // nombre del grupo
                detail = N("MemberSid") is { } sid ? $"member={sid}" : null;
                break;
            case "4698":   // tarea programada creada
                actor = N("SubjectUserName");
                target = N("TaskName");
                break;
            case "7045":   // servicio instalado
                actor = N("AccountName");
                target = N("ServiceName");
                detail = N("ImagePath", "ImageName");
                break;
            default:       // incluye 5002 (WAS: App Pool deshabilitado) y eventos de Defender/Sysmon
                actor = N("SubjectUserName", "User", "Detection User");
                target = N("Threat Name", "Path", "TaskName", "ServiceName") ?? positional.FirstOrDefault(p => !string.IsNullOrWhiteSpace(p));
                detail = N("Image", "CommandLine");
                break;
        }

        var ip = Sanitizer.CleanIp(N("IpAddress", "SourceNetworkAddress"));

        var level = sys.Element(Ns + "Level")?.Value;
        var severity = level is "1" or "2" ? Severity.Media : Severity.Info;
        return new SecurityEvent($"{ShortChannel(channel)}-{recordId}", ts.ToUniversalTime(), SourceOf(channel), eventId, severity,
            actor, ip, target, detail);
    }

    private static string ShortChannel(string channel) => channel switch
    {
        "Security" => "sec",
        "System" => "sys",
        "Microsoft-Windows-Windows Defender/Operational" => "def",
        "Microsoft-Windows-Sysmon/Operational" => "sysmon",
        _ => channel.ToLowerInvariant().Replace(' ', '_').Replace('/', '.')
    };

    public static long? RecordIdOf(string xml)
    {
        try
        {
            var v = XDocument.Parse(xml).Root?.Element(Ns + "System")?.Element(Ns + "EventRecordID")?.Value;
            return long.TryParse(v, out var id) ? id : null;
        }
        catch (System.Xml.XmlException) { return null; }
    }
}
