#pragma warning disable CA1416   // estas pruebas se omiten fuera de Windows (RequireWindowsAdmin)
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using SecurityAgent.Collectors.Audits;
using SecurityAgent.Collectors.EventLog;
using SecurityAgent.Core.Events;
using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;
using Xunit.Abstractions;

namespace CScph26.Tests;

/// <summary>
/// Pruebas contra un Windows REAL (en CI: máquina efímera de GitHub con permisos de administrador). En Linux se omiten.
/// Validan lo que no se puede comprobar con datos simulados: netsh, Job Object, Event Log, XML real de los eventos y Defender.
/// </summary>
[Trait("Category", "WindowsIntegration")]
[Collection("WindowsIntegration")]
public class WindowsIntegrationTests(ITestOutputHelper log)
{
    private static void RequireWindowsAdmin()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "solo Windows");
        Skip.IfNot(IsAdmin(), "requiere administrador");
    }

    private static bool IsAdmin() => OperatingSystem.IsWindows() && new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    private static (int Code, string Output) Run(string file, params string[] args)
    {
        var psi = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEndAsync();
        var e = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(120_000)) { p.Kill(true); return (-1, "tiempo agotado"); }
        return (p.ExitCode, o.Result + e.Result);
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LogonUser(string user, string? domain, string password, int logonType, int provider, out IntPtr token);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    /// <summary>Un inicio de sesión de red con contraseña incorrecta: genera un evento 4625 real en cada llamada.</summary>
    private static void FailedLogon(string user)
    {
        if (LogonUser(user, ".", "WrongPass-123!", 3, 0, out var token)) CloseHandle(token);
    }

    private static string FindWorkerDll()
    {
        var root = Path.Combine(TestSupport.RepoRoot(), "src", "SecurityAgent.Worker", "bin");
        return Directory.GetFiles(root, "SecurityAgent.Worker.dll", SearchOption.AllDirectories)
            .Where(f => f.Contains("net8.0")).OrderByDescending(File.GetLastWriteTimeUtc).First();
    }

    // ---------------------------------------------------------------- Firewall real

    [SkippableFact]
    public void Firewall_block_and_unblock_roundtrip_with_real_netsh()
    {
        RequireWindowsAdmin();
        const string ip = "203.0.113.250";
        var fw = new WindowsFirewall();
        try
        {
            fw.UnblockIp(ip);                                           // idempotente aunque no exista
            fw.BlockIp(ip, "SEC-TEST");
            var show = Run("netsh", WindowsFirewall.BuildShowArgs(ip));
            log.WriteLine(show.Output);
            Assert.Equal(0, show.Code);
            Assert.Contains(ip, show.Output);

            fw.UnblockIp(ip);
            Assert.NotEqual(0, Run("netsh", WindowsFirewall.BuildShowArgs(ip)).Code);
            fw.UnblockIp(ip);                                           // y de nuevo: sin error
        }
        finally { fw.UnblockIp(ip); }
    }

    // ---------------------------------------------------------------- Job Object real (en un proceso aparte)

    [SkippableFact]
    public void Job_object_memory_cap_really_blocks_allocations()
    {
        RequireWindowsAdmin();
        var r = Run("dotnet", FindWorkerDll(), "--selftest-limits", "256", "0");
        log.WriteLine(r.Output);
        Assert.Contains("APPLIED", r.Output);
        Assert.Contains("ALLOC_BLOCKED", r.Output);
    }

    [SkippableFact]
    public void Job_object_cpu_cap_really_throttles()
    {
        RequireWindowsAdmin();
        var r = Run("dotnet", FindWorkerDll(), "--selftest-limits", "0", "10");
        log.WriteLine(r.Output);
        Assert.Contains("APPLIED", r.Output);
        var m = Regex.Match(r.Output, @"CPU_FRACTION ([0-9.,]+)");
        Assert.True(m.Success, "no se obtuvo la medición de CPU");
        var fraction = double.Parse(m.Groups[1].Value.Replace(',', '.'), System.Globalization.CultureInfo.InvariantCulture);
        Assert.True(fraction <= 0.25, $"el proceso usó {fraction:P0} de la CPU con un tope del 10 %");
    }

    // ---------------------------------------------------------------- Event Log real (canal propio)

    [SkippableFact]
    public void Real_event_log_is_read_incrementally_and_parsed()
    {
        RequireWindowsAdmin();
        const string logName = "CScph26Test", src = "CScph26Src";
        if (System.Diagnostics.EventLog.SourceExists(src)) System.Diagnostics.EventLog.DeleteEventSource(src);
        if (System.Diagnostics.EventLog.Exists(logName)) System.Diagnostics.EventLog.Delete(logName);
        System.Diagnostics.EventLog.CreateEventSource(new EventSourceCreationData(src, logName));
        try
        {
            Thread.Sleep(2000);                                         // el registro nuevo tarda un instante en estar disponible
            using var writer = new System.Diagnostics.EventLog(logName) { Source = src };
            for (var i = 1; i <= 3; i++) writer.WriteEntry($"mensaje {i}", EventLogEntryType.Warning, 4242);
            Thread.Sleep(1000);

            var source = new WindowsEventRecordSource();
            var all = source.Read(logName, 0, 100);
            Assert.Equal(3, all.Count);
            Assert.Equal(all.Max(r => r.RecordId), source.LatestRecordId(logName));
            Assert.Equal(2, source.Read(logName, all[0].RecordId, 100).Count);        // lectura incremental
            Assert.Empty(source.Read("CanalQueNoExiste", 0, 10));                       // canal inexistente: vacío, sin excepción

            var ev = EventLogXmlParser.Parse(all[0].Xml, logName)!;
            log.WriteLine(all[0].Xml);
            Assert.Equal("4242", ev.Type);
            Assert.Equal("eventlog.cscph26test", ev.Source);
            Assert.Equal("mensaje 1", ev.Target);

            // Collector completo con cursor persistente
            var dir = Path.Combine(Path.GetTempPath(), "cscph26-win-" + Guid.NewGuid().ToString("N"));
            using var store = new SqliteStateStore(new StateStoreOptions { DatabasePath = Path.Combine(dir, "agent.db") });
            var collector = new EventLogCollector(source, store, new EventLogCollectorOptions { Channels = { logName }, StartPolicy = StartPolicy.FromStart });
            var batch = collector.PollAsync().GetAwaiter().GetResult();
            Assert.Equal(3, batch.Events.Count);
            batch.Commit();
            Assert.Empty(collector.PollAsync().GetAwaiter().GetResult().Events);
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        }
        finally
        {
            if (System.Diagnostics.EventLog.SourceExists(src)) System.Diagnostics.EventLog.DeleteEventSource(src);
            if (System.Diagnostics.EventLog.Exists(logName)) System.Diagnostics.EventLog.Delete(logName);
        }
    }

    // ---------------------------------------------------------------- Eventos de seguridad reales

    private static readonly string[] AuditGuids =
    {
        "{0CCE9215-69AE-11D9-BED3-505054503030}",   // Logon
        "{0CCE9235-69AE-11D9-BED3-505054503030}",   // User Account Management
        "{0CCE9237-69AE-11D9-BED3-505054503030}",   // Security Group Management
        "{0CCE9227-69AE-11D9-BED3-505054503030}",   // Other Object Access Events (4698)
    };

    private List<SecurityEvent> WaitForEvents(WindowsEventRecordSource source, string channel, long afterId, Func<List<SecurityEvent>, bool> done, int seconds = 45)
    {
        var events = new List<SecurityEvent>();
        for (var i = 0; i < seconds && !done(events); i++)
        {
            Thread.Sleep(1000);
            events = source.Read(channel, afterId, 5000).Select(r => EventLogXmlParser.Parse(r.Xml, channel)).Where(e => e != null).Select(e => e!).ToList();
        }
        return events;
    }

    [SkippableFact]
    public void Real_security_events_are_parsed_and_trigger_the_catalog_rules()
    {
        RequireWindowsAdmin();
        foreach (var g in AuditGuids) Run("auditpol", "/set", $"/subcategory:{g}", "/success:enable", "/failure:enable");

        var source = new WindowsEventRecordSource();
        var secBefore = source.LatestRecordId("Security");
        var sysBefore = source.LatestRecordId("System");
        try
        {
            log.WriteLine(Run("net", "use", @"\\127.0.0.1\IPC$", "/user:cscph26fake", "WrongPass-123!").Output);             // 4625 por SMB (con IP de origen)
            for (var i = 0; i < 8; i++) FailedLogon("cscph26fake");                                                         // 8 × 4625 por la API de Windows
            log.WriteLine(Run("net", "user", "cscph26tmp", "Xx9!tempS1", "/add").Output);                                    // 4720 (contraseña ≤ 14 caracteres: sin pregunta interactiva)
            log.WriteLine(Run("net", "localgroup", "Administrators", "cscph26tmp", "/add").Output);                          // 4732
            log.WriteLine(Run("sc.exe", "create", "CScph26TestSvc", "binPath=", @"C:\Windows\System32\cmd.exe", "start=", "demand").Output);   // 7045
            log.WriteLine(Run("schtasks", "/create", "/tn", "CScph26TestTask", "/tr", @"C:\Windows\System32\cmd.exe", "/sc", "once", "/st", "23:59", "/f").Output);   // 4698

            var sec = WaitForEvents(source, "Security", secBefore, evs =>
                evs.Count(e => e.Type == "4625") >= 8 && evs.Any(e => e.Type == "4720") && evs.Any(e => e.Type == "4732") && evs.Any(e => e.Type == "4698"));
            var sys = WaitForEvents(source, "System", sysBefore, evs => evs.Any(e => e.Type == "7045" && e.Target == "CScph26TestSvc"));
            log.WriteLine($"Security: {string.Join(",", sec.GroupBy(e => e.Type).Select(g => $"{g.Key}x{g.Count()}"))}   System: {sys.Count} eventos");

            // 4625 reales
            var failed = sec.Where(e => e.Type == "4625" && e.Actor == "cscph26fake").ToList();
            Assert.True(failed.Count >= 8, $"4625 vistos: {failed.Count}");
            Assert.All(failed, e => Assert.Equal("eventlog.security", e.Source));
            log.WriteLine("IP de origen de los 4625 reales: " + string.Join(" | ", failed.Select(e => e.Ip ?? "(sin IP)").Distinct()));
            var rawFailed = source.Read("Security", secBefore, 5000).First(r => EventLogXmlParser.Parse(r.Xml, "Security") is { Type: "4625", Actor: "cscph26fake" });
            log.WriteLine("XML real de un 4625:\n" + rawFailed.Xml);

            // cuenta, grupo, tarea
            var created = sec.Single(e => e.Type == "4720" && e.Target == "cscph26tmp");
            Assert.False(string.IsNullOrEmpty(created.Actor));
            var group = sec.First(e => e.Type == "4732");
            Assert.False(string.IsNullOrEmpty(group.Target));
            Assert.Contains("member=", group.Detail);
            Assert.Contains(sec, e => e.Type == "4698" && (e.Target ?? "").Contains("CScph26TestTask"));

            // servicio
            var svc = sys.First(e => e.Type == "7045" && e.Target == "CScph26TestSvc");
            Assert.Contains("cmd.exe", svc.Detail, StringComparison.OrdinalIgnoreCase);

            // Reglas del catálogo sobre eventos REALES
            var engine = new RuleEngine(RuleLoader.LoadDirectory(TestSupport.RulesDir), Allowlist.LoadFile(Path.Combine(TestSupport.RulesDir, "allowlist.yaml")));
            var hits = sec.Concat(sys).OrderBy(e => e.Timestamp).SelectMany(engine.Process).ToList();
            Assert.Contains(hits, h => h.Rule.Id == "SEC-003");
            Assert.Contains(hits, h => h.Rule.Id == "SEC-004" && h.EventIds.Any(id => id.StartsWith("sys-")));
            Assert.Contains(hits, h => h.Rule.Id == "SEC-004" && h.EventIds.Any(id => id.StartsWith("sec-")));
            // los fallos no tienen una IP externa atribuible (loopback / sin IP): SEC-001 no debe bloquear nada
            Assert.DoesNotContain(hits, h => h.Rule.Id == "SEC-001");

            // el umbral y la agrupación funcionan con los eventos reales (regla de solo alerta agrupada por cuenta)
            var alertOnly = RuleLoader.ParseYaml("id: T-4625\nfuente: eventlog.security\ncondicion:\n  event_id: 4625\n  agrupar_por: usuario\n  umbral: 8\n  ventana: 5m\nrespuesta:\n  accion: notify\n");
            var hit = new RuleEngine(new[] { alertOnly }, Allowlist.Empty).Process_All(failed);
            Assert.NotEmpty(hit);
        }
        finally
        {
            Run("net", "localgroup", "Administrators", "cscph26tmp", "/delete");
            Run("net", "user", "cscph26tmp", "/delete");
            Run("sc.exe", "delete", "CScph26TestSvc");
            Run("schtasks", "/delete", "/tn", "CScph26TestTask", "/f");
        }
    }

    // ---------------------------------------------------------------- Defender real (mejor esfuerzo)

    private const string DefenderChannel = "Microsoft-Windows-Windows Defender/Operational";

    private static bool RealtimeProtectionEnabled() =>
        Run("powershell", "-NoProfile", "-Command", "(Get-MpComputerStatus).RealTimeProtectionEnabled").Output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);

    [SkippableFact]
    public void Defender_realtime_toggle_emits_the_event_ids_used_by_sec008()
    {
        RequireWindowsAdmin();
        Skip.IfNot(Run("powershell", "-NoProfile", "-Command", "Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue").Output.Contains("Get-MpComputerStatus"), "Defender no está disponible");
        var source = new WindowsEventRecordSource();
        var wasEnabled = RealtimeProtectionEnabled();
        log.WriteLine("RealTimeProtectionEnabled al empezar: " + wasEnabled);
        try
        {
            // A) activar (si estaba apagada) → evento 5000
            if (!wasEnabled)
            {
                var beforeOn = source.LatestRecordId(DefenderChannel);
                Run("powershell", "-NoProfile", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $false");
                var on = WaitForEvents(source, DefenderChannel, beforeOn, evs => evs.Any(e => e.Type == "5000"), seconds: 40);
                log.WriteLine("Tras ACTIVAR: " + string.Join(", ", on.Select(e => e.Type).Distinct()));
                Skip.If(on.Count == 0, "no se pudo activar la protección en tiempo real (¿Tamper Protection?)");
                Assert.Contains(on, e => e.Type == "5000" && e.Source == "defender");
                log.WriteLine("Confirmado: 5000 = protección en tiempo real ACTIVADA");
            }

            // B) desactivar → evento 5001, y SEC-008 se dispara con el evento real
            var beforeOff = source.LatestRecordId(DefenderChannel);
            Run("powershell", "-NoProfile", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $true");
            var off = WaitForEvents(source, DefenderChannel, beforeOff, evs => evs.Any(e => e.Type == "5001"), seconds: 40);
            log.WriteLine("Tras DESACTIVAR: " + string.Join(", ", off.Select(e => e.Type).Distinct()));
            if (off.Count == 0) { log.WriteLine("No se pudo desactivar la protección (Tamper Protection): 5001 no verificado en esta máquina."); return; }
            Assert.Contains(off, e => e.Type == "5001" && e.Source == "defender");
            log.WriteLine("Confirmado: 5001 = protección en tiempo real DESACTIVADA");
            var hits = new RuleEngine(RuleLoader.LoadDirectory(TestSupport.RulesDir), Allowlist.Empty).Process_All(off);
            Assert.Contains(hits, h => h.Rule.Id == "SEC-008" && h.EventIds.Count > 0);
        }
        finally
        {
            Run("powershell", "-NoProfile", "-Command", $"Set-MpPreference -DisableRealtimeMonitoring ${!wasEnabled}");
        }
    }

    [SkippableFact]
    public void Defender_detects_eicar_and_event_matches_sec008()
    {
        RequireWindowsAdmin();
        if (!RealtimeProtectionEnabled()) Run("powershell", "-NoProfile", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $false");
        Skip.IfNot(RealtimeProtectionEnabled(), "Defender sin protección en tiempo real en esta máquina");

        var source = new WindowsEventRecordSource();
        var before = source.LatestRecordId(DefenderChannel);

        // Cadena de prueba EICAR (inofensiva, estándar de la industria), partida para que no la marque el antivirus al compilar.
        var eicar = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        var dir = Path.Combine(Path.GetTempPath(), "cscph26-eicar-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "prueba.txt");
        try { File.WriteAllText(path, eicar); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { log.WriteLine("Defender bloqueó la escritura: " + e.Message); }

        var events = WaitForEvents(source, DefenderChannel, before, evs => evs.Any(e => e.Type == "1116"), seconds: 25);
        if (!events.Any(e => e.Type == "1116"))
        {
            log.WriteLine("Sin detección en tiempo real; se fuerza un análisis a pedido de la carpeta");
            Run("powershell", "-NoProfile", "-Command", $"Start-MpScan -ScanType CustomScan -ScanPath '{dir}'");
            events = WaitForEvents(source, DefenderChannel, before, evs => evs.Any(e => e.Type == "1116"), seconds: 40);
        }
        log.WriteLine("IDs de Defender tras EICAR: " + string.Join(", ", events.Select(e => e.Type).Distinct()));
        try { Directory.Delete(dir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }

        var detection = events.FirstOrDefault(e => e.Type == "1116");
        Skip.If(detection is null, "Defender no detectó el archivo EICAR en esta máquina (sin firmas actualizadas o sin conexión a la nube); IDs vistos: " + string.Join(", ", events.Select(e => e.Type).Distinct()));
        Assert.Equal("defender", detection!.Source);
        Assert.Contains("EICAR", detection.Target, StringComparison.OrdinalIgnoreCase);
        log.WriteLine($"1116 → Target={detection.Target}  Detail={detection.Detail}  Actor={detection.Actor}");

        var hits = new RuleEngine(RuleLoader.LoadDirectory(TestSupport.RulesDir), Allowlist.Empty).Process_All(events);
        Assert.Contains(hits, h => h.Rule.Id == "SEC-008");
    }

    // ---------------------------------------------------------------- Sondeos locales

    [SkippableFact]
    public void Hardening_probe_and_certificate_source_run_on_real_windows()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "solo Windows");
        var checks = new WindowsHardeningProbe().Run();
        foreach (var c in checks) log.WriteLine($"{(c.Passed is null ? "?" : c.Passed.Value ? "OK" : "FALLA")}  {c.Name}  — {c.Detail}");
        Assert.True(checks.Count >= 7);
        Assert.All(checks, c => Assert.False(string.IsNullOrWhiteSpace(c.Name)));

        var certs = new X509StoreCertificateSource().List();
        log.WriteLine($"Certificados en LocalMachine\\My y WebHosting: {certs.Count}");
        var audit = new CertificateAudit(new X509StoreCertificateSource(), new CertificateAuditOptions()).RunAsync().GetAwaiter().GetResult();
        log.WriteLine($"Auditoría de certificados: {audit.Status} — {audit.Summary}");
        Assert.NotNull(audit.Status);
    }
}

internal static class EngineExtensions
{
    /// <summary>Procesa una lista de eventos y devuelve todos los aciertos.</summary>
    public static List<RuleHit> Process_All(this RuleEngine engine, IEnumerable<SecurityEvent> events) =>
        events.OrderBy(e => e.Timestamp).SelectMany(engine.Process).ToList();
}

/// <summary>Estas pruebas bloquean hilos (esperas, procesos externos): no deben competir con el resto, que sufriría falsos tiempos de espera.</summary>
[CollectionDefinition("WindowsIntegration", DisableParallelization = true)]
public class WindowsIntegrationCollection { }

internal static class ThreadPoolSetup
{
    /// <summary>Evita la inanición del grupo de hilos en máquinas de pocos núcleos (muchas pruebas usan esperas síncronas).</summary>
    [System.Runtime.CompilerServices.ModuleInitializer]
    internal static void Init() => ThreadPool.SetMinThreads(64, 64);
}
