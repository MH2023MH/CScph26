using Microsoft.Extensions.Configuration;
using System.Net;
using SecurityAgent.Core.Integrity;
using SecurityAgent.Core.Rules;
using SecurityAgent.Core.State;
using SecurityAgent.Responders;

namespace SecurityAgent.Worker;

/// <summary>Órdenes de línea de comandos para el instalador: <c>--make-manifest</c> y <c>--verify-manifest</c>.</summary>
public static class Cli
{
    /// <returns>Código de salida si se ejecutó una orden CLI; null si no era una (arranque normal del servicio).</returns>
    public static int? TryRun(string[] args, string baseDir, IConfiguration config, TextWriter output, IFirewall? firewall = null)
    {
        var options = AgentComposition.BindOptions(config);
        if (args.Contains("--make-manifest"))
        {
            var manifest = IntegrityManifest.Create(baseDir, options.Integrity.KeyBytes);
            var path = Path.Combine(baseDir, IntegrityManifest.FileName);
            var json = manifest.ToJson();
            File.WriteAllText(path, json);
            output.WriteLine($"Manifiesto creado: {path}");
            output.WriteLine($"Archivos protegidos: {manifest.Files.Count}; firmado: {(manifest.Hmac != null ? "sí" : "NO (configure SecurityAgent:Integrity:HmacKey)")}");
            output.WriteLine($"SHA-256 del manifiesto: {IntegrityManifest.Sha256OfText(json)}");
            return 0;
        }
        if (args.Contains("--verify-manifest"))
        {
            var report = IntegrityVerifier.Verify(baseDir, options.Integrity.KeyBytes);
            output.WriteLine(report.Ok ? "INTEGRIDAD OK" : "INTEGRIDAD VIOLADA: " + report.Describe());
            return report.Ok ? 0 : 2;
        }
        if (args.Contains("--unblock-ip"))
        {
            var i = Array.IndexOf(args, "--unblock-ip");
            if (i + 1 >= args.Length || !IPAddress.TryParse(args[i + 1], out var ip))
            {
                output.WriteLine("Uso: --unblock-ip <dirección IP>");
                return 1;
            }
            using var store = new SqliteStateStore(options.Store);
            var executor = new ResponseExecutor(store, firewall ?? new WindowsFirewall(), Allowlist.Empty);
            var hadRecord = executor.Unblock(ip.ToString());
            output.WriteLine(hadRecord ? $"Bloqueo de {ip} retirado del firewall y del registro." : $"No había registro de bloqueo para {ip}; se retiró cualquier regla residual del firewall.");
            return 0;
        }
        if (args.Contains("--set-mode"))
        {
            // Aprobación humana explícita de enforce (principio 1). Es una de las dos llaves; la otra es 'modo: enforce' en el YAML de la regla.
            var i = Array.IndexOf(args, "--set-mode");
            if (i + 2 >= args.Length || !Enum.TryParse<RuleMode>(args[i + 2], true, out var mode))
            {
                output.WriteLine("Uso: --set-mode <ID de regla> <observe|enforce>");
                return 1;
            }
            var rule = RuleLoader.LoadDirectory(options.ResolveRulesDir()).FirstOrDefault(r => r.Id.Equals(args[i + 1], StringComparison.OrdinalIgnoreCase));
            if (rule is null)
            {
                output.WriteLine($"No existe la regla '{args[i + 1]}' en {options.ResolveRulesDir()}.");
                return 1;
            }
            using var store = new SqliteStateStore(options.Store);
            store.SetRuleMode(rule.Id, mode);
            output.WriteLine($"Aprobación guardada: {rule.Id} = {mode}.");
            if (mode == RuleMode.Enforce && rule.FileMode != RuleMode.Enforce)
                output.WriteLine($"AVISO: el archivo de la regla sigue en 'modo: observe'; la regla NO bloqueará hasta que también diga 'modo: enforce' (y se regenere el manifiesto).");
            if (mode == RuleMode.Observe && rule.FileMode == RuleMode.Enforce)
                output.WriteLine("AVISO: el archivo de la regla dice 'modo: enforce' pero la aprobación está retirada: la regla opera en observe.");
            return 0;
        }
        if (args.Contains("--list-blocks"))
        {
            using var store = new SqliteStateStore(options.Store);
            var blocks = store.ListActiveBlocks();
            output.WriteLine(blocks.Count == 0 ? "Sin bloqueos activos." : $"{blocks.Count} bloqueo(s) activo(s):");
            foreach (var b in blocks) output.WriteLine($"  {b.Ip}  regla {b.RuleId}  expira {b.ExpiresAt:u}  ({b.Reason})");
            return 0;
        }
        return null;
    }
}
