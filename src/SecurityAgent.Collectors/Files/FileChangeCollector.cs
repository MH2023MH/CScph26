using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using SecurityAgent.Core.Events;

namespace SecurityAgent.Collectors.Files;

public sealed class FileChangeCollectorOptions
{
    /// <summary>Carpetas raíz a vigilar (p. ej. D:\Apps). Vacío = no se vigila nada.</summary>
    public List<string> Roots { get; set; } = new();
    /// <summary>Patrones de archivo relevantes (SEC-006). Vacío = valores por defecto (el binder de configuración añade, no reemplaza, listas prellenadas).</summary>
    public List<string> Include { get; set; } = new();
    /// <summary>Carpetas que se ignoran. Vacío = valores por defecto.</summary>
    public List<string> ExcludeDirs { get; set; } = new();

    public static readonly string[] DefaultInclude = { "web.config", "appsettings*.json", "*.dll", "*.exe", "*.config" };
    public static readonly string[] DefaultExcludeDirs = { "logs", "log", "temp", "tmp", "data", ".git", "obj", "node_modules", "App_Data" };
    public IReadOnlyList<string> EffectiveInclude => Include.Count > 0 ? Include : DefaultInclude.ToList();
    public IReadOnlyList<string> EffectiveExcludeDirs => ExcludeDirs.Count > 0 ? ExcludeDirs : DefaultExcludeDirs.ToList();
    public TimeSpan Debounce { get; set; } = TimeSpan.FromSeconds(2);
    public int MaxQueued { get; set; } = 10_000;
}

/// <summary>
/// Vigila cambios en archivos con FileSystemWatcher y los entrega como eventos (fuente "fs").
/// Si el búfer del SO se desborda o la cola local se llena emite "fs.overflow": se perdió visibilidad y una regla debe alertarlo.
/// </summary>
public sealed class FileChangeCollector : ICollector, IDisposable
{
    private readonly FileChangeCollectorOptions _opt;
    private readonly TimeProvider _time;
    private readonly ILogger? _log;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentQueue<SecurityEvent> _queue = new();
    private readonly ConcurrentDictionary<(string, string), DateTimeOffset> _last = new();
    private long _seq;

    public FileChangeCollector(FileChangeCollectorOptions options, TimeProvider? time = null, ILogger? log = null, Action<string, string?>? report = null)
    {
        _opt = options;
        _time = time ?? TimeProvider.System;
        _log = log;
        foreach (var root in options.Roots)
        {
            if (!Directory.Exists(root))
            {
                report?.Invoke("fs:" + root, "la carpeta no existe: no se vigila");
                log?.LogWarning("La carpeta vigilada {Root} no existe", root);
                continue;
            }
            try
            {
                var w = new FileSystemWatcher(root)
                {
                    IncludeSubdirectories = true,
                    InternalBufferSize = 64 * 1024,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                };
                w.Created += (_, e) => Enqueue("file.created", e.FullPath, null);
                w.Changed += (_, e) => Enqueue("file.changed", e.FullPath, null);
                w.Deleted += (_, e) => Enqueue("file.deleted", e.FullPath, null);
                w.Renamed += (_, e) => Enqueue("file.renamed", e.FullPath, "from " + e.OldFullPath);
                w.Error += (_, e) => { Enqueue("fs.overflow", root, e.GetException().Message); report?.Invoke("fs:" + root, "error del vigilante: " + e.GetException().Message); };
                w.EnableRaisingEvents = true;
                _watchers.Add(w);
                report?.Invoke("fs:" + root, null);
                log?.LogInformation("Vigilando cambios de archivos en {Root}", root);
            }
            catch (Exception e) when (e is ArgumentException or IOException or UnauthorizedAccessException or PlatformNotSupportedException)
            {
                report?.Invoke("fs:" + root, $"no se puede vigilar: {e.GetType().Name}: {e.Message}");
                log?.LogWarning(e, "No se puede vigilar {Root}", root);
            }
        }
    }

    public string Name => "fs";

    /// <summary>¿Es una ruta que interesa vigilar? (pura, probada aparte).</summary>
    public bool ShouldTrack(string fullPath)
    {
        // Las exclusiones se aplican a la ruta relativa a la raíz vigilada (que /tmp o D:\data en la raíz no excluyan todo).
        var path = fullPath;
        var root = _opt.Roots.FirstOrDefault(r => fullPath.StartsWith(r.TrimEnd('/', '\\') + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                                                  || fullPath.StartsWith(r.TrimEnd('/', '\\') + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
        if (root != null) path = fullPath[root.TrimEnd('/', '\\').Length..];
        var dirs = (Path.GetDirectoryName(path) ?? "").Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (dirs.Any(d => _opt.EffectiveExcludeDirs.Contains(d, StringComparer.OrdinalIgnoreCase))) return false;
        var name = Path.GetFileName(fullPath);
        return _opt.EffectiveInclude.Any(p => Matches(p, name));
    }

    private static bool Matches(string pattern, string name)
    {
        if (!pattern.Contains('*')) return name.Equals(pattern, StringComparison.OrdinalIgnoreCase);
        var parts = pattern.Split('*');
        var idx = 0;
        for (var i = 0; i < parts.Length; i++)
        {
            if (parts[i].Length == 0) continue;
            var found = name.IndexOf(parts[i], idx, StringComparison.OrdinalIgnoreCase);
            if (found < 0 || (i == 0 && found != 0)) return false;
            idx = found + parts[i].Length;
        }
        return parts[^1].Length == 0 || name.EndsWith(parts[^1], StringComparison.OrdinalIgnoreCase);
    }

    private void Enqueue(string type, string path, string? detail)
    {
        var overflow = type == "fs.overflow";
        if (!overflow && !ShouldTrack(path)) return;
        var now = _time.GetUtcNow();
        if (!overflow)
        {
            if (_last.TryGetValue((type, path), out var prev) && now - prev < _opt.Debounce) return;   // ráfagas de un mismo guardado
            _last[(type, path)] = now;
            if (_last.Count > 50_000) _last.Clear();
        }
        if (_queue.Count >= _opt.MaxQueued)
        {
            _log?.LogWarning("Cola de cambios de archivos llena; se descarta {Type} {Path}", type, path);
            return;
        }
        _queue.Enqueue(new SecurityEvent($"fs-{now.ToUnixTimeMilliseconds()}-{Interlocked.Increment(ref _seq)}", now, "fs", type,
            overflow ? Severity.Alta : Severity.Info, null, null, path, detail));
    }

    public Task<CollectorBatch> PollAsync(CancellationToken ct = default)
    {
        var events = new List<SecurityEvent>();
        while (events.Count < 5000 && _queue.TryDequeue(out var ev)) events.Add(ev);
        return Task.FromResult(new CollectorBatch(events, () => { }));   // la cola es en memoria: nada que confirmar
    }

    public void Dispose() { foreach (var w in _watchers) w.Dispose(); }
}
