namespace SecurityAgent.Core;

/// <summary>
/// Ruta completa de las herramientas del sistema (netsh, auditpol). Con un nombre relativo Windows busca primero en el directorio
/// de la aplicación y en el PATH, y un binario plantado ahí se ejecutaría con los privilegios del servicio.
/// </summary>
public static class SystemTools
{
    public static string Path(string exe)
    {
        var dir = Environment.SystemDirectory;       // C:\Windows\System32 (vacío fuera de Windows)
        if (string.IsNullOrEmpty(dir)) return exe;
        var full = System.IO.Path.Combine(dir, exe);
        return File.Exists(full) ? full : exe;
    }
}
