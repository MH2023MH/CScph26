using System.Text;
using SecurityAgent.Core.State;

namespace SecurityAgent.Collectors.Files;

public sealed record TailedLine(string Text, long Offset);

/// <summary>Resultado de una lectura: líneas completas nuevas y el cursor a confirmar cuando se hayan procesado.</summary>
public sealed record TailResult(IReadOnlyList<TailedLine> Lines, long NewOffset, string CursorKey);

/// <summary>
/// Lee solo las líneas nuevas de un archivo de log que otro proceso mantiene abierto (IIS, SQL Server).
/// Persiste el offset en el State Store, detecta truncado/rotación (archivo más corto que el offset) y nunca
/// entrega una línea incompleta. Soporta UTF-8 y UTF-16 (ERRORLOG de SQL Server).
/// </summary>
public sealed class LogTailer(IStateStore store, Encoding encoding, int maxBytesPerPoll = 4 * 1024 * 1024)
{
    public static string KeyFor(string path) => "tail:" + path;

    /// <param name="startAtEndIfNew">Sin cursor previo: true = ignorar el historial (empezar al final); false = leer desde el inicio.</param>
    public TailResult Read(string path, bool startAtEndIfNew)
    {
        var key = KeyFor(path);
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var length = fs.Length;
        var cursor = store.GetCursor(key);

        if (cursor is null)
        {
            if (startAtEndIfNew) return new TailResult(Array.Empty<TailedLine>(), length, key);
            cursor = 0;
        }
        var offset = cursor.Value;
        if (length < offset) offset = 0;                       // truncado o rotado: empezar de nuevo
        if (length == offset) return new TailResult(Array.Empty<TailedLine>(), offset, key);

        var preamble = encoding.GetPreamble();
        var start = offset;
        if (offset == 0 && preamble.Length > 0 && length >= preamble.Length)
        {
            var head = new byte[preamble.Length];
            fs.ReadExactly(head);
            if (head.AsSpan().SequenceEqual(preamble)) start = preamble.Length;
        }

        var toRead = (int)Math.Min(length - start, maxBytesPerPoll);
        var buffer = new byte[toRead];
        fs.Seek(start, SeekOrigin.Begin);
        var read = fs.Read(buffer, 0, toRead);
        // Se trabaja sobre BYTES: si se midiera el texto ya decodificado, cada byte inválido (U+FFFD ocupa 3 bytes en UTF-8)
        // desplazaría el cursor y se perderían o repetirían líneas. El salto de línea se busca alineado a su ancho
        // (1 byte en UTF-8, 2 en UTF-16), que es seguro porque ninguna secuencia multibyte lo contiene.
        var nl = encoding.GetBytes("\n");
        var lines = new List<TailedLine>();
        var segStart = 0;
        var completeBytes = 0;
        for (var i = 0; i + nl.Length <= read; i += nl.Length)
        {
            if (!buffer.AsSpan(i, nl.Length).SequenceEqual(nl)) continue;
            var line = encoding.GetString(buffer, segStart, i - segStart).TrimEnd('\r');
            if (line.Length > 0) lines.Add(new TailedLine(line, start + segStart));
            segStart = i + nl.Length;
            completeBytes = segStart;
        }

        if (completeBytes == 0)   // ninguna línea completa todavía
        {
            // Un "renglón" que llena todo el búfer sin salto de línea no es un log legítimo: se descarta para no quedar ciego en ese archivo.
            if (read >= maxBytesPerPoll) return new TailResult(Array.Empty<TailedLine>(), start + read - read % nl.Length, key);
            return new TailResult(Array.Empty<TailedLine>(), start == offset ? offset : start, key);
        }
        return new TailResult(lines, start + completeBytes, key);
    }

    public void Commit(TailResult result) => store.SetCursor(result.CursorKey, result.NewOffset);
}
