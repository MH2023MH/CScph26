namespace CScph26.Tests;

/// <summary>
/// Windows PowerShell 5.1 lee un .ps1 SIN BOM como ANSI (Windows-1252): los acentos y guiones largos se corrompen
/// y pueden romper el script. Todo .ps1 con caracteres no ASCII debe llevar BOM UTF-8.
/// </summary>
public class ScriptEncodingTests
{
    [Fact]
    public void Every_powershell_script_with_non_ascii_text_has_a_utf8_bom()
    {
        var scripts = Directory.GetFiles(Path.Combine(TestSupport.RepoRoot(), "deploy"), "*.ps1", SearchOption.AllDirectories);
        Assert.NotEmpty(scripts);
        foreach (var f in scripts)
        {
            var b = File.ReadAllBytes(f);
            var hasBom = b.Length >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF;
            var nonAscii = b.Any(x => x > 127);
            Assert.True(hasBom || !nonAscii, $"{Path.GetRelativePath(TestSupport.RepoRoot(), f)} tiene caracteres no ASCII y no lleva BOM UTF-8");
        }
    }
}
