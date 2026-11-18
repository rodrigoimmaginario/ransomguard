using System.Diagnostics;
using System.Runtime.Versioning;
using RansomGuard.Agent.Posture;
using RansomGuard.Agent.Sensors;
using RansomGuard.Agent.Service.Windows;

namespace RansomGuard.Agent.Service.Tests;

/// <summary>Cursor em memória: cada teste começa como um agente recém-instalado.</summary>
internal sealed class MemoryCursorStore : ICursorStore
{
    public string? Content;
    public string? Read() => Content;
    public void Write(string content) => Content = content;
}

/// <summary>Executa um utilitário do Windows e devolve a saída; falha com a mensagem do próprio utilitário.</summary>
internal static class Tool
{
    public static string Run(string file, string arguments)
    {
        var psi = new ProcessStartInfo(file, arguments)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"não iniciou: {file}");
        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit(60_000);
        if (p.ExitCode != 0) throw new InvalidOperationException($"{file} {arguments} → {p.ExitCode}: {stdout} {stderr}".Trim());
        return stdout;
    }
}

/// <summary>
/// Liga uma subcategoria de auditoria e a devolve ao estado anterior ao final — o teste não deixa a máquina de quem
/// o roda com a política alterada. Usa o MESMO código do produto (<see cref="WindowsAudit"/>): consulta e liga pelo
/// GUID, sem depender do idioma do Windows.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class AuditScope : IDisposable
{
    public static readonly AuditSubcategory DetailedFileShare = AuditSubcategory.DetailedFileShare;
    public static readonly AuditSubcategory FileSystem = AuditSubcategory.FileSystem;

    private readonly AuditSubcategory _subcategory;
    private readonly bool _wasEnabled;

    private AuditScope(AuditSubcategory subcategory, bool wasEnabled) { _subcategory = subcategory; _wasEnabled = wasEnabled; }

    public static AuditScope Enable(AuditSubcategory subcategory)
    {
        var bits = WindowsAudit.Query(subcategory, out var error)
                   ?? throw new InvalidOperationException($"não foi possível ler a auditoria {subcategory.English} (erro Win32 {error})");
        var before = AuditPolicyReader.IsSuccess(bits);
        WindowsAudit.EnableSuccess(subcategory);
        if (WindowsAudit.IsSuccessEnabled(subcategory) != true)
            throw new InvalidOperationException($"a auditoria {subcategory.English} não ficou ligada");
        return new AuditScope(subcategory, before);
    }

    public void Dispose()
    {
        if (_wasEnabled) return;   // já estava ligada antes do teste
        try { Tool.Run("auditpol.exe", $"/set /subcategory:{_subcategory.Guid} /success:disable"); } catch (Exception) { }
    }
}

/// <summary>Pasta temporária publicada como share SMB de verdade, removida ao final.</summary>
[SupportedOSPlatform("windows")]
internal sealed class TempShare : IDisposable
{
    public string Name { get; }
    public string LocalPath { get; }
    public string Unc => $@"\\localhost\{Name}";

    private TempShare(string name, string path) { Name = name; LocalPath = path; }

    public static TempShare Create()
    {
        var id = Guid.NewGuid().ToString("N")[..8];
        var name = "rgit" + id;
        // Na raiz do volume do sistema, não no TEMP: em alguns Windows o TEMP vem em nome curto (RUNNER~1) e o
        // evento de objeto usa o nome longo — isso mediria o nome curto, não o produto.
        var path = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory)!, "rg-it-" + id, "Financeiro");
        Directory.CreateDirectory(path);
        // "Todos" pelo SID bem conhecido: o nome da conta muda com o idioma do Windows.
        PowerShellRunner.Run(
            "$todos = (New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')).Translate([System.Security.Principal.NTAccount]).Value; " +
            $"New-SmbShare -Name '{name}' -Path '{path}' -FullAccess $todos -ErrorAction Stop | Out-Null");
        return new TempShare(name, path);
    }

    /// <summary>O mesmo diretório visto pelo share administrativo do volume (<c>\\localhost\C$\...</c>).</summary>
    public string AdminUnc => $@"\\localhost\{LocalPath[0]}$" + LocalPath[2..];

    public void Dispose()
    {
        try { PowerShellRunner.Run($"Remove-SmbShare -Name '{Name}' -Force -ErrorAction SilentlyContinue"); } catch (Exception) { }
        try { Directory.Delete(Path.GetDirectoryName(LocalPath)!, true); } catch (Exception) { }
    }
}

/// <summary>Grava o XML bruto dos eventos reais para virar fixture (artefato da CI).</summary>
[SupportedOSPlatform("windows")]
internal static class Fixtures
{
    public static void Dump(string scenario, long afterRecordId, params string[] mustContainAny)
    {
        var dir = Environment.GetEnvironmentVariable("RG_FIXTURE_DIR");
        if (string.IsNullOrWhiteSpace(dir)) return;
        Directory.CreateDirectory(dir);
        var n = 0;
        foreach (var rec in new WindowsSecurityLogSource().ReadAfter(afterRecordId, 5_000))
        {
            if (!mustContainAny.Any(m => rec.Xml.Contains(m, StringComparison.OrdinalIgnoreCase))) continue;
            File.WriteAllText(Path.Combine(dir, $"{scenario}-{++n:000}-{rec.RecordId}.xml"), rec.Xml);
            if (n >= 60) break;
        }
    }
}
