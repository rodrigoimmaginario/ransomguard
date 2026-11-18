using System.Diagnostics;
using System.Text;

namespace RansomGuard.Agent.Service.Windows;

/// <summary>
/// Executa um comando PowerShell e devolve a saída. É a ponte fina do serviço para os primitivos
/// nativos (FSRM, Get-SmbSession, VSS, firewall, AD). Mantido isolado para o resto do serviço
/// permanecer testável e agnóstico.
///
/// Dois modos:
/// <list type="bullet">
///   <item><see cref="Run"/> — leitura tolerante (postura, consultas): só falha quando o PowerShell sai com erro e mensagem.</item>
///   <item><see cref="RunStrict"/> — ações (contenção): qualquer erro interrompe o script e vira exceção, com a mensagem
///   limpa. Uma ação que "não estourou" não é uma ação que deu certo.</item>
/// </list>
/// </summary>
public static class PowerShellRunner
{
    /// <summary>Caminho absoluto: o serviço roda como SYSTEM e não deve depender do PATH para achar o interpretador.</summary>
    private static readonly string Exe =
        Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");

    private const string ErrorMarker = "RG-ERRO: ";

    public static string Run(string script, TimeSpan? timeout = null) => Execute(script, timeout, strict: false);

    /// <summary>
    /// Roda em modo estrito: erro não terminante também interrompe; a saída de erro é uma linha só, com a mensagem da
    /// exceção. Lança <see cref="InvalidOperationException"/> sempre que o script não termina com sucesso.
    /// </summary>
    public static string RunStrict(string script, TimeSpan? timeout = null) =>
        Execute("$ErrorActionPreference = 'Stop'; try { " + script +
                " } catch { [Console]::Error.WriteLine('" + ErrorMarker + "' + $_.Exception.Message); exit 1 }",
            timeout, strict: true);

    /// <summary>
    /// L1 (laboratório, sessão 1) — roda o script a partir de um ARQUIVO, e não da linha de comando.
    ///
    /// O script do file screen leva a lista de extensões e de nomes de nota de ransomware. Passado em <c>-Command</c>,
    /// o antivírus do Windows classificou a linha de comando do próprio agente como ransomware
    /// (<c>Ransom:PowerShell/FileFix</c>) e impediu o processo de nascer: nenhum file screen era aplicado em servidor
    /// com o antivírus padrão ligado. A resposta nunca é pedir uma exclusão no antivírus.
    ///
    /// O arquivo é gravado numa pasta que só SYSTEM e administradores alcançam (é executado como SYSTEM), com BOM —
    /// o PowerShell 5.1 lê UTF-8 sem BOM como ANSI — e apagado ao terminar.
    /// </summary>
    public static string RunScriptFile(string script, TimeSpan? timeout = null, string? directory = null)
    {
        var dir = directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RansomGuard", "run");
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "rg-" + Guid.NewGuid().ToString("N")[..12] + ".ps1");
        File.WriteAllText(file, script, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        try { return Start($"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{file}\"", timeout, strict: false); }
        finally { try { File.Delete(file); } catch (Exception) { /* fica para a próxima limpeza */ } }
    }

    private static string Execute(string script, TimeSpan? timeout, bool strict) =>
        Start($"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{script.Replace("\"", "\\\"")}\"", timeout, strict);

    private static string Start(string arguments, TimeSpan? timeout, bool strict)
    {
        var psi = new ProcessStartInfo
        {
            FileName = File.Exists(Exe) ? Exe : "powershell.exe",
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Falha ao iniciar PowerShell.");
        var sb = new StringBuilder();
        p.OutputDataReceived += (_, e) => { if (e.Data is not null) sb.AppendLine(e.Data); };
        p.BeginOutputReadLine();
        var err = p.StandardError.ReadToEnd();
        if (!p.WaitForExit((int)(timeout ?? TimeSpan.FromSeconds(30)).TotalMilliseconds))
        {
            try { p.Kill(); } catch { /* ignore */ }
            throw new TimeoutException("PowerShell excedeu o tempo.");
        }
        p.WaitForExit();   // esvazia a leitura assíncrona da saída

        if (strict && p.ExitCode != 0)
            throw new InvalidOperationException(CleanError(err, p.ExitCode));
        if (p.ExitCode != 0 && err.Length > 0)
            throw new InvalidOperationException($"PowerShell falhou: {err.Trim()}");
        return sb.ToString();
    }

    /// <summary>A linha marcada pelo modo estrito, sem o rodapé de posição que o PowerShell acrescenta.</summary>
    private static string CleanError(string stderr, int exitCode)
    {
        foreach (var raw in stderr.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith(ErrorMarker, StringComparison.Ordinal)) return line[ErrorMarker.Length..].Trim();
        }
        var first = stderr.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0);
        return first ?? $"o PowerShell terminou com código {exitCode}";
    }
}

/// <summary>
/// Executa um utilitário do próprio Windows (<c>auditpol.exe</c>, <c>wevtutil.exe</c>) direto, sem passar pelo
/// PowerShell: mais barato, e os argumentos — como o GUID entre chaves de uma subcategoria — chegam como são.
/// </summary>
public static class NativeTool
{
    public static string Run(string file, string arguments, TimeSpan? timeout = null)
    {
        var path = Path.Combine(Environment.SystemDirectory, file);
        var psi = new ProcessStartInfo(File.Exists(path) ? path : file, arguments)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Falha ao iniciar {file}.");
        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();
        if (!p.WaitForExit((int)(timeout ?? TimeSpan.FromSeconds(30)).TotalMilliseconds))
        {
            try { p.Kill(); } catch { /* ignore */ }
            throw new TimeoutException($"{file} excedeu o tempo.");
        }
        if (p.ExitCode != 0)
            throw new InvalidOperationException($"{file} {arguments} terminou com código {p.ExitCode}: {(stderr.Length > 0 ? stderr : stdout).Trim()}");
        return stdout;
    }
}
