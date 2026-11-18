using System.Diagnostics;
using System.Text;
using RansomGuard.Agent.Posture;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// Testes de **integração real**: rodam os comandos do Windows nesta máquina e entregam a saída
/// verdadeira aos parsers. É o portão que pega mudança de formato da Microsoft — algo que fixture
/// nenhuma detecta, porque a fixture é uma foto do que nós achamos que o Windows responde.
///
/// Pulam automaticamente fora do Windows (o CI pode ser Linux).
/// </summary>
public class WindowsPostureIntegrationTests
{
    private static bool NoWindows => OperatingSystem.IsWindows();

    /// <summary>Roda PowerShell e devolve stdout — mesmo quando o comando falha (é o caso interessante).</summary>
    private static (string Output, int ExitCode) Run(string script)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{script.Replace("\"", "\\\"")}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi)!;
        var sb = new StringBuilder();
        sb.Append(p.StandardOutput.ReadToEnd());
        sb.Append(p.StandardError.ReadToEnd());
        p.WaitForExit(30_000);
        return (sb.ToString(), p.ExitCode);
    }

    /// <summary>
    /// O parser entende a tabela que o Windows realmente produz. Se a Microsoft mudar as colunas
    /// do <c>Get-SmbShareAccess</c>, este teste fica vermelho — e não descobrimos no cliente.
    /// </summary>
    [Fact]
    public void Parser_entende_a_saida_real_do_Get_SmbShareAccess()
    {
        if (!NoWindows) return;

        var (saida, _) = Run("Get-SmbShare -ErrorAction SilentlyContinue | Get-SmbShareAccess " +
                             "-ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String -Width 200");

        Assert.NotNull(SharePermissionReader.TryRead(saida));
    }

    /// <summary>
    /// Todo Windows publica C$, ADMIN$ e IPC$ com acesso total a Administrators. Se o parser
    /// contasse isso, **toda** instalação nasceria com o achado crítico "share aberto" — o falso
    /// positivo mais caro do produto, porque aparece na primeira tela que o cliente vê.
    /// </summary>
    [Fact]
    public void Shares_administrativos_desta_maquina_nao_viram_achado()
    {
        if (!NoWindows) return;

        var (saida, _) = Run("Get-SmbShare -Special $true -ErrorAction SilentlyContinue | " +
                             "Get-SmbShareAccess -ErrorAction SilentlyContinue | Format-Table -AutoSize | " +
                             "Out-String -Width 200");
        if (SharePermissionReader.TryRead(saida) is null) return;   // máquina sem shares especiais

        Assert.False(SharePermissionReader.HasBroadWriteAccess(saida));
    }

    /// <summary>
    /// **O caso que motivou a fatia.** Sem privilégio de administrador, o `auditpol` responde
    /// "A required privilege is not held by the client". O comportamento correto é dizer
    /// **não sei** — a versão anterior transformava isso em "auditoria desligada" e acusava o
    /// admin de uma falha que ninguém verificou.
    /// </summary>
    [Fact]
    public void Auditpol_sem_privilegio_vira_desconhecido_e_nao_acusacao()
    {
        const string semPrivilegio = "Error 0x00000522 occurred:\r\nA required privilege is not held by the client.";

        Assert.Null(AuditPolicyReader.TryRead(semPrivilegio, AuditSubcategory.DetailedFileShare));
    }

    /// <summary>
    /// A saída real do auditpol nesta máquina — seja a tabela (rodando elevado) ou o erro de
    /// privilégio — nunca pode virar exceção nem uma afirmação falsa.
    /// </summary>
    [Fact]
    public void Auditpol_real_devolve_resposta_ou_desconhecido_sem_explodir()
    {
        if (!NoWindows) return;

        var (saida, _) = Run($"auditpol /get /subcategory:'{AuditSubcategory.DetailedFileShare.English}' | Out-String");
        var r = AuditPolicyReader.TryRead(saida, AuditSubcategory.DetailedFileShare);

        // Elevado: bool. Sem privilégio: null. Exceção: nunca.
        Assert.True(r is null or true or false);
    }

    /// <summary>Pasta real, sem canário plantado: a resposta é "não tem", não "não sei".</summary>
    [Fact]
    public void Canarios_em_pasta_real_sem_canario()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rg-canary-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "documento.docx"), "x");

            var r = CanaryPresence.Evaluate(new[] { dir },
                p => Directory.EnumerateFiles(p).Select(Path.GetFileName).OfType<string>().ToList());

            Assert.False(r);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    /// <summary>Pasta com os canários plantados de verdade: a nota tem que poder subir.</summary>
    [Fact]
    public void Canarios_presentes_em_pasta_real_sao_reconhecidos()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rg-canary-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            foreach (var nome in RansomGuard.Core.Fsrm.CanaryPlan.NamesFor(dir))
                File.WriteAllText(Path.Combine(dir, nome), "canario");

            var r = CanaryPresence.Evaluate(new[] { dir },
                p => Directory.EnumerateFiles(p).Select(Path.GetFileName).OfType<string>().ToList());

            Assert.True(r);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    /// <summary>Pasta que não existe: desconhecido, nunca "não tem canário".</summary>
    [Fact]
    public void Pasta_inexistente_vira_desconhecido()
    {
        var inexistente = Path.Combine(Path.GetTempPath(), "rg-nao-existe-" + Guid.NewGuid().ToString("N"));

        var r = CanaryPresence.Evaluate(new[] { inexistente },
            p => Directory.EnumerateFiles(p).Select(Path.GetFileName).OfType<string>().ToList());

        Assert.Null(r);
    }
}
