using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using RansomGuard.Agent.Posture;
using RansomGuard.Agent.Protection;
using RansomGuard.Agent.Sensors;

namespace RansomGuard.Agent.Service.Windows;

/// <summary>
/// Autodiagnóstico do agente: <c>RansomGuard.Agent.Service.exe --diagnostico</c>.
///
/// Existe por dois motivos.
///
/// Para o **tester**, responde a pergunta que ele fará primeiro: "instalei e não vejo nada — está
/// quebrado?". Quase sempre não está: falta auditoria ligada ou privilégio de leitura do Security
/// log. Sem esta tela ele desinstala achando que o produto não funciona.
///
/// Para **nós**, é a única forma de provar em máquina real que o coletor lê o log — o teste
/// automatizado roda sem elevação e o Security log exige privilégio.
///
/// Não altera nada no sistema: só lê e relata.
/// </summary>
[SupportedOSPlatform("windows")]
public static class Diagnostico
{
    /// <returns>0 quando o agente consegue enxergar; 1 quando algo o impede.</returns>
    public static int Executar(ProtectedPathSet paths)
    {
        var protectedPaths = paths.Accepted;

        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("RansomGuard · diagnóstico do agente");
        Console.WriteLine(new string('─', 66));

        var impedimentos = new List<string>();

        // ── 1. Elevação ─────────────────────────────────────────────────────────────────────
        var elevado = EstaElevado();
        Relatar("Executando como administrador", elevado,
            elevado ? "sim" : "NÃO — rode este diagnóstico elevado; o serviço roda como LocalSystem");

        // ── 2. Leitura do Security log ──────────────────────────────────────────────────────
        var (podeLer, detalheLeitura) = TentarLerSecurityLog();
        Relatar("Consegue ler o Security log", podeLer, detalheLeitura);
        if (!podeLer)
            impedimentos.Add("Sem acesso ao Security log — o agente fica CEGO. " +
                             "Rode o serviço como LocalSystem ou conceda leitura do log de segurança.");

        // ── 3. Auditoria ligada ─────────────────────────────────────────────────────────────
        // Duas subcategorias, e a diferença entre elas decide se o produto enxerga ou não:
        //   Detailed File Share → 5145, um evento por ARQUIVO, com IP de origem  ← o que importa
        //   File Share          → 5140, um evento por CONEXÃO ao share            ← não serve
        // Cem mil arquivos cifrados numa única sessão produzem um só 5140.
        var detalhado = LerAuditoria(AuditSubcategory.DetailedFileShare);
        Relatar($"Auditoria '{AuditSubcategory.DetailedFileShare.English}' (evento 5145)", detalhado == true,
            detalhado switch
            {
                true => "sim — é esta que faz o produto enxergar acesso a arquivo pela rede",
                false => "NÃO — sem ela o Windows não emite o 5145, e o agente fica cego",
                null => "não foi possível verificar (precisa de elevação)"
            });
        if (detalhado == false)
            impedimentos.Add($"Ligue a auditoria certa: {AuditSubcategory.DetailedFileShare.EnableCommand}");

        // Informativo: útil para o admin entender por que ligar só esta não bastou.
        var porConexao = LerAuditoria(AuditSubcategory.FileShare);
        if (porConexao == true && detalhado != true)
            Console.WriteLine("           Obs.: 'File Share' está ligada, mas ela gera o 5140 " +
                              "(um por conexão) — não serve para detectar criptografia em massa.");

        // 4663 depende TAMBÉM de SACL na pasta; por isso é complementar, não substituto.
        var fileSystem = LerAuditoria(AuditSubcategory.FileSystem);
        Relatar($"Auditoria '{AuditSubcategory.FileSystem.English}' (evento 4663)", fileSystem == true,
            fileSystem switch
            {
                true => "sim (o 4663 ainda exige SACL nas pastas protegidas)",
                false => "não — opcional nesta fase; complementa o 5145 para acesso local",
                null => "não foi possível verificar"
            });

        // ── 4. Eventos realmente chegando ───────────────────────────────────────────────────
        if (podeLer)
        {
            var (qtd, exemplo) = ContarEventosRecentes();
            Relatar("Eventos 4663/5145 presentes no log", qtd > 0,
                qtd > 0 ? $"{qtd} encontrado(s); último: {exemplo}"
                        : "nenhum — auditoria pode estar desligada ou não houve acesso ainda");
            if (qtd == 0)
                impedimentos.Add("Nenhum evento de acesso a arquivo no log. Confira a auditoria e " +
                                 "a SACL das pastas protegidas.");
        }

        // ── 5. Pastas protegidas ────────────────────────────────────────────────────────────
        // Existência é checada aqui, e não na validação de formato: um caminho bem escrito que não
        // existe (typo, volume não montado) passaria como "configurado" e o admin acharia que
        // aquela pasta está protegida.
        var existentes = protectedPaths.Where(Directory.Exists).ToList();
        var ausentes = protectedPaths.Where(p => !Directory.Exists(p)).ToList();

        Relatar("Pastas protegidas configuradas", existentes.Count > 0,
            protectedPaths.Count > 0
                ? string.Join(", ", protectedPaths)
                : "nenhuma — defina PROTECTEDPATHS na instalação ou Agent:ProtectedPaths no registro");
        if (protectedPaths.Count == 0)
            impedimentos.Add("Sem pastas protegidas, o produto não sabe onde plantar canário nem o " +
                             "que vigiar de perto.");

        foreach (var p in ausentes)
        {
            Console.WriteLine($"  [AVISO] Pasta configurada não existe: {p}");
            impedimentos.Add($"A pasta {p} não existe — confira o caminho ou monte o volume.");
        }

        // Caminho recusado precisa aparecer: o admin configurou algo que o produto ignorou.
        foreach (var r in paths.Rejected)
        {
            Console.WriteLine($"  [AVISO] Caminho recusado: {r.Path}\n           {r.Reason}");
            impedimentos.Add($"Caminho recusado ({r.Path}): {r.Reason}");
        }

        // ── 6. Canários e modo de proteção efetivo ──────────────────────────────────────────
        if (existentes.Count > 0)
        {
            // B4: os nomes desta instalação vêm do manifesto (se já existe); sem ele valem os de versões anteriores.
            var nomesDaInstalacao = CanaryManifest.RecognizeExisting(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RansomGuard"));
            var canarios = CanaryPresence.Evaluate(existentes, ListarArquivos, nomesDaInstalacao);
            Relatar("Canários plantados", canarios == true,
                canarios switch
                {
                    true => "sim",
                    false => "ainda não — o agente planta na partida e reaplica de hora em hora",
                    null => "não foi possível verificar (pasta inacessível)"
                });

            var fsrm = FsrmDisponivel();
            Relatar("FSRM disponível neste servidor", fsrm,
                fsrm ? "sim — extensões do catálogo podem ser bloqueadas no file screen"
                     : "não (Windows client ou role de File Server ausente) — a proteção degrada " +
                       "para canário + volume, e o painel diz isso");

            var status = ProtectionStatus.Evaluate(
                existentes.Count,
                canarios == true ? existentes.Count * 6 : 0,
                fsrm, fsrmActive: false);

            Console.WriteLine($"\n  Modo de proteção efetivo: {status.Mode}");
            Console.WriteLine($"  {status.Explanation}");
        }

        // ── Conclusão ───────────────────────────────────────────────────────────────────────
        Console.WriteLine("\n" + new string('─', 66));
        if (impedimentos.Count == 0)
        {
            Console.WriteLine("VERDE — o agente consegue enxergar este servidor.");
            return 0;
        }

        Console.WriteLine("ATENÇÃO — o agente NÃO vai detectar nada enquanto isto não for resolvido:\n");
        foreach (var i in impedimentos) Console.WriteLine($"  • {i}");
        Console.WriteLine("\nEnquanto isso o painel mostra o servidor como calmo — e calmaria sem");
        Console.WriteLine("visibilidade não é segurança.");
        return 1;
    }

    private static void Relatar(string item, bool ok, string detalhe)
        => Console.WriteLine($"  [{(ok ? " OK " : "AVISO")}] {item}\n           {detalhe}");

    private static bool EstaElevado()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception) { return false; }
    }

    private static (bool Ok, string Detalhe) TentarLerSecurityLog()
    {
        try
        {
            var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName));
            using var primeiro = reader.ReadEvent();
            return (true, primeiro is null ? "sim (log vazio)" : "sim");
        }
        catch (UnauthorizedAccessException)
        {
            return (false, "NÃO — privilégio insuficiente para ler o log de segurança");
        }
        catch (Exception ex)
        {
            return (false, $"NÃO — {ex.Message}");
        }
    }

    private static bool? LerAuditoria(AuditSubcategory sub) => WindowsAudit.IsSuccessEnabled(sub);

    private static (int Qtd, string Exemplo) ContarEventosRecentes()
    {
        try
        {
            var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName,
                "*[System[(EventID=4663 or EventID=5145)]]"));

            var qtd = 0;
            string exemplo = "-";
            for (var rec = reader.ReadEvent(); rec is not null && qtd < 50; rec = reader.ReadEvent())
            {
                using (rec)
                {
                    qtd++;
                    var e = SecurityEventParser.Parse(rec.ToXml());
                    if (e is not null) exemplo = $"{e.Op} em '{e.Path}' por {e.User} ({e.SourceIp})";
                }
            }
            return (qtd, exemplo);
        }
        catch (Exception ex)
        {
            return (0, ex.Message);
        }
    }

    private static bool FsrmDisponivel()
    {
        try
        {
            return PowerShellRunner.Run("[bool](Get-Command Get-FsrmFileGroup -ErrorAction SilentlyContinue)")
                .Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception) { return false; }
    }

    private static IReadOnlyList<string> ListarArquivos(string path) =>
        Directory.EnumerateFiles(path).Select(Path.GetFileName).OfType<string>().ToList();
}
