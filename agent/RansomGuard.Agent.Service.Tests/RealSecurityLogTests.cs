using System.Net;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using RansomGuard.Agent.Sensors;
using RansomGuard.Agent.Service.Windows;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Fsrm;
using Xunit.Abstractions;

namespace RansomGuard.Agent.Service.Tests;

/// <summary>
/// O coletor de PRODUÇÃO lendo o Security log de um Windows de verdade. É a primeira prova de que o que os
/// simuladores supõem sobre o Windows é o que o Windows entrega: um share SMB real, auditoria ligada, arquivos
/// gravados pela rede e localmente, e o evento que sai do outro lado.
///
/// Os testes compartilham auditoria e log da máquina, por isso rodam em série.
/// </summary>
[Collection("windows-real")]
[SupportedOSPlatform("windows")]
public sealed class RealSecurityLogTests(ITestOutputHelper output)
{
    private static readonly string Server = Environment.MachineName;

    private static (WindowsFileEventCollector Collector, MemoryCursorStore Cursor) NewAgent()
    {
        var cursor = new MemoryCursorStore();
        var collector = new WindowsFileEventCollector(
            NullLogger<WindowsFileEventCollector>.Instance,
            new EventCursor(cursor),
            shares: new WindowsShareTable(Server, TimeSpan.Zero).Current,
            readSessions: () => Array.Empty<SmbSession>());
        return (collector, cursor);
    }

    /// <summary>Drena até o predicado valer (o serviço de eventos grava com pequeno atraso) ou o prazo acabar.</summary>
    private static List<FileEvent> DrainUntil(WindowsFileEventCollector collector, Func<List<FileEvent>, bool> done, int seconds = 30)
    {
        var all = new List<FileEvent>();
        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < deadline)
        {
            all.AddRange(collector.Drain());
            if (collector.ConsecutiveFailures > 0) throw new InvalidOperationException("o coletor falhou ao ler o Security log");
            if (done(all)) break;
            Thread.Sleep(500);
        }
        return all;
    }

    private void Describe(IEnumerable<FileEvent> events)
    {
        foreach (var e in events)
            output.WriteLine($"{e.Op,-6} share={e.Share} path={e.Path} user={e.User} ip={e.SourceIp} canary={e.IsCanary} pid={e.ProcessId}");
    }

    /// <summary>
    /// Laboratório, sessão 3 — o critério que separa o ransomware que regrava no lugar de quem copia arquivos novos,
    /// conferido com o coletor de produção: arquivo antigo regravado pela rede sai marcado; arquivo novo, não.
    /// </summary>
    [ElevatedFact]
    public void Regravar_pela_rede_um_arquivo_antigo_e_marcado_e_criar_um_novo_nao()
    {
        using var audit = AuditScope.Enable(AuditScope.DetailedFileShare);
        using var share = TempShare.Create();
        var old = Path.Combine(share.LocalPath, "antigo.docx");
        File.WriteAllText(old, "conteúdo original");
        File.SetCreationTimeUtc(old, DateTime.UtcNow.AddDays(-30));
        var (collector, _) = NewAgent();
        Assert.Empty(collector.Drain());

        using (var stream = new FileStream(Path.Combine(share.Unc, "antigo.docx"), FileMode.Open, FileAccess.Write))
        {
            stream.SetLength(0);                                // como o provocador (e o ransomware) regrava no lugar
            stream.Write("cifrado"u8);
        }
        File.WriteAllText(Path.Combine(share.Unc, "novo.docx"), "arquivo novo");

        var events = DrainUntil(collector, all => all.Any(e => e.Path.Equals("novo.docx", StringComparison.OrdinalIgnoreCase) && e.Op == FileOp.Write));
        Describe(events);

        Assert.Contains(events, e => e.Path.Equals("antigo.docx", StringComparison.OrdinalIgnoreCase) && e.Op == FileOp.Write && e.Overwrite);
        Assert.DoesNotContain(events, e => e.Path.Equals("novo.docx", StringComparison.OrdinalIgnoreCase) && e.Overwrite);
    }

    [ElevatedFact]
    public void Escrita_pela_rede_vira_evento_com_share_canonico_usuario_e_caminho()
    {
        using var audit = AuditScope.Enable(AuditScope.DetailedFileShare);
        using var share = TempShare.Create();
        var canonical = $@"\\{Server}\{share.Name}";
        var (collector, cursor) = NewAgent();

        Assert.Empty(collector.Drain());                       // agente recém-instalado: parte de agora
        var baseline = long.Parse(cursor.Content!);
        Assert.Contains(WindowsShareTable.ReadRegistry(), s => s.Name == share.Name
            && s.LocalPath.Equals(share.LocalPath, StringComparison.OrdinalIgnoreCase));

        var canary = CanaryPlan.NamesFor(share.LocalPath)[0];
        Directory.CreateDirectory(Path.Combine(share.Unc, "2024"));
        File.WriteAllText(Path.Combine(share.Unc, "2024", "contrato.docx"), "conteúdo de teste");
        File.WriteAllText(Path.Combine(share.Unc, "planilha.xlsx.locked"), "conteúdo de teste");
        File.WriteAllText(Path.Combine(share.Unc, canary), "conteúdo de teste");
        File.WriteAllText(Path.Combine(share.AdminUnc, "via-admin.docx"), "conteúdo de teste");

        var events = DrainUntil(collector, all =>
            all.Any(e => e.Path.EndsWith("via-admin.docx", StringComparison.OrdinalIgnoreCase) && e.Op == FileOp.Write));
        Fixtures.Dump("rede", baseline, share.Name, share.LocalPath);
        var ours = events.Where(e => e.Share.Equals(canonical, StringComparison.OrdinalIgnoreCase)).ToList();
        Describe(ours);

        var contrato = ours.First(e => e.Path.Equals(@"2024\contrato.docx", StringComparison.OrdinalIgnoreCase) && e.Op == FileOp.Write);
        Assert.EndsWith("\\" + Environment.UserName, contrato.User, StringComparison.OrdinalIgnoreCase);
        Assert.True(contrato.SourceIp == SecurityEventParser.LocalOrigin || IPAddress.TryParse(contrato.SourceIp, out _),
            $"origem inesperada: {contrato.SourceIp}");
        Assert.Equal(".docx", contrato.NewExtension);

        Assert.Contains(ours, e => e.Path.Equals("planilha.xlsx.locked", StringComparison.OrdinalIgnoreCase) && e.NewExtension == ".locked");
        Assert.Contains(ours, e => e.IsCanary && e.Op == FileOp.Write);

        // Quem entra pelo share administrativo continua atingindo o MESMO share publicado.
        Assert.Contains(ours, e => e.Path.Equals("via-admin.docx", StringComparison.OrdinalIgnoreCase) && e.Op == FileOp.Write);
    }

    /// <summary>
    /// O que o Windows registra para cada operação feita pela rede. As afirmações abaixo são o que o motor de detecção
    /// pressupõe; a saída do teste (e o XML publicado como artefato) mostra o resto, para as próximas fatias.
    /// </summary>
    [ElevatedFact]
    public void Cada_operacao_pela_rede_e_registrada_como_o_motor_pressupoe()
    {
        using var audit = AuditScope.Enable(AuditScope.DetailedFileShare);
        using var share = TempShare.Create();
        var canonical = $@"\\{Server}\{share.Name}";
        foreach (var name in new[] { "existente.docx", "renomear.docx", "apagar.docx", "so-abrir.docx", "so-ler.docx" })
            File.WriteAllText(Path.Combine(share.LocalPath, name), "conteúdo inicial");   // local e antes da linha de base: não conta

        var (collector, cursor) = NewAgent();
        Assert.Empty(collector.Drain());
        var baseline = long.Parse(cursor.Content!);

        File.WriteAllText(Path.Combine(share.Unc, "existente.docx"), "sobrescrito pela rede");
        using (var stream = new FileStream(Path.Combine(share.Unc, "varias-gravacoes.bin"), FileMode.Create, FileAccess.Write))
            for (var i = 0; i < 20; i++) { stream.Write(new byte[4096]); stream.Flush(true); }
        File.Move(Path.Combine(share.Unc, "renomear.docx"), Path.Combine(share.Unc, "renomear.docx.locked"));
        File.Delete(Path.Combine(share.Unc, "apagar.docx"));
        using (File.Open(Path.Combine(share.Unc, "so-abrir.docx"), FileMode.Open, FileAccess.ReadWrite)) { }   // abre para escrita, não grava
        _ = File.ReadAllText(Path.Combine(share.Unc, "so-ler.docx"));
        File.WriteAllText(Path.Combine(share.Unc, "fim.docx"), "marcador de fim");

        var events = DrainUntil(collector, all => all.Any(e => e.Path.Equals("fim.docx", StringComparison.OrdinalIgnoreCase) && e.Op == FileOp.Write));
        Fixtures.Dump("operacoes", baseline, share.Name, share.LocalPath);
        var ours = events.Where(e => e.Share.Equals(canonical, StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var g in ours.GroupBy(e => e.Path, StringComparer.OrdinalIgnoreCase).OrderBy(g => g.Key))
            output.WriteLine($"{g.Key,-28} gravar={g.Count(e => e.Op == FileOp.Write)} apagar={g.Count(e => e.Op == FileOp.Delete)} ler={g.Count(e => e.Op == FileOp.Read)}");

        int Count(string path, FileOp op) => ours.Count(e => e.Path.Equals(path, StringComparison.OrdinalIgnoreCase) && e.Op == op);

        Assert.True(Count("existente.docx", FileOp.Write) >= 1, "sobrescrever um arquivo existente precisa aparecer como gravação");
        Assert.True(Count("varias-gravacoes.bin", FileOp.Write) >= 1, "gravar em várias chamadas precisa aparecer como gravação");
        Assert.True(Count("apagar.docx", FileOp.Delete) >= 1, "apagar precisa aparecer como exclusão");
        Assert.Equal(0, Count("so-ler.docx", FileOp.Write) + Count("so-ler.docx", FileOp.Delete));   // ler não é alterar
        Assert.True(Count("so-ler.docx", FileOp.Read) >= 1, "ler precisa aparecer como leitura");
    }

    [ElevatedFact]
    public void Escrita_local_auditada_traz_o_processo_e_cai_no_mesmo_share()
    {
        using var audit = AuditScope.Enable(AuditScope.FileSystem);
        using var share = TempShare.Create();
        var canonical = $@"\\{Server}\{share.Name}";

        // SACL: audita gravação e exclusão de qualquer conta, herdado pelos arquivos da pasta.
        var dir = new DirectoryInfo(share.LocalPath);
        var security = dir.GetAccessControl(AccessControlSections.Audit);
        security.AddAuditRule(new FileSystemAuditRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AuditFlags.Success));
        dir.SetAccessControl(security);

        var (collector, cursor) = NewAgent();
        Assert.Empty(collector.Drain());
        var baseline = long.Parse(cursor.Content!);

        Directory.CreateDirectory(Path.Combine(share.LocalPath, "2024"));
        File.WriteAllText(Path.Combine(share.LocalPath, "2024", "folha.xlsx"), "conteúdo de teste");
        File.WriteAllText(Path.Combine(share.Unc, "pela-rede.xlsx"), "conteúdo de teste");   // mesma pasta auditada, agora por SMB

        var events = DrainUntil(collector, all =>
            all.Any(e => e.Path.EndsWith("folha.xlsx", StringComparison.OrdinalIgnoreCase) && e.Op == FileOp.Write));
        Thread.Sleep(3000);                       // margem para um eventual evento de objeto da gravação por SMB
        events.AddRange(collector.Drain());
        Fixtures.Dump("local", baseline, share.LocalPath);
        var ours = events.Where(e => e.Share.Equals(canonical, StringComparison.OrdinalIgnoreCase)).ToList();
        Describe(ours);

        var folha = ours.First(e => e.Path.Equals(@"2024\folha.xlsx", StringComparison.OrdinalIgnoreCase) && e.Op == FileOp.Write);
        Assert.Equal(SecurityEventParser.LocalOrigin, folha.SourceIp);
        Assert.Equal(Environment.ProcessId, folha.ProcessId);
        Assert.False(string.IsNullOrWhiteSpace(folha.ProcessName));

        // Observado na CI (Windows Server 2025, SMB em loopback, 2026-11-16): a gravação feita por SMB na mesma pasta
        // auditada NÃO gerou evento de objeto — só a local gerou. Ou seja, o 4663 é o sensor de processo local, e o
        // acesso remoto depende do evento de share e do file screen. Se um dia aparecer, tem de ser do sistema (PID 4),
        // nunca um "processo local" a encerrar. Confirmar com cliente remoto de verdade no laboratório.
        var rede = events.Where(e => e.Path.EndsWith("pela-rede.xlsx", StringComparison.OrdinalIgnoreCase)).ToList();
        output.WriteLine($"eventos de objeto para a gravação por SMB: {rede.Count}");
        Assert.All(rede, e => Assert.True(e.ProcessId is null or <= 4, $"PID inesperado para gravação por SMB: {e.ProcessId} ({e.ProcessName})"));
    }

    [ElevatedFact]
    public void Copias_de_sombra_sao_contadas_sem_processo_auxiliar()
    {
        var count = WindowsShadowCopies.TryCount();

        output.WriteLine($"cópias de sombra: {count}");
        Assert.NotNull(count);
        Assert.True(count >= 0);
    }
}
