using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Tests;

/// <summary>Correções do que a sessão 2 do laboratório mostrou (relatorio-2026-11-17-m3-sessao-2.md), no agente.</summary>
public class LabSession2AgentTests
{
    private static readonly DateTime T0 = new(2026, 11, 17, 1, 33, 44, DateTimeKind.Utc);

    // ── L2b: auditoria desligada só é adulteração se o agente já a viu ligada ──────────────────────

    [Fact]
    public void Auditoria_desligada_na_primeira_vez_e_o_padrao_do_Windows_repara_sem_alarme()
    {
        var plan = VisibilityGuard.Evaluate(false, 1L << 30, autoRepair: true, "rg-fs1", T0, shareAuditSeenOnBefore: false);

        Assert.Contains(RepairAction.EnableDetailedFileShareAudit, plan.Repairs);
        Assert.Empty(plan.Signals);
    }

    [Fact]
    public void Auditoria_que_ja_esteve_ligada_e_agora_esta_desligada_e_adulteracao()
    {
        var plan = VisibilityGuard.Evaluate(false, 1L << 30, autoRepair: true, "rg-fs1", T0, shareAuditSeenOnBefore: true);

        Assert.Contains(RepairAction.EnableDetailedFileShareAudit, plan.Repairs);
        Assert.Equal(HostSignalKind.AuditDisabled, Assert.Single(plan.Signals).Kind);
    }

    /// <summary>
    /// L13 — a checagem passa a rodar a cada minuto. Com o reparo falhando (sem direito, por exemplo), o mesmo alarme
    /// não pode sair a cada minuto: sai na transição de ligada para desligada, e de novo só depois que voltar a ligar.
    /// </summary>
    [Fact]
    public void O_alarme_de_auditoria_desligada_sai_uma_vez_por_transicao()
    {
        var state = new VisibilityState(seenOn: true);

        Assert.True(state.ShouldAlert(auditOn: false));
        Assert.False(state.ShouldAlert(auditOn: false));
        Assert.False(state.ShouldAlert(auditOn: true));
        Assert.True(state.SeenOn);
        Assert.True(state.ShouldAlert(auditOn: false));
    }

    [Fact]
    public void Sem_ter_visto_ligada_nao_ha_alarme_e_ver_ligada_uma_vez_fica_registrado()
    {
        var state = new VisibilityState(seenOn: false);

        Assert.False(state.ShouldAlert(auditOn: false));
        Assert.False(state.ShouldAlert(auditOn: true));
        Assert.True(state.SeenOn);
        Assert.True(state.ShouldAlert(auditOn: false));
    }

    // ── L11: o evento de objeto do sistema servindo SMB é acesso pela rede ──────────────────────────

    private sealed class Log : ISecurityLogSource
    {
        public readonly SortedDictionary<long, string> Records = new();
        public long? NewestRecordId() => Records.Count == 0 ? null : Records.Keys.Max();
        public IEnumerable<SecurityLogRecord> ReadAfter(long recordId, int max) =>
            Records.Where(r => r.Key > recordId).Take(max).Select(r => new SecurityLogRecord(r.Key, r.Value)).ToList();
    }

    private sealed class Memory : ICursorStore
    {
        public string? Content = "0";
        public string? Read() => Content;
        public void Write(string content) => Content = content;
    }

    private static string Xml5145(string target) => $"""
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System><EventID>5145</EventID><TimeCreated SystemTime='2026-11-17T01:33:44.100000000Z'/><Computer>rg-fs1.lab.ransomguard.test</Computer></System>
          <EventData>
            <Data Name='SubjectUserName'>bruno</Data><Data Name='SubjectDomainName'>RGLAB</Data>
            <Data Name='IpAddress'>10.88.1.40</Data><Data Name='ShareName'>\\*\Dados</Data>
            <Data Name='ShareLocalPath'>\??\C:\Shares\Dados</Data>
            <Data Name='RelativeTargetName'>{target}</Data><Data Name='AccessList'>%%4417</Data>
          </EventData>
        </Event>
        """;

    private static string Xml4663System(string obj) => $"""
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System><EventID>4663</EventID><TimeCreated SystemTime='2026-11-17T01:33:44.200000000Z'/><Computer>rg-fs1.lab.ransomguard.test</Computer></System>
          <EventData>
            <Data Name='SubjectUserName'>bruno</Data><Data Name='SubjectDomainName'>RGLAB</Data>
            <Data Name='ObjectName'>{obj}</Data><Data Name='AccessList'>%%4417</Data>
            <Data Name='ProcessId'>0x4</Data><Data Name='ProcessName'></Data>
          </EventData>
        </Event>
        """;

    private static SecurityLogCollector Collector(Log log, IReadOnlyList<SmbSession>? sessions = null) =>
        new(log, new EventCursor(new Memory()), () => new ShareMap("rg-fs1", new[] { new ShareEntry("Dados", @"C:\Shares\Dados") }),
            () => sessions ?? Array.Empty<SmbSession>(), new HostSignalBuffer());

    /// <summary>
    /// No laboratório, o acesso pela rede ao canário (que tem regra de auditoria) gerou também o evento de objeto, com
    /// o processo "System" (PID 4) — e o agente o leu como ataque de dentro do servidor: um segundo incidente, sem IP,
    /// tentando encerrar processo. As sessões SMB já tinham caído com a contenção.
    /// </summary>
    [Fact]
    public void Evento_de_objeto_do_sistema_herda_o_ip_do_acesso_pela_rede_do_mesmo_usuario()
    {
        var log = new Log();
        log.Records[1] = Xml5145(@"b4\documento_0001.docx");
        log.Records[2] = Xml4663System(@"C:\Shares\Dados\b4\!Indice 2021.xlsx");

        var events = Collector(log).Drain();

        Assert.All(events, e => Assert.Equal("10.88.1.40", e.SourceIp));
        var objectEvent = Assert.Single(events, e => e.Path.EndsWith("Indice 2021.xlsx"));
        Assert.Null(objectEvent.ProcessId);                     // "System" não é processo a encerrar
        Assert.Null(objectEvent.ProcessName);
    }

    [Fact]
    public void Sem_acesso_pela_rede_no_ciclo_e_sem_sessao_o_evento_do_sistema_fica_sem_processo_a_encerrar()
    {
        var log = new Log();
        log.Records[1] = Xml4663System(@"C:\Shares\Dados\b4\!Indice 2021.xlsx");

        var e = Assert.Single(Collector(log).Drain());

        Assert.Equal(SecurityEventParser.LocalOrigin, e.SourceIp);
        Assert.Null(e.ProcessId);
        var detection = new DetectionEngine().Analyze(new[] { e with { IsCanary = true } }).Single();
        Assert.Null(detection.Processes);
    }

    // ── L10: a atualização do próprio produto não é "serviço novo instalado" ────────────────────────

    private static string Xml7045(string name, string image) =>
        "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>7045</EventID>" +
        "<TimeCreated SystemTime=\"2026-11-17T00:17:34Z\"/><Computer>rg-fs1.lab.ransomguard.test</Computer></System><EventData>" +
        $"<Data Name=\"ServiceName\">{name}</Data><Data Name=\"ImagePath\">{System.Security.SecurityElement.Escape(image)}</Data></EventData></Event>";

    [Fact]
    public void Instalar_o_proprio_agente_na_pasta_do_produto_nao_e_sinal()
    {
        Assert.Null(PreEncryptionEventParser.Parse(Xml7045("RansomGuardAgent", @"""C:\Program Files\RansomGuard\Agente\RansomGuard.Agent.Service.exe""")));
        Assert.Null(PreEncryptionEventParser.Parse(Xml7045("RansomGuard Agent", @"C:\Program Files\RansomGuard\Agente\RansomGuard.Agent.Service.exe")));
    }

    [Theory]
    [InlineData("RansomGuardAgent", @"C:\Users\Public\RansomGuard.Agent.Service.exe")]     // nome do produto, lugar errado
    [InlineData("Atualizador", @"C:\Program Files\RansomGuard\Agente\atualizador.exe")]     // pasta do produto, outro programa
    [InlineData("PSEXESVC", @"%SystemRoot%\PSEXESVC.exe")]
    public void Outro_servico_continua_sendo_sinal(string name, string image)
        => Assert.Equal(HostSignalKind.ServiceInstalled, PreEncryptionEventParser.Parse(Xml7045(name, image))!.Kind);
}
