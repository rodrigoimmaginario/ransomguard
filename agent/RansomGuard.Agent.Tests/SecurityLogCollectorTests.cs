using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// A1 — o coletor não pode reler o Security log inteiro a cada ciclo, nem reprocessar o histórico de
/// uma máquina onde acabou de ser instalado, nem perder evento quando há mais do que cabe num ciclo.
/// </summary>
public class SecurityLogCollectorTests
{
    private sealed class LogFalso : ISecurityLogSource
    {
        public readonly SortedDictionary<long, string> Registros = new();
        public readonly List<long> ConsultasApos = new();
        public long? MaisNovoForcado;

        public long? NewestRecordId() => MaisNovoForcado ?? (Registros.Count == 0 ? null : Registros.Keys.Max());

        public IEnumerable<SecurityLogRecord> ReadAfter(long recordId, int max)
        {
            ConsultasApos.Add(recordId);
            return Registros.Where(r => r.Key > recordId).Take(max).Select(r => new SecurityLogRecord(r.Key, r.Value)).ToList();
        }
    }

    private sealed class Memoria : ICursorStore
    {
        public string? Conteudo;
        public string? Read() => Conteudo;
        public void Write(string content) => Conteudo = content;
    }

    private static string Xml5145(string target = "contrato.docx", string ip = "10.0.9.66", string share = @"\\*\Financeiro") => $"""
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System><EventID>5145</EventID><TimeCreated SystemTime='2026-07-26T14:30:00.000000000Z'/><Computer>FS01.corp.local</Computer></System>
          <EventData>
            <Data Name='SubjectUserName'>vendas1</Data><Data Name='SubjectDomainName'>CORP</Data>
            <Data Name='IpAddress'>{ip}</Data><Data Name='ShareName'>{share}</Data>
            <Data Name='ShareLocalPath'>\??\D:\Shares\Financeiro</Data>
            <Data Name='RelativeTargetName'>{target}</Data><Data Name='AccessList'>%%4417</Data>
          </EventData>
        </Event>
        """;

    /// <summary>4663. PID 4 (System) é o sistema servindo SMB; qualquer outro é um processo deste servidor.</summary>
    private static string Xml4663(string obj = @"D:\Shares\Financeiro\2024\folha.xlsx", string pid = "0x4") => $"""
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System><EventID>4663</EventID><TimeCreated SystemTime='2026-07-26T14:30:00.000000000Z'/><Computer>FS01.corp.local</Computer></System>
          <EventData>
            <Data Name='SubjectUserName'>vendas1</Data><Data Name='SubjectDomainName'>CORP</Data>
            <Data Name='ObjectName'>{obj}</Data><Data Name='AccessList'>%%4417</Data>
            <Data Name='ProcessId'>{pid}</Data><Data Name='ProcessName'>C:\Temp\x.exe</Data>
          </EventData>
        </Event>
        """;

    private const string Xml1102 = """
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System><EventID>1102</EventID><TimeCreated SystemTime='2026-07-26T14:30:00.000000000Z'/><Computer>FS01.corp.local</Computer></System>
          <UserData><LogFileCleared><SubjectUserName>invasor</SubjectUserName><SubjectDomainName>CORP</SubjectDomainName></LogFileCleared></UserData>
        </Event>
        """;

    private static (SecurityLogCollector Coletor, LogFalso Log, Memoria Store, HostSignalBuffer Sinais, List<int> ChamadasSessao) Montar(
        string? cursorSalvo = "0", IReadOnlyList<SmbSession>? sessoes = null)
    {
        var log = new LogFalso();
        var store = new Memoria { Conteudo = cursorSalvo };
        var sinais = new HostSignalBuffer();
        var chamadas = new List<int>();
        var map = new ShareMap("FS01", new[] { new ShareEntry("Financeiro", @"D:\Shares\Financeiro") });
        var coletor = new SecurityLogCollector(log, new EventCursor(store), () => map,
            () => { chamadas.Add(1); return sessoes ?? Array.Empty<SmbSession>(); }, sinais);
        return (coletor, log, store, sinais, chamadas);
    }

    // ── primeira execução ───────────────────────────────────────────────────────────────────

    /// <summary>
    /// Instalado num servidor com um Security log de 1 GB, o agente não pode tratar a semana passada
    /// como ataque em andamento. Sem posição salva, parte do evento mais novo.
    /// </summary>
    [Fact]
    public void Sem_cursor_salvo_parte_do_evento_mais_novo_e_nao_reprocessa_o_historico()
    {
        var (coletor, log, store, _, _) = Montar(cursorSalvo: null);
        for (var i = 1; i <= 300; i++) log.Registros[i] = Xml5145();

        Assert.Empty(coletor.Drain());
        Assert.True(coletor.LastDrain.Baselined);
        Assert.Empty(log.ConsultasApos);            // nem chegou a ler o histórico
        Assert.Equal("300", store.Conteudo);

        log.Registros[301] = Xml5145("novo.docx");
        var eventos = coletor.Drain();

        Assert.Single(eventos);
        Assert.Equal("novo.docx", eventos[0].Path);
    }

    [Fact]
    public void Sem_cursor_e_com_log_vazio_fica_pronto_para_o_primeiro_evento()
    {
        var (coletor, log, _, _, _) = Montar(cursorSalvo: null);

        Assert.Empty(coletor.Drain());
        log.Registros[1] = Xml5145();

        Assert.Single(coletor.Drain());
    }

    // ── leitura incremental ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Pede_ao_log_apenas_o_que_veio_depois_do_cursor()
    {
        var (coletor, log, _, _, _) = Montar(cursorSalvo: "500");
        log.Registros[400] = Xml5145("velho.docx");
        log.Registros[501] = Xml5145("novo.docx");

        var eventos = coletor.Drain();

        Assert.Equal(new long[] { 500 }, log.ConsultasApos);
        Assert.Single(eventos);
        Assert.Equal("novo.docx", eventos[0].Path);
    }

    /// <summary>O cursor acompanha a ponta do log mesmo quando os eventos novos não interessam — senão a próxima consulta recomeça de longe.</summary>
    [Fact]
    public void Cursor_acompanha_a_ponta_do_log_quando_nao_ha_nada_relevante()
    {
        var (coletor, log, store, _, _) = Montar(cursorSalvo: "500");
        log.MaisNovoForcado = 900;                  // 400 eventos de outro tipo, fora do filtro

        Assert.Empty(coletor.Drain());

        Assert.Equal("900", store.Conteudo);
    }

    [Fact]
    public void Tempestade_de_eventos_e_entregue_em_fatias_sem_perder_nenhum()
    {
        var (coletor, log, _, _, _) = Montar(cursorSalvo: "0");
        var total = SecurityLogCollector.MaxPerCycle + 5;
        for (var i = 1; i <= total; i++) log.Registros[i] = Xml5145($"arq{i}.docx");

        var primeira = coletor.Drain();
        Assert.Equal(SecurityLogCollector.MaxPerCycle, primeira.Count);
        Assert.True(coletor.LastDrain.Truncated);

        var segunda = coletor.Drain();
        Assert.Equal(5, segunda.Count);
        Assert.False(coletor.LastDrain.Truncated);
        Assert.Equal($"arq{SecurityLogCollector.MaxPerCycle + 1}.docx", segunda[0].Path);   // o evento seguinte ao teto não se perde
    }

    [Fact]
    public void Log_limpo_reinicia_a_leitura_do_comeco_do_log_novo()
    {
        var (coletor, log, _, sinais, _) = Montar(cursorSalvo: "1000000");
        log.Registros[1] = Xml1102;
        log.Registros[2] = Xml5145("depois-da-limpeza.docx");

        var eventos = coletor.Drain();

        Assert.Single(eventos);
        Assert.Contains(sinais.Drain(), s => s.Kind == HostSignalKind.SecurityLogCleared);
    }

    // ── identidade e atribuição ─────────────────────────────────────────────────────────────

    [Fact]
    public void Eventos_saem_com_o_share_canonico()
    {
        var (coletor, log, _, _, _) = Montar();
        log.Registros[1] = Xml5145(@"2024\contrato.docx");
        log.Registros[2] = Xml4663();

        var eventos = coletor.Drain();

        Assert.All(eventos, e => Assert.Equal(@"\\FS01\Financeiro", e.Share));
        Assert.Equal(@"2024\contrato.docx", eventos[0].Path);
        Assert.Equal(@"2024\folha.xlsx", eventos[1].Path);
    }

    [Fact]
    public void Evento_local_recebe_a_origem_da_sessao_do_usuario()
    {
        var (coletor, log, _, _, _) = Montar(sessoes: new[] { new SmbSession(@"CORP\vendas1", "10.0.0.7") });
        log.Registros[1] = Xml4663();

        Assert.Equal("10.0.0.7", coletor.Drain()[0].SourceIp);
    }

    /// <summary>
    /// Processo local identificado é local, mesmo que o usuário também tenha uma sessão aberta de outra máquina:
    /// a resposta certa é encerrar o processo, não bloquear a estação dele.
    /// </summary>
    [Fact]
    public void Evento_de_processo_local_nao_e_atribuido_a_sessao_do_usuario()
    {
        var (coletor, log, _, _, chamadas) = Montar(sessoes: new[] { new SmbSession(@"CORP\vendas1", "10.0.0.7") });
        log.Registros[1] = Xml4663(pid: "0x1a2c");

        var e = Assert.Single(coletor.Drain());

        Assert.Equal(SecurityEventParser.LocalOrigin, e.SourceIp);
        Assert.Equal(0x1a2c, e.ProcessId);
        Assert.Empty(chamadas);
    }

    /// <summary>Listar sessões custa caro no Windows; o 5145 já traz o IP, então só eventos sem origem justificam a consulta.</summary>
    [Fact]
    public void Sessoes_so_sao_consultadas_quando_ha_evento_sem_origem()
    {
        var (coletor, log, _, _, chamadas) = Montar();
        log.Registros[1] = Xml5145();
        coletor.Drain();
        Assert.Empty(chamadas);

        log.Registros[2] = Xml4663();
        coletor.Drain();
        Assert.Single(chamadas);
    }

    [Fact]
    public void Falha_ao_listar_sessoes_nao_derruba_a_coleta()
    {
        var log = new LogFalso();
        log.Registros[1] = Xml4663();
        var map = new ShareMap("FS01", Array.Empty<ShareEntry>());
        var coletor = new SecurityLogCollector(log, new EventCursor(new Memoria { Conteudo = "0" }), () => map,
            () => throw new InvalidOperationException("sem acesso"), new HostSignalBuffer());

        var e = Assert.Single(coletor.Drain());
        Assert.Equal(SecurityEventParser.LocalOrigin, e.SourceIp);
    }

    // ── E3: eventos do file screen (FSRM) entram no mesmo fluxo ───────────────────────────────────────────────────

    private static string XmlFsrm(string file, string user = @"CORP\vendas1", int pid = 4) => $"""
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System><Provider Name='SRMSVC'/><EventID>8215</EventID><TimeCreated SystemTime='2026-07-26T14:30:01.000000000Z'/></System>
          <EventData><Data>RansomGuard-FSRM|user={user}|file={file}|screen=D:\Shares\Financeiro|group="RansomGuard_Ransomware"|pid={pid}|image={(pid == 4 ? "Process ID (4)" : @"C:\Temp\enc.exe")}</Data></EventData>
        </Event>
        """;

    private static (SecurityLogCollector Coletor, LogFalso Seguranca, LogFalso Fsrm, Memoria CursorFsrm) MontarComFsrm(string? cursorFsrm = "0")
    {
        var seguranca = new LogFalso(); var fsrm = new LogFalso();
        var storeFsrm = new Memoria { Conteudo = cursorFsrm };
        var map = new ShareMap("FS01", new[] { new ShareEntry("Financeiro", @"D:\Shares\Financeiro") });
        var coletor = new SecurityLogCollector(seguranca, new EventCursor(new Memoria { Conteudo = "0" }), () => map,
            () => Array.Empty<SmbSession>(), new HostSignalBuffer(), fsrmSource: fsrm, fsrmCursor: new EventCursor(storeFsrm));
        return (coletor, seguranca, fsrm, storeFsrm);
    }

    /// <summary>O 5145 só mostra o nome antigo numa renomeação; o evento do file screen traz o nome novo, com a extensão.</summary>
    [Fact]
    public void Renomeacao_para_extensao_do_catalogo_aparece_pelo_file_screen()
    {
        var (coletor, _, fsrm, _) = MontarComFsrm();
        fsrm.Registros[1] = XmlFsrm(@"D:\Shares\Financeiro\2024\contrato.docx.lockbit");

        var e = Assert.Single(coletor.Drain());

        Assert.Equal(@"\\FS01\Financeiro", e.Share);
        Assert.Equal(@"2024\contrato.docx.lockbit", e.Path);
        Assert.Equal(".lockbit", e.NewExtension);
        Assert.Equal(@"CORP\vendas1", e.User);
    }

    /// <summary>O FSRM não conhece o IP do cliente. Se o mesmo usuário tem evento de share neste ciclo, a origem é aquela.</summary>
    [Fact]
    public void Evento_do_file_screen_pela_rede_herda_o_ip_do_mesmo_usuario_neste_ciclo()
    {
        var (coletor, seguranca, fsrm, _) = MontarComFsrm();
        seguranca.Registros[1] = Xml5145("contrato.docx", ip: "10.0.9.66");
        fsrm.Registros[1] = XmlFsrm(@"D:\Shares\Financeiro\contrato.docx.lockbit");

        var eventos = coletor.Drain();

        Assert.Equal(2, eventos.Count);
        Assert.All(eventos, e => Assert.Equal("10.0.9.66", e.SourceIp));
    }

    [Fact]
    public void Evento_do_file_screen_de_processo_local_continua_local_e_guarda_o_processo()
    {
        var (coletor, seguranca, fsrm, _) = MontarComFsrm();
        seguranca.Registros[1] = Xml5145("contrato.docx", ip: "10.0.9.66");      // o mesmo usuário também está pela rede
        fsrm.Registros[1] = XmlFsrm(@"D:\Shares\Financeiro\contrato.docx.lockbit", pid: 4321);

        var local = coletor.Drain().Single(e => e.Path.EndsWith(".lockbit"));

        Assert.Equal(SecurityEventParser.LocalOrigin, local.SourceIp);
        Assert.Equal(4321, local.ProcessId);
    }

    [Fact]
    public void Log_do_file_screen_tem_cursor_proprio_e_nao_reprocessa_historico_na_primeira_execucao()
    {
        var (coletor, _, fsrm, store) = MontarComFsrm(cursorFsrm: null);
        fsrm.Registros[50] = XmlFsrm(@"D:\Shares\Financeiro\antigo.docx.lockbit");

        Assert.Empty(coletor.Drain());
        Assert.Equal("50", store.Conteudo);

        fsrm.Registros[51] = XmlFsrm(@"D:\Shares\Financeiro\novo.docx.lockbit");
        Assert.Equal("novo.docx.lockbit", Assert.Single(coletor.Drain()).Path);
    }

    [Fact]
    public void Evento_de_outro_file_screen_no_mesmo_log_e_ignorado()
    {
        var (coletor, _, fsrm, store) = MontarComFsrm();
        fsrm.Registros[1] = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>8215</EventID></System><EventData><Data>file screen do cliente</Data></EventData></Event>";

        Assert.Empty(coletor.Drain());
        Assert.Equal("1", store.Conteudo);
    }

    [Fact]
    public void Registro_ilegivel_e_pulado_sem_travar_o_cursor()
    {
        var (coletor, log, store, _, _) = Montar();
        log.Registros[1] = "<Event";
        log.Registros[2] = Xml5145();

        Assert.Single(coletor.Drain());
        Assert.Equal("2", store.Conteudo);
    }
}
