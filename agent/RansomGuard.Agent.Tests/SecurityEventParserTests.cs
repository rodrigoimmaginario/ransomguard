using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// Parsing dos eventos de auditoria do Windows. É onde o produto deixa de ser cego: o
/// <c>DetectionEngine</c> já sabe correlacionar e decidir, mas até aqui nunca recebeu um evento
/// de verdade. O XML abaixo é o formato real emitido pelo Windows (Security log).
/// </summary>
public class SecurityEventParserTests
{
    private static readonly DateTime T0 = new(2026, 7, 26, 14, 30, 0, DateTimeKind.Utc);

    /// <summary>5145 — acesso a share. Traz IP de origem, share e caminho relativo.</summary>
    private static string Xml5145(
        string user = "vendas1", string domain = "CORP", string ip = "10.0.9.66",
        string share = "\\\\*\\Financeiro", string target = "contrato.docx",
        string accessList = "%%4417") => $"""
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System>
            <EventID>5145</EventID>
            <TimeCreated SystemTime='2026-07-26T14:30:00.000000000Z'/>
            <EventRecordID>91011</EventRecordID>
          </System>
          <EventData>
            <Data Name='SubjectUserSid'>S-1-5-21-1</Data>
            <Data Name='SubjectUserName'>{user}</Data>
            <Data Name='SubjectDomainName'>{domain}</Data>
            <Data Name='SubjectLogonId'>0x3e7</Data>
            <Data Name='ObjectType'>File</Data>
            <Data Name='IpAddress'>{ip}</Data>
            <Data Name='IpPort'>50123</Data>
            <Data Name='ShareName'>{share}</Data>
            <Data Name='ShareLocalPath'>\??\D:\Shares\Financeiro</Data>
            <Data Name='RelativeTargetName'>{target}</Data>
            <Data Name='AccessMask'>0x2</Data>
            <Data Name='AccessList'>{accessList}</Data>
          </EventData>
        </Event>
        """;

    /// <summary>4663 — acesso a objeto. Caminho completo, mas SEM IP de origem.</summary>
    private static string Xml4663(
        string user = "vendas1", string domain = "CORP",
        string obj = @"D:\Shares\Financeiro\contrato.docx",
        string accessList = "%%4417") => $"""
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System>
            <EventID>4663</EventID>
            <TimeCreated SystemTime='2026-07-26T14:30:00.000000000Z'/>
            <EventRecordID>91012</EventRecordID>
          </System>
          <EventData>
            <Data Name='SubjectUserName'>{user}</Data>
            <Data Name='SubjectDomainName'>{domain}</Data>
            <Data Name='SubjectLogonId'>0x3e7</Data>
            <Data Name='ObjectServer'>Security</Data>
            <Data Name='ObjectType'>File</Data>
            <Data Name='ObjectName'>{obj}</Data>
            <Data Name='HandleId'>0x9c8</Data>
            <Data Name='AccessList'>{accessList}</Data>
            <Data Name='ProcessId'>0x1a2c</Data>
            <Data Name='ProcessName'>C:\Windows\System32\ntoskrnl.exe</Data>
          </EventData>
        </Event>
        """;

    [Fact]
    public void Evento_5145_traz_quem_de_onde_e_o_que()
    {
        var e = SecurityEventParser.Parse(Xml5145())!;

        Assert.Equal(@"CORP\vendas1", e.User);
        Assert.Equal("10.0.9.66", e.SourceIp);
        Assert.Equal("Financeiro", e.Share);
        Assert.Equal("contrato.docx", e.Path);
        Assert.Equal(FileOp.Write, e.Op);
        Assert.Equal(T0, e.At);
    }

    [Fact]
    public void Evento_4663_nao_tem_ip_e_e_marcado_como_local()
    {
        var e = SecurityEventParser.Parse(Xml4663())!;

        Assert.Equal(@"CORP\vendas1", e.User);
        Assert.Equal(SecurityEventParser.LocalOrigin, e.SourceIp);
        Assert.Equal("contrato.docx", e.Path);
    }

    /// <summary>
    /// Os códigos de acesso do Windows (%%NNNN) decidem a operação. Errar aqui faz leitura virar
    /// escrita — e leitura em massa é backup rodando, não ataque.
    /// </summary>
    [Theory]
    [InlineData("%%4417", FileOp.Write)]          // WriteData
    [InlineData("%%4418", FileOp.Write)]          // AppendData
    [InlineData("%%1537", FileOp.Delete)]         // DELETE
    [InlineData("%%4422", FileOp.Delete)]         // DeleteChild
    [InlineData("%%4420", FileOp.Read)]           // WriteEA sozinho não é gravação de dados nem exclusão
    [InlineData("%%4416", FileOp.Read)]           // ReadData
    [InlineData("%%4423", FileOp.Read)]           // ReadAttributes
    public void Codigo_de_acesso_define_a_operacao(string accessList, FileOp esperado)
        => Assert.Equal(esperado, SecurityEventParser.Parse(Xml5145(accessList: accessList))!.Op);

    /// <summary>Escrita ganha de leitura quando os dois aparecem no mesmo evento.</summary>
    [Fact]
    public void Escrita_prevalece_sobre_leitura_no_mesmo_evento()
        => Assert.Equal(FileOp.Write, SecurityEventParser.Parse(Xml5145(accessList: "%%4416 %%4417"))!.Op);

    [Fact]
    public void Delete_prevalece_sobre_escrita()
        => Assert.Equal(FileOp.Delete, SecurityEventParser.Parse(Xml5145(accessList: "%%4417 %%1537"))!.Op);

    /// <summary>O share vem como <c>\\*\Nome</c> no evento; o produto usa só o nome.</summary>
    [Theory]
    [InlineData(@"\\*\Financeiro", "Financeiro")]
    [InlineData(@"\\*\Dados$", "Dados$")]
    [InlineData("Financeiro", "Financeiro")]
    public void Nome_do_share_e_normalizado(string bruto, string esperado)
        => Assert.Equal(esperado, SecurityEventParser.Parse(Xml5145(share: bruto))!.Share);

    /// <summary>Extensão de ransomware é o sinal mais direto que existe.</summary>
    [Fact]
    public void Extensao_resultante_e_extraida()
    {
        var e = SecurityEventParser.Parse(Xml5145(target: "contrato.docx.locked"))!;
        Assert.Equal(".locked", e.NewExtension);
    }

    [Fact]
    public void Arquivo_sem_extensao_nao_inventa_uma()
        => Assert.Null(SecurityEventParser.Parse(Xml5145(target: "LEIAME"))!.NewExtension);

    /// <summary>
    /// Tocar num canário é o sinal de maior confiança do produto — nenhum usuário legítimo abre um
    /// arquivo que ele não sabe que existe. Se o parser não marcar, a contenção não dispara.
    /// </summary>
    [Fact]
    public void Canario_e_reconhecido_pelo_nome()
    {
        var canario = RansomGuard.Core.Fsrm.CanaryPlan.NamesFor(@"D:\Shares\Financeiro")[0];
        var e = SecurityEventParser.Parse(Xml5145(target: canario))!;

        Assert.True(e.IsCanary);
    }

    [Fact]
    public void Arquivo_comum_nao_e_canario()
        => Assert.False(SecurityEventParser.Parse(Xml5145(target: "contrato.docx"))!.IsCanary);

    [Fact]
    public void Canario_em_subpasta_tambem_conta()
    {
        var canario = RansomGuard.Core.Fsrm.CanaryPlan.NamesFor(@"D:\X")[0];
        var e = SecurityEventParser.Parse(Xml5145(target: $@"subpasta\{canario}"))!;

        Assert.True(e.IsCanary);
    }

    /// <summary>
    /// **Achado da validação em máquina real.** Acessar <c>\\localhost\share</c> registra o 5145
    /// com <c>::1</c> — loopback. Se isso passasse como IP remoto, a escada de contenção
    /// bloquearia o loopback no firewall do próprio servidor e derrubaria a sessão de quem está
    /// trabalhando localmente: o produto quebraria o servidor que veio proteger.
    /// </summary>
    [Theory]
    [InlineData("::1")]
    [InlineData("127.0.0.1")]
    [InlineData("0:0:0:0:0:0:0:1")]
    public void Loopback_e_tratado_como_origem_local(string ip)
        => Assert.Equal(SecurityEventParser.LocalOrigin, SecurityEventParser.Parse(Xml5145(ip: ip))!.SourceIp);

    [Fact]
    public void Ip_remoto_de_verdade_continua_sendo_remoto()
        => Assert.Equal("10.0.9.66", SecurityEventParser.Parse(Xml5145(ip: "10.0.9.66"))!.SourceIp);

    [Theory]
    [InlineData("")]
    [InlineData("-")]
    public void Endereco_ausente_vira_local(string ip)
        => Assert.Equal(SecurityEventParser.LocalOrigin, SecurityEventParser.Parse(Xml5145(ip: ip))!.SourceIp);

    /// <summary>IPv6 de rede é origem remota legítima — não pode cair na regra do loopback.</summary>
    [Fact]
    public void Ipv6_de_rede_nao_e_confundido_com_loopback()
        => Assert.Equal("fe80::1c2b:3d4e", SecurityEventParser.Parse(Xml5145(ip: "fe80::1c2b:3d4e"))!.SourceIp);

    [Fact]
    public void Usuario_sem_dominio_nao_ganha_barra_solta()
    {
        var e = SecurityEventParser.Parse(Xml5145(domain: "", user: "SYSTEM"))!;
        Assert.Equal("SYSTEM", e.User);
    }

    // ── Robustez: o coletor não pode morrer por causa de um evento estranho ──────────────────

    [Theory]
    [InlineData("")]
    [InlineData("não é xml")]
    [InlineData("<Event><System><EventID>4624</EventID></System></Event>")]   // evento irrelevante
    public void Entrada_invalida_ou_irrelevante_devolve_nulo(string xml)
        => Assert.Null(SecurityEventParser.Parse(xml));

    [Fact]
    public void Evento_sem_alvo_e_descartado()
    {
        var semAlvo = Xml5145(target: "");
        Assert.Null(SecurityEventParser.Parse(semAlvo));
    }

    /// <summary>
    /// Ruído de infraestrutura do próprio Windows: o share IPC$ recebe acesso o tempo todo e não
    /// tem nada a ver com arquivos de usuário. Deixar passar polui a detecção.
    /// </summary>
    [Fact]
    public void Acesso_ao_IPC_e_ignorado()
        => Assert.Null(SecurityEventParser.Parse(Xml5145(share: @"\\*\IPC$", target: "srvsvc")));

    [Fact]
    public void RecordId_e_extraido_para_o_cursor()
        => Assert.Equal(91011, SecurityEventParser.RecordIdOf(Xml5145()));

    [Fact]
    public void Evento_4663_traz_o_processo_local_em_hexa()
    {
        var e = SecurityEventParser.Parse(Xml4663())!;
        Assert.Equal(0x1a2c, e.ProcessId);
        Assert.EndsWith("ntoskrnl.exe", e.ProcessName);
        Assert.True(RansomGuard.Core.Response.ResponseTarget.IsProtectedProcess(e.ProcessName));
    }

    [Fact]
    public void Evento_5145_nao_tem_processo()
    {
        var e = SecurityEventParser.Parse(Xml5145())!;
        Assert.Null(e.ProcessId);
    }

}

/// <summary>
/// O 4663 não traz IP. Sem correlacionar com a sessão SMB, toda criptografia remota apareceria
/// como "local" — e a contenção não teria em quem bater. É o elo que faz o produto atribuir o
/// ataque à máquina certa.
/// </summary>
public class SessionCorrelatorTests
{
    private static readonly DateTime T0 = new(2026, 7, 26, 14, 30, 0, DateTimeKind.Utc);

    private static FileEvent Local(string user = @"CORP\vendas1", string share = "Financeiro") =>
        new(T0, user, SecurityEventParser.LocalOrigin, share, FileOp.Write, "x.docx");

    [Fact]
    public void Evento_local_ganha_o_ip_da_sessao_do_mesmo_usuario()
    {
        var sessoes = new[] { new SmbSession(@"CORP\vendas1", "10.0.9.66", "Financeiro") };

        var e = SessionCorrelator.Attribute(Local(), sessoes);

        Assert.Equal("10.0.9.66", e.SourceIp);
    }

    [Fact]
    public void Sem_sessao_correspondente_continua_local()
    {
        var e = SessionCorrelator.Attribute(Local(), Array.Empty<SmbSession>());
        Assert.Equal(SecurityEventParser.LocalOrigin, e.SourceIp);
    }

    /// <summary>Sessão de outro usuário não pode emprestar o IP — atribuição errada acusa inocente.</summary>
    [Fact]
    public void Sessao_de_outro_usuario_nao_e_usada()
    {
        var sessoes = new[] { new SmbSession(@"CORP\outro", "10.0.9.99", "Financeiro") };

        Assert.Equal(SecurityEventParser.LocalOrigin, SessionCorrelator.Attribute(Local(), sessoes).SourceIp);
    }

    /// <summary>Mesmo usuário em dois shares: vale a sessão do share do evento.</summary>
    [Fact]
    public void Share_desempata_sessoes_do_mesmo_usuario()
    {
        var sessoes = new[]
        {
            new SmbSession(@"CORP\vendas1", "10.0.0.1", "Publica"),
            new SmbSession(@"CORP\vendas1", "10.0.0.2", "Financeiro")
        };

        Assert.Equal("10.0.0.2", SessionCorrelator.Attribute(Local(), sessoes).SourceIp);
    }

    [Fact]
    public void Evento_que_ja_tem_ip_nao_e_alterado()
    {
        var comIp = Local() with { SourceIp = "10.0.9.66" };
        var sessoes = new[] { new SmbSession(@"CORP\vendas1", "10.0.0.9", "Financeiro") };

        Assert.Equal("10.0.9.66", SessionCorrelator.Attribute(comIp, sessoes).SourceIp);
    }

    [Fact]
    public void Comparacao_de_usuario_ignora_caixa()
    {
        var sessoes = new[] { new SmbSession(@"corp\VENDAS1", "10.0.9.66", "financeiro") };
        Assert.Equal("10.0.9.66", SessionCorrelator.Attribute(Local(), sessoes).SourceIp);
    }

    /// <summary>Saída real do <c>Get-SmbSession</c>, em tabela.</summary>
    [Fact]
    public void Sessoes_sao_lidas_da_saida_do_PowerShell()
    {
        const string saida = """
            SessionId    ClientComputerName ClientUserName    NumOpens
            ---------    ------------------ --------------    --------
            412316860417 10.0.9.66          CORP\vendas1      3
            412316860418 10.0.9.70          CORP\backup       1
            """;

        var s = SessionCorrelator.ParseSessions(saida);

        Assert.Equal(2, s.Count);
        Assert.Equal("10.0.9.66", s[0].SourceIp);
        Assert.Equal(@"CORP\vendas1", s[0].User);
    }

    [Fact]
    public void Saida_de_sessoes_vazia_nao_quebra()
        => Assert.Empty(SessionCorrelator.ParseSessions(""));

    [Fact]
    public void Mensagem_de_erro_nao_vira_sessao()
        => Assert.Empty(SessionCorrelator.ParseSessions("Get-SmbSession : Acesso negado."));
}