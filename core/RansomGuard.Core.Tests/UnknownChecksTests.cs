using RansomGuard.Core.Score;

namespace RansomGuard.Core.Tests;

/// <summary>
/// O Score não pode punir o que não mediu. Antes desta fatia, uma leitura que falhava virava
/// silenciosamente "está ruim" — o servidor de um admin caprichoso levava um achado crítico de
/// "share aberto para Everyone" que ninguém tinha verificado. Nota errada destrói a confiança no
/// produto justamente na tela que é a porta de entrada do produto.
///
/// Regra nova: checagem não realizada entra em <c>UnknownChecks</c>, sai do numerador E do
/// denominador, e aparece na lista de não verificados — visível, nunca silenciosa.
/// </summary>
public class UnknownChecksTests
{
    /// <summary>Servidor perfeito: nenhuma regra violada.</summary>
    private static PostureSnapshot Impecavel(string server = "FS01") => new()
    {
        Server = server,
        SmbSigningRequired = true,
        SmbAuthRateLimiter = true,
        VssEnabled = true,
        BackupServiceRunning = true,
        BackupsProtected = true,
        FsrmActive = true,
        ShareAuditingEnabled = true,
        CanariesPlanted = true,
        AgentInstalled = true
    };

    [Fact]
    public void Sem_desconhecidos_o_comportamento_nao_muda()
    {
        var r = new RiskScoreEngine().ScoreServer(Impecavel());

        Assert.Equal(100, r.Score);
        Assert.Empty(r.Findings);
        Assert.Empty(r.Unknown);
    }

    [Fact]
    public void Checagem_desconhecida_nao_vira_achado()
    {
        // Não deu para ler a ACL do share — não sabemos se está aberto.
        var posture = Impecavel() with
        {
            SharesWritableByEveryone = true,          // valor "pessimista" que o coletor chutava
            UnknownChecks = new HashSet<string> { "share-everyone" }
        };

        var r = new RiskScoreEngine().ScoreServer(posture);

        Assert.DoesNotContain(r.Findings, f => f.Rule.Id == "share-everyone");
        Assert.Contains(r.Unknown, u => u.Id == "share-everyone");
    }

    [Fact]
    public void Nota_e_calculada_sobre_o_que_foi_medido()
    {
        // Servidor impecável no que deu para medir, com uma checagem não realizada:
        // a nota continua 100 — porque 100% do que sabemos está correto.
        var posture = Impecavel() with { UnknownChecks = new HashSet<string> { "fsrm" } };

        var r = new RiskScoreEngine().ScoreServer(posture);

        Assert.Equal(100, r.Score);
        Assert.Single(r.Unknown);
    }

    [Fact]
    public void Violacao_real_continua_pesando_mesmo_com_outra_desconhecida()
    {
        var posture = Impecavel() with
        {
            SmbV1Enabled = true,                                   // violação de verdade
            UnknownChecks = new HashSet<string> { "fsrm" }         // e uma não medida
        };

        var r = new RiskScoreEngine().ScoreServer(posture);

        Assert.Contains(r.Findings, f => f.Rule.Id == "smb-v1");
        Assert.True(r.Score < 100, "SMBv1 ligado tem que derrubar a nota");
        Assert.Contains(r.Unknown, u => u.Id == "fsrm");
    }

    /// <summary>
    /// O peso da regra desconhecida sai do denominador: senão, o servidor seria punido de novo
    /// por via indireta (nota diluída) — o mesmo erro com outra roupa.
    /// </summary>
    [Fact]
    public void Peso_do_desconhecido_sai_do_denominador()
    {
        var comUmaViolacao = Impecavel() with { SmbV1Enabled = true };
        var mesmaViolacaoComOutraDesconhecida = comUmaViolacao with
        {
            UnknownChecks = new HashSet<string> { "vss" }
        };

        var a = new RiskScoreEngine().ScoreServer(comUmaViolacao).Score;
        var b = new RiskScoreEngine().ScoreServer(mesmaViolacaoComOutraDesconhecida).Score;

        // SMBv1 pesa 8; VSS pesa 8. No primeiro caso perde-se 8 de 100 → 92. No segundo, o peso do
        // VSS sai do denominador: 8 de 92 → 91. A nota cai um pouco porque a mesma falha pesa
        // proporcionalmente mais num universo menor — o que é honesto: medimos menos coisas.
        Assert.Equal(92, a);                                                   // 100 × (100−8)/100
        Assert.Equal(91, b);                                                   // 100 × (92−8)/92
        Assert.True(b < a, "com menos coisas medidas, a mesma falha pesa proporcionalmente mais");
    }

    [Fact]
    public void Tudo_desconhecido_nao_gera_nota_falsamente_perfeita()
    {
        var todas = ScoreRules.Default.Select(r => r.Id).ToHashSet();
        var posture = Impecavel() with { UnknownChecks = todas };

        var r = new RiskScoreEngine().ScoreServer(posture);

        // Sem nada medido não há nota honesta possível: 0 medido = 0 de confiança.
        Assert.Equal(0, r.Score);
        Assert.Equal(ScoreRules.Default.Count, r.Unknown.Count);
        Assert.Empty(r.Findings);
    }

    [Fact]
    public void Desconhecido_traz_a_regra_inteira_para_a_tela_explicar()
    {
        var posture = Impecavel() with { UnknownChecks = new HashSet<string> { "share-everyone" } };

        var u = new RiskScoreEngine().ScoreServer(posture).Unknown.Single();

        // O painel precisa dizer o que não foi verificado e por que isso importa.
        Assert.Equal("share-everyone", u.Id);
        Assert.False(string.IsNullOrWhiteSpace(u.Title));
        Assert.False(string.IsNullOrWhiteSpace(u.AttackPremise));
    }

    [Fact]
    public void Id_desconhecido_que_nao_existe_no_catalogo_e_ignorado()
    {
        var posture = Impecavel() with { UnknownChecks = new HashSet<string> { "regra-que-nao-existe" } };

        var r = new RiskScoreEngine().ScoreServer(posture);

        Assert.Equal(100, r.Score);
        Assert.Empty(r.Unknown);
    }

    [Fact]
    public void Rede_consolida_servidores_com_checagens_desconhecidas()
    {
        var a = Impecavel("FS01");
        var b = Impecavel("FS02") with { UnknownChecks = new HashSet<string> { "fsrm" } };

        var rede = new RiskScoreEngine().ScoreNetwork(new[] { a, b });

        Assert.Equal(2, rede.Servers.Count);
        Assert.All(rede.Servers, s => Assert.Equal(100, s.Score));
    }
}
