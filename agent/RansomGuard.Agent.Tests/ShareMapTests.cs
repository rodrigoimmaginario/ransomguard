using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// D1 — o Windows fala de share de três jeitos (nome no 5145, caminho local no 4663, share
/// administrativo quando o atacante tem credencial de admin). O motor precisa de UM nome por share,
/// na forma que o resto do produto já usa: <c>\\SERVIDOR\Share</c>.
/// </summary>
public class ShareMapTests
{
    private static ShareMap Map(params (string Name, string Path)[] shares) =>
        new("FS01", shares.Select(s => new ShareEntry(s.Name, s.Path)));

    private static ParsedFileEvent Evento(string? shareName, string? local, string share = "x", string path = "x", bool canario = false) =>
        new(new FileEvent(DateTime.UnixEpoch, @"CORP\vendas1", "10.0.9.66", share, FileOp.Write, path, ".docx", canario), shareName, local);

    [Fact]
    public void Evento_de_share_vira_UNC_do_servidor_com_caminho_relativo()
    {
        var e = Map(("Financeiro", @"D:\Shares\Financeiro"))
            .Canonicalize(Evento("Financeiro", @"D:\Shares\Financeiro\2024\contrato.docx"));

        Assert.Equal(@"\\FS01\Financeiro", e.Share);
        Assert.Equal(@"2024\contrato.docx", e.Path);
    }

    [Fact]
    public void Evento_de_objeto_local_cai_no_mesmo_share()
    {
        var e = Map(("Financeiro", @"D:\Shares\Financeiro"))
            .Canonicalize(Evento(null, @"D:\Shares\Financeiro\2024\contrato.docx"));

        Assert.Equal(@"\\FS01\Financeiro", e.Share);
        Assert.Equal(@"2024\contrato.docx", e.Path);
    }

    /// <summary>Quem tem credencial de admin costuma entrar por C$; continua sendo o share Financeiro que está sendo cifrado.</summary>
    [Fact]
    public void Acesso_por_share_administrativo_e_atribuido_ao_share_publicado()
    {
        var e = Map(("Financeiro", @"C:\Shares\Financeiro"))
            .Canonicalize(Evento("C$", @"C:\Shares\Financeiro\contrato.docx"));

        Assert.Equal(@"\\FS01\Financeiro", e.Share);
        Assert.Equal("contrato.docx", e.Path);
    }

    [Fact]
    public void Entre_shares_aninhados_vence_o_mais_especifico()
    {
        var e = Map(("Dados", @"D:\Dados"), ("RH", @"D:\Dados\RH"))
            .Canonicalize(Evento(null, @"D:\Dados\RH\folha.xlsx"));

        Assert.Equal(@"\\FS01\RH", e.Share);
        Assert.Equal("folha.xlsx", e.Path);
    }

    [Fact]
    public void Prefixo_so_vale_em_fronteira_de_pasta()
    {
        var e = Map(("Fin", @"D:\Shares\Fin"))
            .Canonicalize(Evento(null, @"D:\Shares\Financeiro\contrato.docx"));

        Assert.NotEqual(@"\\FS01\Fin", e.Share);
    }

    [Fact]
    public void Comparacao_ignora_caixa_e_barra_final()
    {
        var e = Map(("Financeiro", @"d:\shares\financeiro\"))
            .Canonicalize(Evento("FINANCEIRO", @"D:\Shares\Financeiro\a.docx"));

        Assert.Equal(@"\\FS01\Financeiro", e.Share);
        Assert.Equal("a.docx", e.Path);
    }

    [Fact]
    public void Share_na_raiz_do_volume_funciona()
    {
        var e = Map(("Dados", @"E:\")).Canonicalize(Evento("Dados", @"E:\pasta\a.docx"));

        Assert.Equal(@"\\FS01\Dados", e.Share);
        Assert.Equal(@"pasta\a.docx", e.Path);
    }

    /// <summary>Tabela de shares indisponível não pode cegar o agente: o nome do evento basta para o UNC.</summary>
    [Fact]
    public void Sem_tabela_o_nome_do_evento_ainda_vira_UNC()
    {
        var e = Map().Canonicalize(Evento("Financeiro", @"D:\Shares\Financeiro\a.docx", path: "a.docx"));

        Assert.Equal(@"\\FS01\Financeiro", e.Share);
        Assert.Equal("a.docx", e.Path);
    }

    /// <summary>Pasta local que não é share: identidade pelo caminho completo (nunca só o nome da pasta, que colide).</summary>
    [Fact]
    public void Objeto_local_fora_de_qualquer_share_usa_a_pasta_completa()
    {
        var e = Map(("Financeiro", @"D:\Shares\Financeiro"))
            .Canonicalize(Evento(null, @"E:\Trabalho\2024\a.docx"));

        Assert.Equal(@"E:\Trabalho\2024", e.Share);
        Assert.Equal("a.docx", e.Path);
    }

    [Fact]
    public void Preserva_os_demais_campos_do_evento()
    {
        var e = Map(("Financeiro", @"D:\Shares\Financeiro"))
            .Canonicalize(Evento("Financeiro", @"D:\Shares\Financeiro\a.docx", canario: true));

        Assert.True(e.IsCanary);
        Assert.Equal(@"CORP\vendas1", e.User);
        Assert.Equal("10.0.9.66", e.SourceIp);
        Assert.Equal(".docx", e.NewExtension);
    }

    [Theory]
    [InlineData(@"\\FS01\Isca", @"\\FS01\Isca")]
    [InlineData(@"\\fs01.corp.local\Isca", @"\\FS01\Isca")]
    [InlineData("Isca", @"\\FS01\Isca")]
    [InlineData(@"  \\outro\Isca\  ", @"\\FS01\Isca")]
    public void Share_configurado_pelo_admin_e_normalizado_para_a_mesma_forma(string configurado, string esperado)
        => Assert.Equal(esperado, Map().NormalizeConfigured(configurado));

    [Fact]
    public void Share_configurado_vazio_e_ignorado()
        => Assert.Null(Map().NormalizeConfigured("   "));

    // ── tabela de shares do registro (LanmanServer\Shares) ──────────────────────────────────

    [Fact]
    public void Le_o_caminho_de_cada_share_do_registro()
    {
        var shares = ShareMap.ParseLanmanShares(new Dictionary<string, string[]>
        {
            ["Financeiro"] = new[] { "CSCFlags=0", "MaxUses=4294967295", @"Path=D:\Shares\Financeiro", "Permissions=0", "Remark=", "ShareName=Financeiro", "Type=0" },
            ["RH"] = new[] { @"Path=D:\Dados\RH", "Type=0" }
        });

        Assert.Equal(2, shares.Count);
        Assert.Contains(new ShareEntry("Financeiro", @"D:\Shares\Financeiro"), shares);
        Assert.Contains(new ShareEntry("RH", @"D:\Dados\RH"), shares);
    }

    [Fact]
    public void Ignora_entrada_sem_caminho_ou_que_nao_e_disco()
    {
        var shares = ShareMap.ParseLanmanShares(new Dictionary<string, string[]>
        {
            ["Impressora"] = new[] { @"Path=HP,LocalsplOnly", "Type=1" },
            ["Quebrado"] = new[] { "Type=0" },
            ["Vazio"] = Array.Empty<string>()
        });

        Assert.Empty(shares);
    }
}
