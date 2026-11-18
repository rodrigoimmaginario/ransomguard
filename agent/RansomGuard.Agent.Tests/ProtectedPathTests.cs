using RansomGuard.Agent.Protection;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// F12 é a primeira fatia em que o produto **escreve** no ambiente do cliente. Antes de plantar
/// qualquer coisa, é preciso decidir onde é seguro plantar — e onde plantar seria dano, não
/// proteção.
/// </summary>
public class ProtectedPathTests
{
    [Fact]
    public void Configuracao_vazia_nao_e_erro()
    {
        var r = ProtectedPaths.Parse("");

        Assert.Empty(r.Accepted);
        Assert.Empty(r.Rejected);
    }

    [Fact]
    public void Separa_caminhos_por_ponto_e_virgula()
    {
        var r = ProtectedPaths.Parse(@"D:\Shares\Financeiro;E:\Dados");

        Assert.Equal(2, r.Accepted.Count);
        Assert.Contains(@"D:\Shares\Financeiro", r.Accepted);
        Assert.Contains(@"E:\Dados", r.Accepted);
    }

    [Fact]
    public void Ignora_espacos_e_entradas_vazias()
    {
        var r = ProtectedPaths.Parse(@"  D:\A ; ; E:\B  ;");

        Assert.Equal(new[] { @"D:\A", @"E:\B" }, r.Accepted);
    }

    /// <summary>Duplicata silenciosa faria o produto plantar e reportar o mesmo lugar duas vezes.</summary>
    [Fact]
    public void Remove_duplicatas_ignorando_caixa_e_barra_final()
    {
        var r = ProtectedPaths.Parse(@"D:\Dados;d:\dados\;D:\DADOS");

        Assert.Single(r.Accepted);
    }

    // ── Caminhos que o produto se recusa a tocar ────────────────────────────────────────────

    /// <summary>
    /// Plantar canário ou aplicar file screen na raiz de um volume, no Windows ou em Program Files
    /// é dano, não proteção: atinge arquivos de sistema e de todos os aplicativos de uma vez.
    /// Um erro de digitação na GPO não pode virar incidente no parque inteiro.
    /// </summary>
    [Theory]
    [InlineData(@"C:\")]
    [InlineData(@"C:")]
    [InlineData(@"D:\")]
    [InlineData(@"C:\Windows")]
    [InlineData(@"C:\Windows\System32")]
    [InlineData(@"C:\Program Files")]
    [InlineData(@"C:\Program Files (x86)")]
    [InlineData(@"C:\ProgramData")]
    public void Caminhos_perigosos_sao_recusados(string caminho)
    {
        var r = ProtectedPaths.Parse(caminho);

        Assert.Empty(r.Accepted);
        Assert.Single(r.Rejected);
        Assert.False(string.IsNullOrWhiteSpace(r.Rejected[0].Reason));
    }

    /// <summary>Subpasta de um share dentro de outro volume é legítima — não pode ser confundida.</summary>
    [Theory]
    [InlineData(@"D:\Shares\Financeiro")]
    [InlineData(@"E:\Dados\Contratos")]
    [InlineData(@"C:\Shares\Publica")]
    public void Pastas_de_dados_sao_aceitas(string caminho)
        => Assert.Contains(caminho, ProtectedPaths.Parse(caminho).Accepted);

    /// <summary>Recusar um caminho não pode derrubar os outros — o admin corrige o que errou.</summary>
    [Fact]
    public void Caminho_recusado_nao_invalida_os_demais()
    {
        var r = ProtectedPaths.Parse(@"C:\Windows;D:\Shares\Financeiro");

        Assert.Single(r.Accepted);
        Assert.Single(r.Rejected);
        Assert.Equal(@"D:\Shares\Financeiro", r.Accepted[0]);
    }

    [Fact]
    public void Caminho_relativo_e_recusado()
    {
        var r = ProtectedPaths.Parse(@"..\Dados;Dados");

        Assert.Empty(r.Accepted);
        Assert.Equal(2, r.Rejected.Count);
    }

    /// <summary>Caminho UNC aponta para outro servidor — quem protege aquele servidor é o agente dele.</summary>
    [Fact]
    public void Caminho_de_rede_e_recusado()
    {
        var r = ProtectedPaths.Parse(@"\\OUTRO-FS\Financeiro");

        Assert.Empty(r.Accepted);
        Assert.Contains("agente", r.Rejected[0].Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Motivo_da_recusa_e_legivel_para_o_admin()
    {
        var motivo = ProtectedPaths.Parse(@"C:\Windows").Rejected[0].Reason;

        Assert.Contains("sistema", motivo, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// O modo de proteção efetivo é o que o painel mostra ao admin. Reportar "protegido" quando só
/// metade das defesas está de pé é o mesmo pecado da nota mentirosa: parece completo sem ser.
/// </summary>
public class ProtectionModeTests
{
    [Fact]
    public void Sem_pastas_configuradas_nao_ha_protecao()
    {
        var m = ProtectionStatus.Evaluate(protectedPaths: 0, canariesPlanted: 0, fsrmAvailable: true, fsrmActive: false);

        Assert.Equal(ProtectionMode.None, m.Mode);
        Assert.Contains("pasta", m.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Sem_FSRM_o_modo_e_somente_canario_e_isso_e_dito()
    {
        var m = ProtectionStatus.Evaluate(protectedPaths: 2, canariesPlanted: 12, fsrmAvailable: false, fsrmActive: false);

        Assert.Equal(ProtectionMode.CanaryOnly, m.Mode);
        Assert.Contains("FSRM", m.Explanation);
    }

    [Fact]
    public void Com_FSRM_passivo_o_modo_e_auditoria()
    {
        var m = ProtectionStatus.Evaluate(protectedPaths: 2, canariesPlanted: 12, fsrmAvailable: true, fsrmActive: false);

        Assert.Equal(ProtectionMode.CanaryAndAudit, m.Mode);
    }

    [Fact]
    public void Com_FSRM_ativo_o_modo_e_bloqueio()
    {
        var m = ProtectionStatus.Evaluate(protectedPaths: 2, canariesPlanted: 12, fsrmAvailable: true, fsrmActive: true);

        Assert.Equal(ProtectionMode.CanaryAndBlock, m.Mode);
    }

    /// <summary>
    /// Pastas configuradas mas nenhum canário plantado é o caso do "achei que estava protegido":
    /// o produto precisa gritar isso, não arredondar para cima.
    /// </summary>
    [Fact]
    public void Pastas_sem_canario_nao_contam_como_protegidas()
    {
        var m = ProtectionStatus.Evaluate(protectedPaths: 2, canariesPlanted: 0, fsrmAvailable: true, fsrmActive: true);

        Assert.Equal(ProtectionMode.None, m.Mode);
        Assert.Contains("canário", m.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Explicacao_nunca_e_vazia()
    {
        foreach (var fsrm in new[] { true, false })
        foreach (var ativo in new[] { true, false })
        foreach (var canarios in new[] { 0, 6 })
        {
            var m = ProtectionStatus.Evaluate(1, canarios, fsrm, ativo);
            Assert.False(string.IsNullOrWhiteSpace(m.Explanation));
        }
    }
}
