using RansomGuard.Agent.Posture;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// Parsing das saídas do Windows que alimentam a postura. É aqui que mora a inteligência dos
/// coletores — o serviço só invoca o PowerShell e entrega o texto. Assim a parte que erra fica
/// coberta por teste, e não depende de rodar num file server.
/// </summary>
public class SharePermissionReaderTests
{
    /// <summary>Saída típica de <c>Get-SmbShare | Get-SmbShareAccess | Format-Table</c>.</summary>
    private const string SaidaComShareAberto = """
        Name        ScopeName AccountName                  AccessControlType AccessRight
        ----        --------- -----------                  ----------------- -----------
        Financeiro  *         Everyone                     Allow             Full
        Financeiro  *         CORP\Financeiro-RW           Allow             Change
        Publica     *         BUILTIN\Users                Allow             Read
        """;

    private const string SaidaFechada = """
        Name        ScopeName AccountName                  AccessControlType AccessRight
        ----        --------- -----------                  ----------------- -----------
        Financeiro  *         CORP\Financeiro-RW           Allow             Change
        Contratos   *         CORP\Juridico                Allow             Full
        """;

    [Fact]
    public void Everyone_com_escrita_e_share_aberto()
        => Assert.True(SharePermissionReader.HasBroadWriteAccess(SaidaComShareAberto));

    [Fact]
    public void So_grupos_especificos_nao_e_share_aberto()
        => Assert.False(SharePermissionReader.HasBroadWriteAccess(SaidaFechada));

    /// <summary>Everyone só com leitura não permite criptografar — não é o achado.</summary>
    [Fact]
    public void Everyone_somente_leitura_nao_conta()
    {
        const string s = """
            Name      ScopeName AccountName AccessControlType AccessRight
            ----      --------- ----------- ----------------- -----------
            Publica   *         Everyone    Allow             Read
            """;
        Assert.False(SharePermissionReader.HasBroadWriteAccess(s));
    }

    /// <summary>Deny para Everyone é o contrário do achado — não pode ser lido como permissão.</summary>
    [Fact]
    public void Everyone_com_deny_nao_conta()
    {
        const string s = """
            Name      ScopeName AccountName AccessControlType AccessRight
            ----      --------- ----------- ----------------- -----------
            Publica   *         Everyone    Deny              Full
            """;
        Assert.False(SharePermissionReader.HasBroadWriteAccess(s));
    }

    [Theory]
    [InlineData("Everyone")]
    [InlineData("BUILTIN\\Users")]
    [InlineData("NT AUTHORITY\\Authenticated Users")]
    [InlineData("CORP\\Domain Users")]
    [InlineData("Todos")]                       // Windows em português
    public void Grupos_amplos_reconhecidos(string conta)
    {
        var s = $"""
            Name      ScopeName AccountName AccessControlType AccessRight
            ----      --------- ----------- ----------------- -----------
            Dados     *         {conta}     Allow             Change
            """;
        Assert.True(SharePermissionReader.HasBroadWriteAccess(s));
    }

    /// <summary>
    /// Shares administrativos (C$, ADMIN$, IPC$) dão acesso amplo por definição e só a
    /// administradores. Contá-los faria todo servidor Windows nascer com achado crítico.
    /// </summary>
    [Theory]
    [InlineData("C$")]
    [InlineData("ADMIN$")]
    [InlineData("IPC$")]
    public void Shares_administrativos_sao_ignorados(string share)
    {
        var s = $"""
            Name      ScopeName AccountName AccessControlType AccessRight
            ----      --------- ----------- ----------------- -----------
            {share}   *         Everyone    Allow             Full
            """;
        Assert.False(SharePermissionReader.HasBroadWriteAccess(s));
    }

    [Fact]
    public void Saida_vazia_ou_ruido_nao_afirma_nada()
    {
        Assert.Null(SharePermissionReader.TryRead(""));
        Assert.Null(SharePermissionReader.TryRead("   \n  "));
        Assert.Null(SharePermissionReader.TryRead("Get-SmbShare : O termo não é reconhecido"));
    }

    [Fact]
    public void Saida_valida_devolve_resposta_e_nao_desconhecido()
    {
        Assert.True(SharePermissionReader.TryRead(SaidaComShareAberto));
        Assert.False(SharePermissionReader.TryRead(SaidaFechada));
    }
}

/// <summary>
/// Leitura da política de auditoria — e a distinção que custou uma validação real para aparecer:
///
/// <b>"File Share" e "Detailed File Share" são subcategorias diferentes.</b> A primeira gera o
/// evento 5140, um por <i>conexão</i> ao share. A segunda gera o <b>5145</b>, um por <i>arquivo</i>
/// — e é só esse que serve para detectar criptografia em massa.
///
/// Como "File Share" é substring de "Detailed File Share", um casamento frouxo lê a subcategoria
/// errada e responde "auditoria ligada" enquanto o evento que o produto precisa segue desligado.
/// Ou seja: o mesmo erro da nota mentirosa, em outro lugar.
/// </summary>
public class AuditPolicyReaderTests
{
    /// <summary>Saída típica de <c>auditpol /get /category:"Object Access"</c>.</summary>
    private const string Completa = """
        System audit policy
        Category/Subcategory                      Setting
        Object Access
          File System                             No Auditing
          File Share                              Success
          Detailed File Share                     No Auditing
        """;

    [Fact]
    public void File_Share_ligada_nao_significa_Detailed_File_Share_ligada()
    {
        // Foi exatamente o que aconteceu na validação: o owner ligou "File Share", o parser
        // respondeu "ligada", e nenhum 5145 apareceu.
        Assert.True(AuditPolicyReader.TryRead(Completa, AuditSubcategory.FileShare));
        Assert.False(AuditPolicyReader.TryRead(Completa, AuditSubcategory.DetailedFileShare));
    }

    [Fact]
    public void Le_a_subcategoria_pedida_e_nao_a_primeira_que_aparece()
        => Assert.False(AuditPolicyReader.TryRead(Completa, AuditSubcategory.FileSystem));

    [Theory]
    [InlineData("Success")]
    [InlineData("Success and Failure")]
    public void Sucesso_habilitado_significa_auditoria_ligada(string setting)
    {
        var s = $"""
            Category/Subcategory                      Setting
              Detailed File Share                     {setting}
            """;
        Assert.True(AuditPolicyReader.TryRead(s, AuditSubcategory.DetailedFileShare));
    }

    [Theory]
    [InlineData("No Auditing")]
    [InlineData("Failure")]   // só falha não gera 5145 de acesso bem-sucedido — e é o acesso que
                              // existe num ataque com credencial válida
    public void Sem_sucesso_auditado_e_lido_como_desligada(string setting)
    {
        var s = $"""
            Category/Subcategory                      Setting
              Detailed File Share                     {setting}
            """;
        Assert.False(AuditPolicyReader.TryRead(s, AuditSubcategory.DetailedFileShare));
    }

    [Fact]
    public void Windows_em_portugues_e_reconhecido()
    {
        const string s = """
            Categoria/Subcategoria                    Configuração
            Acesso a Objeto
              Compartilhamento de Arquivos Detalhado  Êxito e Falha
            """;
        Assert.True(AuditPolicyReader.TryRead(s, AuditSubcategory.DetailedFileShare));
    }

    /// <summary>Em português, "Compartilhamento de Arquivos" também é prefixo do detalhado.</summary>
    [Fact]
    public void Portugues_tambem_distingue_as_duas_subcategorias()
    {
        const string s = """
            Categoria/Subcategoria                    Configuração
              Compartilhamento de Arquivos            Êxito
              Compartilhamento de Arquivos Detalhado  Sem Auditoria
            """;
        Assert.True(AuditPolicyReader.TryRead(s, AuditSubcategory.FileShare));
        Assert.False(AuditPolicyReader.TryRead(s, AuditSubcategory.DetailedFileShare));
    }

    [Fact]
    public void Subcategoria_ausente_da_saida_vira_desconhecido()
    {
        const string s = """
            Category/Subcategory                      Setting
              File System                             Success
            """;
        Assert.Null(AuditPolicyReader.TryRead(s, AuditSubcategory.DetailedFileShare));
    }

    [Fact]
    public void Saida_inutil_vira_desconhecido()
    {
        Assert.Null(AuditPolicyReader.TryRead("", AuditSubcategory.DetailedFileShare));
        Assert.Null(AuditPolicyReader.TryRead("Erro: acesso negado.", AuditSubcategory.DetailedFileShare));
        Assert.Null(AuditPolicyReader.TryRead("Category/Subcategory   Setting", AuditSubcategory.DetailedFileShare));
    }

    /// <summary>
    /// O comando que o produto sugere precisa ser o que de fato liga o 5145 — em qualquer idioma do Windows, por isso
    /// aponta a subcategoria pelo GUID (o nome muda com o idioma, e "File Share" é outra coisa).
    /// </summary>
    [Fact]
    public void Comando_de_correcao_aponta_a_subcategoria_certa()
    {
        Assert.Contains("{0CCE9244-69AE-11D9-BED3-505054503030}", AuditSubcategory.DetailedFileShare.EnableCommand);
        Assert.DoesNotContain(AuditSubcategory.FileShare.Guid, AuditSubcategory.DetailedFileShare.EnableCommand);
        Assert.Contains("success:enable", AuditSubcategory.DetailedFileShare.EnableCommand);
    }
}

public class CanaryPresenceTests
{
    private static readonly string[] Pastas = { @"D:\Shares\Financeiro" };

    [Fact]
    public void Sem_pasta_protegida_nao_da_para_afirmar()
        => Assert.Null(CanaryPresence.Evaluate(Array.Empty<string>(), _ => Array.Empty<string>()));

    [Fact]
    public void Canarios_presentes_em_todas_as_pastas()
    {
        var esperados = RansomGuard.Core.Fsrm.CanaryPlan.NamesFor(Pastas[0]);
        Assert.True(CanaryPresence.Evaluate(Pastas, _ => esperados));
    }

    [Fact]
    public void Pasta_sem_canario_derruba_a_resposta()
        => Assert.False(CanaryPresence.Evaluate(Pastas, _ => Array.Empty<string>()));

    /// <summary>Uma pasta protegida sem canário já basta: o buraco está aberto ali.</summary>
    [Fact]
    public void Basta_uma_pasta_descoberta()
    {
        var duas = new[] { @"D:\A", @"D:\B" };
        var r = CanaryPresence.Evaluate(duas,
            pasta => pasta == @"D:\A" ? RansomGuard.Core.Fsrm.CanaryPlan.NamesFor(pasta) : Array.Empty<string>());
        Assert.False(r);
    }

    [Fact]
    public void Erro_ao_listar_a_pasta_vira_desconhecido()
        => Assert.Null(CanaryPresence.Evaluate(Pastas, _ => throw new UnauthorizedAccessException()));
}
