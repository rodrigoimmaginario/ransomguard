using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// O contrato entre o Windows e o parser, escrito com XML que um Windows Server REAL produziu (capturado pela
/// CI em <c>windows-latest</c> pelos testes do serviço e guardado em <c>Fixtures/real</c>). As fixtures escritas à
/// mão descrevem o que achávamos que o Windows faz; estas descrevem o que ele faz.
/// </summary>
public class RealEventContractTests
{
    private static string Real(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "real", name));

    private static readonly ShareMap Map = new("FS01", new[] { new ShareEntry("rgit12fe010c", @"C:\rg-it-12fe010c\Financeiro") });

    /// <summary>
    /// Abrir um arquivo para gravação pede WriteData, AppendData, <b>WriteEA (%%4420)</b> e WriteAttributes. O parser
    /// tratava %%4420 como "apagar filho" (que é %%4422), então toda abertura para gravação virava exclusão.
    /// </summary>
    [Fact]
    public void Abrir_para_gravar_e_gravacao_nao_exclusao()
    {
        var e = SecurityEventParser.Parse(Real("5145-abrir-arquivo-novo-para-gravar.xml"))!;

        Assert.Equal(FileOp.Write, e.Op);
    }

    [Fact]
    public void Evento_de_share_real_traz_usuario_alvo_extensao_e_origem_local_no_loopback()
    {
        var p = SecurityEventParser.ParseDetailed(Real("5145-abrir-arquivo-novo-para-gravar.xml"))!;

        Assert.Equal(@"runnervmm7ud1\runneradmin", p.Event.User);
        Assert.Equal("rgit12fe010c", p.ShareName);
        Assert.Equal(@"C:\rg-it-12fe010c\Financeiro\2024\contrato.docx", p.LocalFullPath);
        Assert.Equal(".docx", p.Event.NewExtension);
        Assert.Equal(SecurityEventParser.LocalOrigin, p.Event.SourceIp);        // ::1
        Assert.Equal(new DateTime(2026, 11, 16, 13, 16, 52, DateTimeKind.Utc), p.Event.At.AddTicks(-(p.Event.At.Ticks % TimeSpan.TicksPerSecond)));

        var canonical = Map.Canonicalize(p);
        Assert.Equal(@"\\FS01\rgit12fe010c", canonical.Share);
        Assert.Equal(@"2024\contrato.docx", canonical.Path);
    }

    [Fact]
    public void A_gravacao_em_si_tambem_e_registrada_e_e_gravacao()
        => Assert.Equal(FileOp.Write, SecurityEventParser.Parse(Real("5145-gravar-dados.xml"))!.Op);

    [Fact]
    public void Listar_a_raiz_do_share_e_leitura()
    {
        var p = SecurityEventParser.ParseDetailed(Real("5145-listar-raiz-do-share.xml"))!;

        Assert.Equal(FileOp.Read, p.Event.Op);
        Assert.Equal(@"\\FS01\rgit12fe010c", Map.Canonicalize(p).Share);
    }

    [Fact]
    public void Canario_real_e_reconhecido_na_abertura_para_gravar()
    {
        var e = SecurityEventParser.Parse(Real("5145-abrir-canario-para-gravar.xml"))!;

        Assert.True(e.IsCanary);
        Assert.Equal(FileOp.Write, e.Op);
    }

    // ── como o Windows registra cada operação pela rede (CI, Windows Server, 2026-11-16) ──────────────────────
    // Gravar um arquivo: 1 evento de abertura (máscara ampla, inclui %%4417) + 1 evento só com %%4417 na primeira
    //   gravação. Vinte gravações no mesmo handle continuam sendo esses dois eventos.
    // Abrir para gravação SEM gravar: só o evento de abertura — no momento da abertura, igual a quem vai gravar.
    // Renomear: só o nome ANTIGO aparece, com acesso de exclusão. O nome novo (e a extensão nova) não é registrado.
    // Apagar: um evento de exclusão. Ler: um evento de leitura.

    [Fact]
    public void Abrir_para_gravar_sem_gravar_e_indistinguivel_de_gravar_no_evento_de_abertura()
        => Assert.Equal(FileOp.Write, SecurityEventParser.Parse(Real("5145-abrir-para-gravar-sem-gravar.xml"))!.Op);

    /// <summary>
    /// Limite do 5145 que o motor precisa respeitar: ransomware que cifra no lugar e depois renomeia para
    /// <c>.locked</c> NÃO entrega a extensão nova por este evento — quem vê o nome de destino é o file screen do FSRM.
    /// </summary>
    [Fact]
    public void Renomear_so_mostra_o_nome_antigo_como_exclusao()
    {
        var e = SecurityEventParser.Parse(Real("5145-renomear-so-mostra-o-nome-antigo.xml"))!;

        Assert.Equal(FileOp.Delete, e.Op);
        Assert.Equal("renomear.docx", e.Path);
        Assert.Equal(".docx", e.NewExtension);
    }

    /// <summary>Criar uma subpasta aparece como gravação na pasta (AppendData = AddSubdirectory): conta como um "arquivo" gravado.</summary>
    [Fact]
    public void Criar_subpasta_aparece_como_gravacao_na_pasta()
    {
        var e = SecurityEventParser.Parse(Real("5145-criar-subpasta.xml"))!;

        Assert.Equal(FileOp.Write, e.Op);
        Assert.Equal("2024", e.Path);
        Assert.Null(e.NewExtension);
    }

    [Fact]
    public void Apagar_e_exclusao_e_ler_e_leitura()
    {
        Assert.Equal(FileOp.Delete, SecurityEventParser.Parse(Real("5145-apagar.xml"))!.Op);
        Assert.Equal(FileOp.Read, SecurityEventParser.Parse(Real("5145-ler.xml"))!.Op);
    }

    /// <summary>
    /// No 4663 real o processo pode vir como caminho de DISPOSITIVO (<c>\Device\HarddiskVolume4\...</c>), não como
    /// <c>C:\...</c>. O PID e o nome da imagem continuam utilizáveis; comparar o caminho inteiro com o de
    /// <c>Get-Process</c> não funciona (pendência da fatia de resposta local).
    /// </summary>
    [Fact]
    public void Evento_de_objeto_real_traz_pid_e_imagem_do_processo()
    {
        var p = SecurityEventParser.ParseDetailed(Real("4663-gravar-local.xml"))!;

        Assert.Equal(FileOp.Write, p.Event.Op);
        Assert.Equal(0x18dc, p.Event.ProcessId);
        Assert.StartsWith(@"\Device\HarddiskVolume", p.Event.ProcessName);
        Assert.EndsWith("testhost.exe", p.Event.ProcessName);
        Assert.False(ResponseTarget.IsProtectedProcess(p.Event.ProcessName));
        Assert.Equal(@"C:\rg-it-8f79d436\Financeiro\2024\folha.xlsx", p.LocalFullPath);
        Assert.Equal(SecurityEventParser.LocalOrigin, p.Event.SourceIp);
    }
}
