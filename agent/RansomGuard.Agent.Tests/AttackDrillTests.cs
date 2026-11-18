using RansomGuard.Agent.Drill;
using RansomGuard.Core.Fsrm;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// O ensaio **imita ransomware**. Se puder ser apontado para dados de produção por engano, ele é o
/// incidente. Por isso os testes das travas vêm primeiro e são os mais rigorosos do projeto: um
/// utilitário defensivo que destrói dado do cliente é pior que não ter utilitário nenhum.
/// </summary>
public class AttackDrillSafetyTests
{
    private sealed class FakeFs : IDrillFileSystem
    {
        public readonly Dictionary<string, List<string>> Dirs = new(StringComparer.OrdinalIgnoreCase);
        public readonly List<string> Deleted = new();
        public readonly List<(string From, string To)> Moved = new();
        public readonly Dictionary<string, string> Written = new(StringComparer.OrdinalIgnoreCase);
        public readonly List<string> Touched = new();

        public bool DirectoryExists(string path) => Dirs.ContainsKey(path);
        public bool FileExists(string full) =>
            Dirs.TryGetValue(Path.GetDirectoryName(full)!, out var f) &&
            f.Contains(Path.GetFileName(full), StringComparer.OrdinalIgnoreCase);
        public IReadOnlyList<string> ListFiles(string path) =>
            Dirs.TryGetValue(path, out var f) ? f : Array.Empty<string>();
        public void CreateDirectory(string path) { if (!Dirs.ContainsKey(path)) Dirs[path] = new(); }
        public void WriteFile(string full, string content)
        {
            Written[full] = content;
            var dir = Path.GetDirectoryName(full)!;
            CreateDirectory(dir);
            var nome = Path.GetFileName(full);
            if (!Dirs[dir].Contains(nome, StringComparer.OrdinalIgnoreCase)) Dirs[dir].Add(nome);
        }
        public void Move(string from, string to)
        {
            Moved.Add((from, to));
            var dir = Path.GetDirectoryName(from)!;
            Dirs[dir].Remove(Path.GetFileName(from));
            Dirs[dir].Add(Path.GetFileName(to));
        }
        public void Touch(string full) => Touched.Add(full);
        public void DeleteDirectory(string path) { Deleted.Add(path); Dirs.Remove(path); }
    }

    private const string Pasta = @"D:\ensaio-ransomguard";

    /// <summary>Pasta pronta: com marcador e arquivos.</summary>
    private static FakeFs Preparada(params string[] extras)
    {
        var fs = new FakeFs();
        fs.CreateDirectory(Pasta);
        fs.Dirs[Pasta].Add(AttackDrill.MarkerFile);
        for (var i = 1; i <= 10; i++) fs.Dirs[Pasta].Add($"documento_{i:D4}.docx");
        fs.Dirs[Pasta].AddRange(extras);
        return fs;
    }

    // ── Trava 1: marcador obrigatório ───────────────────────────────────────────────────────

    /// <summary>
    /// A trava mais importante do projeto inteiro. Uma pasta com dados reais nunca terá o marcador,
    /// então o ensaio se recusa a tocá-la — mesmo que o operador aponte para ela.
    /// </summary>
    [Fact]
    public void Recusa_pasta_sem_marcador()
    {
        var fs = new FakeFs();
        fs.CreateDirectory(@"D:\Shares\Financeiro");
        fs.Dirs[@"D:\Shares\Financeiro"].Add("contrato.docx");

        var r = new AttackDrill(fs).CheckTarget(@"D:\Shares\Financeiro");

        Assert.NotNull(r);
        Assert.Contains(AttackDrill.MarkerFile, r!.Reason);
    }

    [Fact]
    public void Aceita_pasta_com_marcador()
        => Assert.Null(new AttackDrill(Preparada()).CheckTarget(Pasta));

    [Fact]
    public void Recusa_pasta_que_nao_existe()
    {
        var r = new AttackDrill(new FakeFs()).CheckTarget(@"D:\nao-existe");

        Assert.NotNull(r);
        Assert.Contains("não existe", r!.Reason);
    }

    // ── Trava 2: caminhos perigosos (mesma lista do F12) ────────────────────────────────────

    [Theory]
    [InlineData(@"C:\")]
    [InlineData(@"C:\Windows")]
    [InlineData(@"C:\Program Files")]
    [InlineData(@"\\SERVIDOR\Financeiro")]
    [InlineData(@"..\dados")]
    public void Recusa_caminho_perigoso_mesmo_com_marcador(string caminho)
    {
        var fs = new FakeFs();
        fs.CreateDirectory(caminho);
        fs.Dirs[caminho].Add(AttackDrill.MarkerFile);

        Assert.NotNull(new AttackDrill(fs).CheckTarget(caminho));
    }

    // ── Trava 3: nunca criptografa ──────────────────────────────────────────────────────────

    /// <summary>
    /// O conteúdo escrito é inerte e legível. Não há chave, não há cifra — nada aqui pode ficar
    /// irrecuperável, porque nada é perdido de verdade.
    /// </summary>
    [Fact]
    public void Reescrita_grava_conteudo_inerte_e_legivel()
    {
        var fs = Preparada();
        var drill = new AttackDrill(fs);

        drill.Execute(Pasta, drill.Plan(Pasta, DrillScenario.MassRewrite));

        Assert.NotEmpty(fs.Written);
        foreach (var c in fs.Written.Values)
        {
            Assert.Contains("ensaio", c, StringComparison.OrdinalIgnoreCase);
            // Texto legível, não bloco binário: conteúdo cifrado teria caracteres de controle.
            Assert.All(c, ch => Assert.True(!char.IsControl(ch) || ch is '\r' or '\n',
                $"caractere de controle inesperado: {(int)ch}"));
        }
    }

    [Fact]
    public void Bilhete_de_resgate_se_identifica_como_ensaio()
    {
        Assert.Contains("NAO E UM ATAQUE REAL", AttackDrill.RansomNoteContent);
        Assert.Contains("Nenhum arquivo foi criptografado", AttackDrill.RansomNoteContent);
    }

    // ── Trava 4: planejar não executa ───────────────────────────────────────────────────────

    /// <summary>`Plan` descreve; só `Execute` age. É o que permite mostrar o plano e pedir confirmação.</summary>
    [Fact]
    public void Planejar_nao_toca_em_nada()
    {
        var fs = Preparada();

        var plano = new AttackDrill(fs).Plan(Pasta, DrillScenario.Full);

        Assert.NotEmpty(plano);
        Assert.Empty(fs.Written);
        Assert.Empty(fs.Moved);
        Assert.Empty(fs.Touched);
        Assert.Empty(fs.Deleted);
    }

    // ── Trava 5: reversível ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Limpar_apaga_a_pasta_de_ensaio()
    {
        var fs = Preparada();

        Assert.Null(new AttackDrill(fs).Clean(Pasta));
        Assert.Contains(Pasta, fs.Deleted);
    }

    /// <summary>Limpar tem a MESMA trava da execução: sem marcador, não se apaga nada.</summary>
    [Fact]
    public void Limpar_recusa_pasta_sem_marcador()
    {
        var fs = new FakeFs();
        fs.CreateDirectory(@"D:\Shares\Financeiro");

        Assert.NotNull(new AttackDrill(fs).Clean(@"D:\Shares\Financeiro"));
        Assert.Empty(fs.Deleted);
    }

    // ── Preparação da pasta ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Preparar_cria_marcador_e_arquivos_descartaveis()
    {
        var fs = new FakeFs();

        Assert.Null(new AttackDrill(fs).PrepareFolder(Pasta, fileCount: 5));

        Assert.Contains(AttackDrill.MarkerFile, fs.Dirs[Pasta]);
        Assert.Equal(5, fs.Dirs[Pasta].Count(f => f.StartsWith("documento_")));
    }

    /// <summary>
    /// Pasta com conteúdo desconhecido pode ser do cliente. O ensaio nunca reaproveita — exige
    /// pasta vazia ou já marcada.
    /// </summary>
    [Fact]
    public void Preparar_recusa_pasta_com_conteudo_desconhecido()
    {
        var fs = new FakeFs();
        fs.CreateDirectory(@"D:\Dados");
        fs.Dirs[@"D:\Dados"].Add("contrato.docx");

        var r = new AttackDrill(fs).PrepareFolder(@"D:\Dados");

        Assert.NotNull(r);
        Assert.Contains("já tem arquivos", r!.Reason);
    }

    [Fact]
    public void Preparar_aceita_repetir_na_pasta_ja_marcada()
        => Assert.Null(new AttackDrill(Preparada()).PrepareFolder(Pasta, fileCount: 3));

    [Fact]
    public void Preparar_recusa_caminho_perigoso()
        => Assert.NotNull(new AttackDrill(new FakeFs()).PrepareFolder(@"C:\Windows"));
}

/// <summary>
/// Contrato do ataque a partir do CLIENTE (F19): o provocador roda numa estação e mira o share de
/// teste por um <b>drive mapeado</b> (<c>X:\…</c>). Assim as escritas viajam por SMB e o file server
/// registra o evento 5145 com o <b>IP remoto real</b> do cliente — o elo que o ensaio local (que só
/// gera <c>::1</c>) nunca prova.
///
/// A trava tem que deixar o drive mapeado passar (parece local) e continuar recusando o caminho
/// <b>UNC</b> (<c>\\servidor\share</c>): apontar o provocador direto para outro servidor é justamente
/// o que não queremos — quem protege aquele servidor é o agente instalado nele.
/// </summary>
public class AttackDrillRemoteAttackContractTests
{
    private sealed class Fs : IDrillFileSystem
    {
        public readonly Dictionary<string, List<string>> Dirs = new(StringComparer.OrdinalIgnoreCase);
        public bool DirectoryExists(string path) => Dirs.ContainsKey(path);
        public bool FileExists(string full) =>
            Dirs.TryGetValue(Path.GetDirectoryName(full)!, out var f) &&
            f.Contains(Path.GetFileName(full), StringComparer.OrdinalIgnoreCase);
        public IReadOnlyList<string> ListFiles(string path) =>
            Dirs.TryGetValue(path, out var f) ? f : Array.Empty<string>();
        public void CreateDirectory(string path) { if (!Dirs.ContainsKey(path)) Dirs[path] = new(); }
        public void WriteFile(string full, string content) { }
        public void Move(string from, string to) { }
        public void Touch(string full) { }
        public void DeleteDirectory(string path) { }
    }

    private static Fs Marcada(string pasta)
    {
        var fs = new Fs();
        fs.CreateDirectory(pasta);
        fs.Dirs[pasta].Add(AttackDrill.MarkerFile);
        return fs;
    }

    [Theory]
    [InlineData(@"X:\ensaio")]        // drive de rede mapeado (net use X: \\FS01\teste)
    [InlineData(@"Z:\rg-ensaio")]
    public void Aceita_drive_mapeado_com_marcador(string pasta)
        => Assert.Null(new AttackDrill(Marcada(pasta)).CheckTarget(pasta));

    [Theory]
    [InlineData(@"\\FS01\teste")]
    [InlineData(@"\\FS01\teste\ensaio")]
    [InlineData(@"//FS01/teste")]
    public void Recusa_UNC_mesmo_com_marcador(string pasta)
    {
        var r = new AttackDrill(Marcada(pasta)).CheckTarget(pasta);

        Assert.NotNull(r);
        // A mensagem manda instalar o agente no servidor de destino — não atacar de fora.
        Assert.Contains("rede", r!.Reason, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Preparar também recusa UNC: nem a pasta de ensaio pode ser criada direto no share por caminho
    /// de rede — o operador tem que mapear um drive primeiro.
    /// </summary>
    [Fact]
    public void Preparar_recusa_UNC()
        => Assert.NotNull(new AttackDrill(new Fs()).PrepareFolder(@"\\FS01\teste\ensaio"));
}

/// <summary>Os cenários precisam provocar exatamente o sinal que o produto sabe detectar.</summary>
public class AttackDrillScenarioTests
{
    private sealed class Fs : IDrillFileSystem
    {
        public readonly List<string> Files = new();
        public readonly List<string> Touched = new();
        public readonly List<(string, string)> Moved = new();
        public readonly Dictionary<string, string> Written = new();

        public bool DirectoryExists(string path) => true;
        public bool FileExists(string full) => Files.Contains(Path.GetFileName(full));
        public IReadOnlyList<string> ListFiles(string path) => Files;
        public void CreateDirectory(string path) { }
        public void WriteFile(string full, string c)
        {
            Written[full] = c;
            // Sobrescrever não duplica a entrada — é o que um disco de verdade faz.
            var nome = Path.GetFileName(full);
            if (!Files.Contains(nome, StringComparer.OrdinalIgnoreCase)) Files.Add(nome);
        }
        public void Move(string from, string to)
        {
            Moved.Add((from, to));
            Files.Remove(Path.GetFileName(from));
            Files.Add(Path.GetFileName(to));
        }
        public void Touch(string full) => Touched.Add(full);
        public void DeleteDirectory(string path) { }
    }

    private const string Pasta = @"D:\ensaio";

    private static Fs ComArquivos(int n = 10, bool comCanario = true)
    {
        var fs = new Fs();
        fs.Files.Add(AttackDrill.MarkerFile);
        for (var i = 1; i <= n; i++) fs.Files.Add($"documento_{i:D4}.docx");
        if (comCanario) fs.Files.AddRange(CanaryPlan.NamesFor(Pasta));
        return fs;
    }

    [Fact]
    public void Reescrita_produz_a_extensao_do_catalogo()
    {
        var fs = ComArquivos();
        var drill = new AttackDrill(fs);

        var plano = drill.Plan(Pasta, DrillScenario.MassRewrite);

        Assert.All(plano, a => Assert.EndsWith(AttackDrill.EncryptedExtension, a.NewName));
        // A extensão precisa estar no catálogo semente, senão o FSRM não a reconheceria.
        Assert.Contains("*" + AttackDrill.EncryptedExtension, SeedCatalog.Patterns);
    }

    [Fact]
    public void Renomeacao_troca_a_extensao_original()
    {
        var plano = new AttackDrill(ComArquivos()).Plan(Pasta, DrillScenario.MassRename);

        Assert.All(plano, a => Assert.DoesNotContain(".docx", a.NewName!));
    }

    /// <summary>É o sinal de maior confiança do produto — sem ele, não há contenção.</summary>
    [Fact]
    public void Cenario_canario_toca_todos_os_canarios()
    {
        var fs = ComArquivos();
        var drill = new AttackDrill(fs);

        var plano = drill.Plan(Pasta, DrillScenario.Canary);
        drill.Execute(Pasta, plano);

        Assert.Equal(CanaryPlan.NamesFor(Pasta).Count, fs.Touched.Count);
        Assert.All(fs.Touched, t => Assert.True(CanaryPlan.IsCanary(t)));
    }

    [Fact]
    public void Sem_canario_plantado_o_cenario_fica_vazio_e_isso_e_correto()
    {
        // Se o agente ainda não plantou, não há o que tocar — o ensaio não inventa canário.
        var plano = new AttackDrill(ComArquivos(comCanario: false)).Plan(Pasta, DrillScenario.Canary);

        Assert.Empty(plano);
    }

    [Fact]
    public void Bilhete_casa_com_o_padrao_do_catalogo()
    {
        Assert.StartsWith("HOW_TO_DECRYPT", AttackDrill.RansomNoteName);
        Assert.Contains(SeedCatalog.Patterns, p => p.StartsWith("HOW_TO_DECRYPT"));
    }

    [Fact]
    public void Completo_segue_a_ordem_de_um_ataque_real()
    {
        var plano = new AttackDrill(ComArquivos()).Plan(Pasta, DrillScenario.Full);

        // Varre (toca o canário) → cifra → deixa o bilhete.
        Assert.Equal("canário", plano[0].Kind);
        Assert.Contains(plano, a => a.Kind == "reescrita");
        Assert.Equal("bilhete de resgate", plano[^1].Kind);
    }

    [Fact]
    public void O_marcador_nunca_e_alvo()
    {
        var plano = new AttackDrill(ComArquivos()).Plan(Pasta, DrillScenario.Full);

        Assert.DoesNotContain(plano, a => a.Target == AttackDrill.MarkerFile);
    }

    /// <summary>Rodar duas vezes não deve reprocessar o que já foi "cifrado".</summary>
    [Fact]
    public void Arquivo_ja_atacado_nao_entra_de_novo()
    {
        var fs = ComArquivos();
        var drill = new AttackDrill(fs);
        drill.Execute(Pasta, drill.Plan(Pasta, DrillScenario.MassRewrite));

        var segundo = drill.Plan(Pasta, DrillScenario.MassRewrite);

        Assert.DoesNotContain(segundo, a => a.Kind == "reescrita");
    }

    [Fact]
    public void Volume_respeita_o_limite_pedido()
    {
        var plano = new AttackDrill(ComArquivos(n: 500, comCanario: false))
            .Plan(Pasta, DrillScenario.MassRewrite, count: 120);

        Assert.Equal(120, plano.Count);
    }

    [Fact]
    public void Execute_conta_as_acoes_realizadas()
    {
        var fs = ComArquivos();
        var drill = new AttackDrill(fs);
        var plano = drill.Plan(Pasta, DrillScenario.Full);

        Assert.Equal(plano.Count, drill.Execute(Pasta, plano));
    }
}
