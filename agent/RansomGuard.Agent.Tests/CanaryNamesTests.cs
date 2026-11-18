using RansomGuard.Agent.Posture;
using RansomGuard.Agent.Protection;
using RansomGuard.Core.Fsrm;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// B4 — nomes de canário por instalação. O nome fixo e autoidentificado (<c>*_ransomguard_canary.*</c>) estava no
/// código, que será aberto: qualquer ransomware o pularia com uma linha.
/// </summary>
public class CanaryNamesTests
{
    private static byte[] Seed(byte fill) => Enumerable.Repeat(fill, 32).ToArray();

    [Fact]
    public void Cada_instalacao_tem_os_seus_nomes_e_eles_nao_denunciam_o_produto()
    {
        var a = CanaryNames.Generate(Seed(1));
        var b = CanaryNames.Generate(Seed(2));

        Assert.Equal(9, a.Count);
        Assert.Equal(9, a.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Equal(a, CanaryNames.Generate(Seed(1)));                      // a mesma semente dá os mesmos nomes
        Assert.Empty(a.Intersect(b, StringComparer.OrdinalIgnoreCase));      // outra instalação, outros nomes
        Assert.All(a.Concat(b), n =>
        {
            Assert.DoesNotContain("ransom", n, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("canary", n, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("canario", n, StringComparison.OrdinalIgnoreCase);
            Assert.True(CanaryNames.IsValidFileName(n), n);
            Assert.Contains(Path.GetExtension(n), CanaryPlan.Extensions);
        });
    }

    /// <summary>A varredura alfabética encontra um canário antes e depois dos arquivos do cliente.</summary>
    [Fact]
    public void Os_nomes_continuam_nas_pontas_da_ordenacao_da_pasta()
    {
        var names = CanaryNames.Generate(Seed(7));
        var folder = names.Concat(new[] { "Ata de reuniao.docx", "contrato 2024.pdf", "Zeladoria.xlsx", "0001 nota.pdf" })
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();

        Assert.Contains(folder[0], names);
        Assert.Contains(folder[^1], names);
    }

    [Theory]
    [InlineData("Relatorio.docx", true)] [InlineData("a", true)] [InlineData("", false)] [InlineData("sub\\x.docx", false)]
    [InlineData("x:y.docx", false)] [InlineData("con", false)] [InlineData("nome?.pdf", false)] [InlineData("fim. ", false)]
    public void Nome_informado_pelo_administrador_precisa_ser_um_nome_de_arquivo(string name, bool valid)
        => Assert.Equal(valid, CanaryNames.IsValidFileName(name));

    [Fact]
    public void Lista_do_administrador_vale_no_lugar_da_gerada_e_o_que_e_invalido_ou_repetido_sai()
    {
        var parsed = CanaryNames.Parse("!Indice.xlsx; zz fechamento.pdf ;sub\\ruim.docx;!indice.xlsx;;");

        Assert.Equal(new[] { "!Indice.xlsx", "zz fechamento.pdf" }, parsed);
        Assert.Empty(CanaryNames.Parse(null));
    }

    [Fact]
    public void O_reconhecimento_soma_os_nomes_da_instalacao_aos_das_versoes_anteriores()
    {
        var name = $"!Planilha {Guid.NewGuid():N}.xlsx";
        Assert.False(CanaryPlan.IsCanary(name));

        CanaryPlan.Recognize(new[] { name });

        Assert.True(CanaryPlan.IsCanary(name));
        Assert.True(CanaryPlan.IsCanary(@"D:\Shares\2024\" + name.ToUpperInvariant()));
        Assert.True(CanaryPlan.IsCanary("!0__ransomguard_canary.docx"));     // canário de versão anterior segue reconhecido
        Assert.False(CanaryPlan.IsCanary("Planilha do cliente.xlsx"));
    }
}

/// <summary>
/// O plantio com canários próprios: planta os novos, tira os antigos e — o ponto de segurança — só trata como seu o
/// arquivo cujo CONTEÚDO confere. Um arquivo do cliente com nome de canário nunca é sobrescrito nem apagado.
/// </summary>
public class CanaryPlanterCustomNamesTests
{
    private sealed class Fs : ICanaryFileSystem
    {
        public Dictionary<string, Dictionary<string, byte[]>> Folders { get; } = new(StringComparer.OrdinalIgnoreCase);
        public void Folder(string path, params string[] clientFiles) =>
            Folders[path] = clientFiles.ToDictionary(f => f, f => System.Text.Encoding.UTF8.GetBytes("do cliente: " + f), StringComparer.OrdinalIgnoreCase);
        public IEnumerable<string> Names(string path) => Folders[path].Keys.OrderBy(n => n, StringComparer.OrdinalIgnoreCase);

        public bool DirectoryExists(string path) => Folders.ContainsKey(path);
        public IReadOnlyList<string> ListFiles(string path) => Folders[path].Keys.ToList();
        public IReadOnlyList<string> ListDirectories(string path) =>
            Folders.Keys.Where(k => k.StartsWith(path + "\\", StringComparison.OrdinalIgnoreCase) && !k[(path.Length + 1)..].Contains('\\')).ToList();
        public void WriteCanary(string fullPath, string content) => WriteCanary(fullPath, System.Text.Encoding.UTF8.GetBytes(content));
        public void WriteCanary(string fullPath, byte[] content) => Folders[Path.GetDirectoryName(fullPath)!][Path.GetFileName(fullPath)] = content;
        public bool ContentEquals(string fullPath, byte[] expected) =>
            Folders[Path.GetDirectoryName(fullPath)!].TryGetValue(Path.GetFileName(fullPath), out var actual) && actual.AsSpan().SequenceEqual(expected);
        public void Delete(string fullPath) => Folders[Path.GetDirectoryName(fullPath)!].Remove(Path.GetFileName(fullPath));
    }

    private static readonly byte[] Seed = Enumerable.Range(0, 32).Select(i => (byte)(i * 7 + 3)).ToArray();
    private static readonly string[] Names = { $"!Indice {Guid.NewGuid():N}.xlsx", $"~Fechamento {Guid.NewGuid():N}.pdf" };
    private static CanarySet Set(params string[] names) => new(names.Length > 0 ? names : Names, name => CanaryNames.ContentFor(Seed, name));

    [Fact]
    public void O_conteudo_e_proprio_da_instalacao_tem_cara_do_tipo_e_nao_cita_o_produto()
    {
        var pdf = CanaryNames.ContentFor(Seed, "~Fechamento.pdf");
        var docx = CanaryNames.ContentFor(Seed, "!Indice.docx");

        Assert.Equal(pdf, CanaryNames.ContentFor(Seed, "~FECHAMENTO.PDF"));                 // estável por nome
        Assert.NotEqual(pdf, CanaryNames.ContentFor(Seed.Reverse().ToArray(), "~Fechamento.pdf"));   // outra instalação, outro conteúdo
        Assert.StartsWith("%PDF-", System.Text.Encoding.Latin1.GetString(pdf, 0, 8));
        Assert.Equal(new byte[] { 0x50, 0x4B, 0x03, 0x04 }, docx.Take(4));
        Assert.InRange(pdf.Length, 12_000, 60_000);
        Assert.DoesNotContain("ransomguard", System.Text.Encoding.Latin1.GetString(pdf), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Planta_os_canarios_da_instalacao_e_retira_os_de_nome_antigo()
    {
        var fs = new Fs();
        fs.Folder(@"D:\Dados", "contrato.docx", "!0__ransomguard_canary.docx", "~zz__ransomguard_canary.pdf");
        fs.Folder(@"D:\Dados\2024", "nota.pdf");

        var results = new CanaryPlanter(fs, Set()).Plant(new[] { @"D:\Dados" });

        Assert.All(results, r => Assert.True(r.Ok, r.Error));
        Assert.Equal(new[] { "contrato.docx" }.Concat(Names).OrderBy(n => n, StringComparer.OrdinalIgnoreCase), fs.Names(@"D:\Dados"));
        Assert.Equal(new[] { "nota.pdf" }.Concat(Names).OrderBy(n => n, StringComparer.OrdinalIgnoreCase), fs.Names(@"D:\Dados\2024"));
        Assert.Equal(4, CanaryPlanter.CountPlanted(results));

        // Rodar de novo não planta nem remove nada.
        var again = new CanaryPlanter(fs, Set()).Plant(new[] { @"D:\Dados" });
        Assert.Equal(0, again.Sum(r => r.Planted));
        Assert.Equal(4, again.Sum(r => r.AlreadyPresent));
    }

    /// <summary>
    /// Sem marca no nome, "é canário" não pode ser decidido pelo nome. Se fosse, desfazer a proteção apagaria o
    /// arquivo de um cliente que por acaso — ou por escolha infeliz do administrador — tem o mesmo nome.
    /// </summary>
    [Fact]
    public void Arquivo_do_cliente_com_nome_de_canario_nao_e_contado_nem_sobrescrito_nem_apagado()
    {
        var fs = new Fs();
        fs.Folder(@"D:\Dados", "contrato.docx", Names[0]);                 // o cliente já tem um arquivo com esse nome
        var original = fs.Folders[@"D:\Dados"][Names[0]];
        var planter = new CanaryPlanter(fs, Set());

        var planted = planter.Plant(new[] { @"D:\Dados" });

        Assert.Equal(1, planted.Sum(r => r.Collisions));
        Assert.Equal(1, CanaryPlanter.CountPlanted(planted));               // só o outro nome virou canário
        Assert.Same(original, fs.Folders[@"D:\Dados"][Names[0]]);

        planter.Remove(new[] { @"D:\Dados" });

        Assert.Equal(new[] { Names[0], "contrato.docx" }.OrderBy(n => n, StringComparer.OrdinalIgnoreCase), fs.Names(@"D:\Dados"));
        Assert.Same(original, fs.Folders[@"D:\Dados"][Names[0]]);
    }

    [Fact]
    public void Nomes_trocados_pelo_administrador_fazem_os_canarios_anteriores_sairem_no_proximo_plantio()
    {
        var fs = new Fs();
        fs.Folder(@"D:\Dados", "contrato.docx");
        new CanaryPlanter(fs, Set()).Plant(new[] { @"D:\Dados" });
        var novos = new[] { $"!Novo {Guid.NewGuid():N}.docx" };

        new CanaryPlanter(fs, Set(novos)).Plant(new[] { @"D:\Dados" });

        Assert.Equal(new[] { "contrato.docx", novos[0] }.OrderBy(n => n, StringComparer.OrdinalIgnoreCase), fs.Names(@"D:\Dados"));
    }

    /// <summary>Quem constrói o plantio sem os canários da instalação só enxerga — e só apaga — os de marca antiga.</summary>
    [Fact]
    public void Sem_os_canarios_da_instalacao_a_remocao_so_leva_os_de_marca_antiga()
    {
        var fs = new Fs();
        fs.Folder(@"D:\Dados", "contrato.docx", "!0__ransomguard_canary.docx");
        new CanaryPlanter(fs, Set()).Plant(new[] { @"D:\Outra" });          // registra os nomes; não toca em D:\Dados
        fs.Folders[@"D:\Dados"][Names[0]] = CanaryNames.ContentFor(Seed, Names[0]);

        new CanaryPlanter(fs).Remove(new[] { @"D:\Dados" });

        Assert.Equal(new[] { Names[0], "contrato.docx" }.OrderBy(n => n, StringComparer.OrdinalIgnoreCase), fs.Names(@"D:\Dados"));
    }

    [Fact]
    public void A_postura_confere_os_nomes_da_instalacao()
    {
        var files = new Dictionary<string, IReadOnlyList<string>> { [@"D:\Dados"] = Names.Append("contrato.docx").ToList() };

        Assert.True(CanaryPresence.Evaluate(new[] { @"D:\Dados" }, p => files[p], Names));
        Assert.False(CanaryPresence.Evaluate(new[] { @"D:\Dados" }, p => new[] { Names[0] }, Names));
        Assert.False(CanaryPresence.Evaluate(new[] { @"D:\Dados" }, p => files[p]));   // sem a lista, espera os nomes antigos
    }
}
