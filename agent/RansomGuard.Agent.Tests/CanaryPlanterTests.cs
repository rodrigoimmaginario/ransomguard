using RansomGuard.Agent.Protection;
using RansomGuard.Core.Fsrm;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// O plantio é a primeira escrita do produto no ambiente do cliente. Os testes aqui cobrem menos o
/// "funciona" e mais o "não estraga nada" — que é o que decide se um admin confia em deixar o
/// agente mexer nas pastas dele.
/// </summary>
public class CanaryPlanterTests
{
    /// <summary>Disco de mentira, com falhas controláveis.</summary>
    private sealed class FakeFs : ICanaryFileSystem
    {
        public readonly Dictionary<string, List<string>> Dirs = new(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string, string> Written = new(StringComparer.OrdinalIgnoreCase);
        public readonly List<string> Deleted = new();
        public Exception? FalhaAoEscrever;
        public Exception? FalhaAoListar;

        public FakeFs(params string[] pastas)
        {
            foreach (var p in pastas) Dirs[p] = new List<string>();
        }

        public bool DirectoryExists(string path) => Dirs.ContainsKey(path);

        public IReadOnlyList<string> ListFiles(string path) =>
            FalhaAoListar is null ? Dirs[path] : throw FalhaAoListar;

        public void WriteCanary(string fullPath, string content)
        {
            if (FalhaAoEscrever is not null) throw FalhaAoEscrever;
            Written[fullPath] = content;
            Dirs[Path.GetDirectoryName(fullPath)!].Add(Path.GetFileName(fullPath));
        }

        public void Delete(string fullPath)
        {
            Deleted.Add(fullPath);
            Dirs[Path.GetDirectoryName(fullPath)!].Remove(Path.GetFileName(fullPath));
        }
    }

    private const string Pasta = @"D:\Shares\Financeiro";

    [Fact]
    public void Planta_todos_os_canarios_previstos()
    {
        var fs = new FakeFs(Pasta);

        var r = new CanaryPlanter(fs).Plant(new[] { Pasta }).Single();

        Assert.True(r.Ok);
        Assert.Equal(CanaryPlan.NamesFor(Pasta).Count, r.Planted);
        Assert.Equal(0, r.AlreadyPresent);
    }

    /// <summary>
    /// O agente roda em ciclo. Um plantio que reescrevesse o arquivo a cada volta mudaria o
    /// timestamp sem parar e faria o backup incremental do cliente copiar isso para sempre.
    /// </summary>
    [Fact]
    public void Rodar_de_novo_nao_reescreve_nada()
    {
        var fs = new FakeFs(Pasta);
        var planter = new CanaryPlanter(fs);
        planter.Plant(new[] { Pasta });
        var escritasApos1 = fs.Written.Count;

        var r = planter.Plant(new[] { Pasta }).Single();

        Assert.Equal(0, r.Planted);
        Assert.Equal(CanaryPlan.NamesFor(Pasta).Count, r.AlreadyPresent);
        Assert.Equal(escritasApos1, fs.Written.Count);
    }

    [Fact]
    public void Canario_apagado_pelo_usuario_e_replantado()
    {
        var fs = new FakeFs(Pasta);
        var planter = new CanaryPlanter(fs);
        planter.Plant(new[] { Pasta });

        var umNome = CanaryPlan.NamesFor(Pasta)[0];
        fs.Dirs[Pasta].Remove(umNome);

        var r = planter.Plant(new[] { Pasta }).Single();

        Assert.Equal(1, r.Planted);
    }

    [Fact]
    public void Conteudo_e_inerte_e_explica_o_que_e()
    {
        var fs = new FakeFs(Pasta);
        new CanaryPlanter(fs).Plant(new[] { Pasta });

        var conteudo = fs.Written.Values.First();

        Assert.Contains("RansomGuard", conteudo);
        Assert.Contains("apagado sem risco", conteudo);
        // Nunca introduzir no cliente o tipo de arquivo do qual o produto o defende.
        Assert.DoesNotContain("<script", conteudo, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Sub Auto", conteudo, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("MZ", conteudo[..2]);
    }

    [Fact]
    public void Arquivos_do_cliente_na_pasta_nao_sao_tocados()
    {
        var fs = new FakeFs(Pasta);
        fs.Dirs[Pasta].Add("contrato.docx");

        new CanaryPlanter(fs).Plant(new[] { Pasta });

        Assert.DoesNotContain(fs.Written.Keys, k => k.EndsWith("contrato.docx"));
        Assert.Contains("contrato.docx", fs.Dirs[Pasta]);
    }

    // ── Isolamento de falha ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Pasta_inexistente_vira_erro_legivel_e_nao_excecao()
    {
        var r = new CanaryPlanter(new FakeFs()).Plant(new[] { Pasta }).Single();

        Assert.False(r.Ok);
        Assert.Contains("não encontrada", r.Error!, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Meia proteção é melhor que nenhuma — desde que o admin saiba qual metade.</summary>
    [Fact]
    public void Uma_pasta_problematica_nao_impede_as_outras()
    {
        const string boa = @"D:\Shares\Boa";
        var fs = new FakeFs(boa);

        var r = new CanaryPlanter(fs).Plant(new[] { @"D:\Shares\NaoExiste", boa });

        Assert.False(r[0].Ok);
        Assert.True(r[1].Ok);
        Assert.True(r[1].Planted > 0);
    }

    [Fact]
    public void Sem_permissao_para_escrever_vira_erro_da_pasta()
    {
        var fs = new FakeFs(Pasta) { FalhaAoEscrever = new UnauthorizedAccessException("acesso negado") };

        var r = new CanaryPlanter(fs).Plant(new[] { Pasta }).Single();

        Assert.False(r.Ok);
        Assert.Contains("acesso negado", r.Error!);
    }

    // ── Remoção ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Remove_apaga_os_canarios()
    {
        var fs = new FakeFs(Pasta);
        var planter = new CanaryPlanter(fs);
        planter.Plant(new[] { Pasta });

        var r = planter.Remove(new[] { Pasta }).Single();

        Assert.Equal(CanaryPlan.NamesFor(Pasta).Count, r.Planted);
        Assert.Empty(fs.Dirs[Pasta]);
    }

    /// <summary>
    /// A pasta é do cliente. Uma remoção que varresse o diretório seria destruição de dados — o
    /// pior desfecho possível para um produto que se vende como anti-ransomware.
    /// </summary>
    [Fact]
    public void Remove_nunca_apaga_arquivo_do_cliente()
    {
        var fs = new FakeFs(Pasta);
        new CanaryPlanter(fs).Plant(new[] { Pasta });
        fs.Dirs[Pasta].Add("contrato.docx");
        fs.Dirs[Pasta].Add("_aaa_algo_do_cliente.docx");   // parecido, mas sem a marca

        new CanaryPlanter(fs).Remove(new[] { Pasta });

        Assert.Contains("contrato.docx", fs.Dirs[Pasta]);
        Assert.Contains("_aaa_algo_do_cliente.docx", fs.Dirs[Pasta]);
        Assert.All(fs.Deleted, d => Assert.True(CanaryPlan.IsCanary(d)));
    }

    [Fact]
    public void Remover_de_pasta_sem_canario_nao_e_erro()
    {
        var fs = new FakeFs(Pasta);
        fs.Dirs[Pasta].Add("contrato.docx");

        var r = new CanaryPlanter(fs).Remove(new[] { Pasta }).Single();

        Assert.True(r.Ok);
        Assert.Equal(0, r.Planted);
        Assert.Empty(fs.Deleted);
    }

    [Fact]
    public void Contagem_ignora_pastas_que_falharam()
    {
        var fs = new FakeFs(@"D:\Boa");

        var r = new CanaryPlanter(fs).Plant(new[] { @"D:\NaoExiste", @"D:\Boa" });

        Assert.Equal(CanaryPlan.NamesFor(@"D:\Boa").Count, CanaryPlanter.CountPlanted(r));
    }
}

/// <summary>G1 — canários densos: subpastas até 2 níveis, com teto por raiz, e a âncora "!0_" primeiro na ordenação.</summary>
public class DenseCanaryTests
{
    private sealed class TreeFs : ICanaryFileSystem
    {
        public readonly Dictionary<string, List<string>> Subdirs = new(StringComparer.OrdinalIgnoreCase);
        public readonly List<string> Written = new();
        public bool DirectoryExists(string path) => Subdirs.ContainsKey(path);
        public IReadOnlyList<string> ListFiles(string path) => Array.Empty<string>();
        public IReadOnlyList<string> ListDirectories(string path) => Subdirs.TryGetValue(path, out var l) ? l : Array.Empty<string>();
        public void WriteCanary(string fullPath, string content) => Written.Add(fullPath);
        public void Delete(string fullPath) { }
        public void Add(string dir, params string[] subs) { Subdirs[dir] = subs.ToList(); foreach (var s in subs) Subdirs.TryAdd(s, new List<string>()); }
    }

    [Fact]
    public void Plants_in_root_and_two_levels_of_subdirectories_but_not_deeper()
    {
        var fs = new TreeFs();
        fs.Add(@"D:\Shares\Fin", @"D:\Shares\Fin\2024", @"D:\Shares\Fin\2025");
        fs.Add(@"D:\Shares\Fin\2024", @"D:\Shares\Fin\2024\Q1");
        fs.Add(@"D:\Shares\Fin\2024\Q1", @"D:\Shares\Fin\2024\Q1\jan");   // nível 3: fora

        var dirs = new CanaryPlanter(fs).ExpandWithSubdirectories(new[] { @"D:\Shares\Fin" });

        Assert.Equal(new[] { @"D:\Shares\Fin", @"D:\Shares\Fin\2024", @"D:\Shares\Fin\2025", @"D:\Shares\Fin\2024\Q1" }, dirs);
        var results = new CanaryPlanter(fs).Plant(new[] { @"D:\Shares\Fin" });
        Assert.Equal(4, results.Count);
        Assert.Equal(4 * RansomGuard.Core.Fsrm.CanaryPlan.NamesFor("x").Count, fs.Written.Count);
    }

    [Fact]
    public void Subdirectory_budget_is_capped_per_root()
    {
        var fs = new TreeFs();
        fs.Add(@"D:\Big", Enumerable.Range(0, 1000).Select(i => $@"D:\Big\d{i}").ToArray());
        var dirs = new CanaryPlanter(fs).ExpandWithSubdirectories(new[] { @"D:\Big" });
        Assert.Equal(1 + CanaryPlanter.MaxSubdirectoriesPerRoot, dirs.Count);
    }

    [Fact]
    public void Exclamation_anchor_sorts_before_digits_and_letters()
    {
        var names = RansomGuard.Core.Fsrm.CanaryPlan.NamesFor("x");
        var sample = new List<string> { "0relatorio.xlsx", "Aa.docx", "zebra.pdf", "_plano.docx" };
        sample.AddRange(names);
        var sorted = sample.OrderBy(n => n.ToUpperInvariant(), StringComparer.Ordinal).ToList();
        Assert.StartsWith("!0_", sorted[0]);
        Assert.StartsWith("~zz_", sorted[^1]);
    }
}
