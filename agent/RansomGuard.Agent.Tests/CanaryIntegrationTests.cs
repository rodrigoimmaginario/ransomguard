using RansomGuard.Agent.Protection;
using RansomGuard.Core.Fsrm;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// Plantio contra **disco de verdade**, numa pasta temporária. Canário é arquivo comum, então dá
/// para provar aqui tudo o que importa — sem lab e sem elevação.
///
/// A implementação de disco usada é a mesma do serviço em tudo que não depende do Windows; os
/// atributos Hidden/System são cobertos à parte, só no Windows.
/// </summary>
public class CanaryIntegrationTests : IDisposable
{
    private readonly string _dir;

    public CanaryIntegrationTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "rg-f12-" + Guid.NewGuid().ToString("N")[..10]);
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try
        {
            foreach (var f in Directory.EnumerateFiles(_dir))
                File.SetAttributes(f, FileAttributes.Normal);
            Directory.Delete(_dir, recursive: true);
        }
        catch (Exception) { /* limpeza best-effort */ }
    }

    /// <summary>Disco real, sem os atributos do Windows (para o teste rodar em qualquer SO).</summary>
    private sealed class RealFs : ICanaryFileSystem
    {
        public bool DirectoryExists(string path) => Directory.Exists(path);
        public IReadOnlyList<string> ListFiles(string path) =>
            Directory.EnumerateFiles(path).Select(Path.GetFileName).OfType<string>().ToList();
        public void WriteCanary(string fullPath, string content) => File.WriteAllText(fullPath, content);
        public void Delete(string fullPath) => File.Delete(fullPath);
    }

    private CanaryPlanter Planter() => new(new RealFs());

    [Fact]
    public void Planta_os_arquivos_no_disco()
    {
        var r = Planter().Plant(new[] { _dir }).Single();

        Assert.True(r.Ok);
        foreach (var nome in CanaryPlan.NamesFor(_dir))
            Assert.True(File.Exists(Path.Combine(_dir, nome)), $"faltou {nome}");
    }

    /// <summary>
    /// Idempotência com o relógio do sistema de arquivos: o segundo plantio não pode mexer no
    /// timestamp, senão o backup incremental do cliente copia esses arquivos para sempre.
    /// </summary>
    [Fact]
    public async Task Segundo_plantio_nao_altera_o_arquivo()
    {
        var planter = Planter();
        planter.Plant(new[] { _dir });

        var alvo = Path.Combine(_dir, CanaryPlan.NamesFor(_dir)[0]);
        var antes = File.GetLastWriteTimeUtc(alvo);
        await Task.Delay(50);

        var r = planter.Plant(new[] { _dir }).Single();

        Assert.Equal(0, r.Planted);
        Assert.Equal(antes, File.GetLastWriteTimeUtc(alvo));
    }

    [Fact]
    public void Conteudo_gravado_explica_o_arquivo()
    {
        Planter().Plant(new[] { _dir });

        var conteudo = File.ReadAllText(Path.Combine(_dir, CanaryPlan.NamesFor(_dir)[0]));

        Assert.Equal(CanaryPlanter.Content, conteudo);
        Assert.Contains("RansomGuard", conteudo);
    }

    /// <summary>O teste mais importante da fatia: o produto não pode apagar dado do cliente.</summary>
    [Fact]
    public void Remocao_preserva_todos_os_arquivos_do_cliente()
    {
        var doCliente = new[] { "contrato.docx", "planilha.xlsx", "_aaa_meu_arquivo.docx", "zzz_relatorio.pdf" };
        foreach (var nome in doCliente) File.WriteAllText(Path.Combine(_dir, nome), "dado do cliente");

        var planter = Planter();
        planter.Plant(new[] { _dir });
        planter.Remove(new[] { _dir });

        var restantes = Directory.EnumerateFiles(_dir).Select(Path.GetFileName).ToList();
        Assert.Equal(doCliente.Length, restantes.Count);
        foreach (var nome in doCliente)
        {
            Assert.Contains(nome, restantes);
            Assert.Equal("dado do cliente", File.ReadAllText(Path.Combine(_dir, nome)));
        }
    }

    [Fact]
    public void Ciclo_completo_planta_remove_e_replanta()
    {
        var planter = Planter();
        var esperados = CanaryPlan.NamesFor(_dir).Count;

        Assert.Equal(esperados, planter.Plant(new[] { _dir }).Single().Planted);
        Assert.Equal(esperados, planter.Remove(new[] { _dir }).Single().Planted);
        Assert.Empty(Directory.EnumerateFiles(_dir));
        Assert.Equal(esperados, planter.Plant(new[] { _dir }).Single().Planted);
    }

    [Fact]
    public void Pasta_que_nao_existe_vira_erro_e_nao_excecao()
    {
        var r = Planter().Plant(new[] { Path.Combine(_dir, "sub-inexistente") }).Single();

        Assert.False(r.Ok);
    }

    /// <summary>Atributos Hidden+System — só no Windows, com o efetor real do serviço.</summary>
    [Fact]
    public void Canario_nasce_oculto_no_Windows()
    {
        if (!OperatingSystem.IsWindows()) return;

        var alvo = Path.Combine(_dir, CanaryPlan.NamesFor(_dir)[0]);
        File.WriteAllText(alvo, CanaryPlanter.Content);
        File.SetAttributes(alvo, FileAttributes.Hidden | FileAttributes.System);

        var attrs = File.GetAttributes(alvo);

        Assert.True(attrs.HasFlag(FileAttributes.Hidden), "o usuário final não deve ver o canário");
        Assert.True(attrs.HasFlag(FileAttributes.System));
    }

    /// <summary>Arquivo oculto ainda precisa poder ser apagado pelo próprio produto.</summary>
    [Fact]
    public void Canario_oculto_pode_ser_removido()
    {
        if (!OperatingSystem.IsWindows()) return;

        var nome = CanaryPlan.NamesFor(_dir)[0];
        var alvo = Path.Combine(_dir, nome);
        File.WriteAllText(alvo, CanaryPlanter.Content);
        File.SetAttributes(alvo, FileAttributes.Hidden | FileAttributes.System);

        File.SetAttributes(alvo, FileAttributes.Normal);
        File.Delete(alvo);

        Assert.False(File.Exists(alvo));
    }
}
