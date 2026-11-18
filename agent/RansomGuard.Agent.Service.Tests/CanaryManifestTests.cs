using System.Runtime.Versioning;
using Microsoft.Extensions.Logging.Abstractions;
using RansomGuard.Agent.Protection;
using RansomGuard.Agent.Service.Windows;
using RansomGuard.Core.Fsrm;

namespace RansomGuard.Agent.Service.Tests;

/// <summary>B4 — o manifesto local: nomes desta instalação, protegidos, e a memória do que precisa ser desfeito.</summary>
[SupportedOSPlatform("windows")]
public sealed class CanaryManifestTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rg-canary-" + Guid.NewGuid().ToString("N")[..10]);
    public CanaryManifestTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    private CanaryManifest Load(string? configured = null, string? dir = null) => CanaryManifest.Load(dir ?? _dir, configured, NullLogger.Instance);

    [Fact]
    public void Os_nomes_sao_gerados_uma_vez_ficam_protegidos_e_sao_os_mesmos_ao_reabrir()
    {
        var first = Load();
        var second = Load();

        Assert.Equal(9, first.Names.Count);
        Assert.Equal(first.Names, second.Names);
        Assert.All(first.Names, n => Assert.True(CanaryPlan.IsCanary(n)));
        var raw = File.ReadAllText(Path.Combine(_dir, CanaryManifest.FileName));
        Assert.StartsWith("RGP1:", raw);
        Assert.All(first.Names, n => Assert.DoesNotContain(n, raw));
    }

    [Fact]
    public void Duas_instalacoes_nao_compartilham_nomes()
    {
        var other = Path.Combine(_dir, "outra");
        Directory.CreateDirectory(other);

        Assert.Empty(Load().Names.Intersect(Load(dir: other).Names, StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public void Nomes_do_administrador_valem_e_os_anteriores_continuam_reconhecidos_para_serem_retirados()
    {
        var generated = Load().Names;
        var custom = $"!Indice {Guid.NewGuid():N}.xlsx;Arquivo morto {Guid.NewGuid():N}.pdf;~Fecho {Guid.NewGuid():N}.docx";

        var manifest = Load(custom);

        Assert.Equal(3, manifest.Names.Count);
        Assert.StartsWith("!Indice ", manifest.Names[0]);
        Assert.All(generated, n => Assert.True(CanaryPlan.IsCanary(n)));          // aposentados: reconhecidos
        Assert.Equal(manifest.Names, Load(custom).Names);

        // Menos de três nomes válidos não substituem nada.
        Assert.Equal(manifest.Names.Count, Load(custom).Names.Count);
        Assert.Equal(9, Load("um.docx;sub\\dois.docx", Path.Combine(_dir, "x")).Names.Count);
    }

    [Fact]
    public void As_pastas_plantadas_ficam_registradas_mesmo_depois_de_sairem_da_configuracao()
    {
        var manifest = Load();
        manifest.RememberRoots(new[] { @"D:\Financeiro", @"E:\Projetos" });
        manifest.RememberRoots(new[] { @"d:\financeiro" });                      // repetida: não duplica

        Assert.Equal(new[] { @"D:\Financeiro", @"E:\Projetos" }, Load().Roots.OrderBy(r => r));
    }

    [Fact]
    public void Linha_de_comando_reconhece_os_nomes_sem_criar_manifesto()
    {
        Assert.Empty(CanaryManifest.RecognizeExisting(_dir));
        Assert.False(File.Exists(Path.Combine(_dir, CanaryManifest.FileName)));

        var names = Load().Names;

        Assert.Equal(names, CanaryManifest.RecognizeExisting(_dir));
    }

    [Fact]
    public void Manifesto_ilegivel_e_guardado_e_substituido_sem_derrubar_o_agente()
    {
        var before = Load().Names;
        File.WriteAllText(Path.Combine(_dir, CanaryManifest.FileName), "RGP1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        var after = Load().Names;

        Assert.Equal(9, after.Count);
        Assert.Empty(before.Intersect(after, StringComparer.OrdinalIgnoreCase));
        Assert.Contains(Directory.GetFiles(_dir), f => Path.GetFileName(f).StartsWith(CanaryManifest.FileName + ".ilegivel-"));
    }

    /// <summary>Em disco de verdade: planta com os nomes da instalação, e desfazer leva só o que é do produto.</summary>
    [Fact]
    public void Em_pasta_real_planta_os_nomes_da_instalacao_e_desfaz_so_o_que_e_do_produto()
    {
        var share = Path.Combine(_dir, "share");
        Directory.CreateDirectory(Path.Combine(share, "2024"));
        File.WriteAllText(Path.Combine(share, "contrato do cliente.docx"), "x");
        File.WriteAllText(Path.Combine(share, "!0__ransomguard_canary.docx"), "canário de versão anterior");
        var manifest = Load();
        File.WriteAllText(Path.Combine(share, "2024", manifest.Names[4]), "arquivo do cliente que, por acaso, tem nome de canário");
        var planter = new CanaryPlanter(new WindowsCanaryFileSystem(), manifest.Set);

        var planted = planter.Plant(new[] { share });

        Assert.All(planted, r => Assert.True(r.Ok, r.Error));
        var files = Directory.GetFiles(share, "*", SearchOption.AllDirectories).Select(Path.GetFileName).ToList();
        Assert.Equal(18, files.Count(f => manifest.Names.Contains(f!)));
        Assert.DoesNotContain(files, f => f!.Contains("ransomguard", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(1, planted.Sum(r => r.Collisions));                         // o arquivo do cliente não virou canário
        Assert.Equal(17, CanaryPlanter.CountPlanted(planted));
        foreach (var canary in Directory.GetFiles(share).Where(f => manifest.Names.Contains(Path.GetFileName(f))))
            Assert.DoesNotContain("RansomGuard", File.ReadAllText(canary), StringComparison.OrdinalIgnoreCase);   // nem o conteúdo denuncia

        Assert.Equal(17, planter.Plant(new[] { share }).Sum(r => r.AlreadyPresent));   // idempotente: confere pelo conteúdo

        planter.Remove(new[] { share });

        var left = Directory.GetFiles(share, "*", SearchOption.AllDirectories).Select(Path.GetFileName).OrderBy(n => n).ToList();
        Assert.Equal(new[] { "contrato do cliente.docx", manifest.Names[4] }.OrderBy(n => n), left);   // o do cliente fica, mesmo com nome de canário
        Assert.Equal("arquivo do cliente que, por acaso, tem nome de canário", File.ReadAllText(Path.Combine(share, "2024", manifest.Names[4])));
    }
}
