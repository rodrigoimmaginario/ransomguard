using RansomGuard.Core.Catalog;
using RansomGuard.Core.Fsrm;
using RansomGuard.Core.Signing;

namespace RansomGuard.Core.Tests;

/// <summary>
/// A semente é o que o agente usa enquanto o elo de distribuição do catálogo assinado não existe
/// (AUD-1). Ela precisa ser útil sem ser perigosa — e, principalmente, precisa **sair de cena**
/// assim que um catálogo assinado de verdade chegar.
/// </summary>
public class SeedCatalogTests
{
    [Fact]
    public void Semente_e_um_catalogo_valido()
    {
        var c = RansomwareCatalog.FromJson(SeedCatalog.Json);

        Assert.Equal(SeedCatalog.Version, c.Version);
        Assert.Equal(SeedCatalog.Patterns.Count, c.Patterns.Count);
    }

    /// <summary>
    /// Versão 0 garante que **qualquer** catálogo assinado real (versão ≥ 1) passa pelo
    /// anti-rollback e substitui a semente. Se a semente nascesse com versão alta, ela bloquearia a
    /// própria atualização — o produto ficaria preso na lista compilada para sempre.
    /// </summary>
    [Fact]
    public void Semente_nao_bloqueia_a_chegada_do_catalogo_assinado()
    {
        var seed = Enumerable.Range(30, 32).Select(i => (byte)i).ToArray();
        var keyId = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var pub = MinisignPublicKey.FromRaw(keyId, Minisign.PublicKeyFromSeed(seed));

        // O agente começa com a semente aceita.
        var verifier = new CatalogVerifier(pub, lastAcceptedVersion: SeedCatalog.Version);

        var real = "{\"version\":1,\"patterns\":[\"*.locked\"]}";
        var sig = Minisign.Sign(System.Text.Encoding.UTF8.GetBytes(real), seed, keyId, "catalog v1");

        Assert.True(verifier.TryLoad(real, sig).Accepted);
    }

    [Fact]
    public void Semente_cobre_as_familias_mais_conhecidas()
    {
        foreach (var esperado in new[] { "*.locked", "*.lockbit", "*.conti", "*.akira", "*.wncry" })
            Assert.Contains(esperado, SeedCatalog.Patterns);
    }

    [Fact]
    public void Semente_inclui_bilhetes_de_resgate()
        => Assert.Contains(SeedCatalog.Patterns, p => p.Contains("DECRYPT", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Curinga largo demais viraria bloqueio de arquivo legítimo — o falso positivo mais caro que
    /// existe, porque acontece em share de produção e o admin culpa o produto na hora.
    /// </summary>
    [Theory]
    [InlineData("*")]
    [InlineData("*.*")]
    [InlineData("*.doc")]
    [InlineData("*.docx")]
    [InlineData("*.xlsx")]
    [InlineData("*.pdf")]
    [InlineData("*.txt")]
    public void Semente_nao_contem_padrao_perigoso(string perigoso)
        => Assert.DoesNotContain(perigoso, SeedCatalog.Patterns);

    /// <summary>A semente gera um plano de FSRM aplicável — senão ela não serve para nada.</summary>
    [Fact]
    public void Semente_gera_script_de_FSRM()
    {
        var script = FsrmPlan.BuildPowerShell(
            RansomwareCatalog.FromJson(SeedCatalog.Json), new[] { @"D:\Shares\Financeiro" }, active: false);

        Assert.Contains("*.locked", script);
        Assert.Contains("PASSIVO", script);   // o padrão é auditar, não bloquear
    }

    [Fact]
    public void Modo_ativo_gera_script_de_bloqueio()
    {
        var script = FsrmPlan.BuildPowerShell(
            RansomwareCatalog.FromJson(SeedCatalog.Json), new[] { @"D:\Shares\Financeiro" }, active: true);

        Assert.Contains("ATIVO", script);
    }
}
