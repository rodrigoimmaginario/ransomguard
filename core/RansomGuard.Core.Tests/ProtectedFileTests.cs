using RansomGuard.Core.Security;

namespace RansomGuard.Core.Tests;

/// <summary>Arquivo de segredo protegido: o que está em disco não é legível, e cada uso só abre o que é seu.</summary>
public sealed class ProtectedFileTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rg-pf-" + Guid.NewGuid().ToString("N")[..10]);
    public ProtectedFileTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    [Fact]
    public void Conteudo_nao_fica_legivel_e_volta_igual_com_o_mesmo_proposito()
    {
        var path = Path.Combine(_dir, "segredo.json");

        ProtectedFile.Write(path, "valor-muito-reconhecivel", "teste.a");

        Assert.DoesNotContain("valor-muito-reconhecivel", File.ReadAllText(path));
        Assert.True(ProtectedFile.IsProtected(path));
        Assert.Equal("valor-muito-reconhecivel", ProtectedFile.Read(path, "teste.a"));
        Assert.Single(Directory.GetFiles(_dir));               // sem temporário para trás
    }

    [Fact]
    public void Arquivo_de_um_uso_nao_abre_como_se_fosse_de_outro()
    {
        var path = Path.Combine(_dir, "agente.json");
        ProtectedFile.Write(path, "chave do agente", "RansomGuard.Agent.Identity.v1");

        Assert.Throws<InvalidDataException>(() => ProtectedFile.Read(path, "RansomGuard.Panel.v1"));
        Assert.Equal("chave do agente", ProtectedFile.Read(path, "RansomGuard.Agent.Identity.v1"));
    }

    [Fact]
    public void Ausente_e_nulo_texto_antigo_e_lido_e_selado_e_adulterado_e_erro()
    {
        Assert.Null(ProtectedFile.Read(Path.Combine(_dir, "nao-existe"), "p"));

        var legacy = Path.Combine(_dir, "antigo.json");
        File.WriteAllText(legacy, "{\"x\":1}");
        Assert.Equal("{\"x\":1}", ProtectedFile.ReadAndSeal(legacy, "p"));
        Assert.True(ProtectedFile.IsProtected(legacy));
        Assert.Equal("{\"x\":1}", ProtectedFile.ReadAndSeal(legacy, "p"));

        File.WriteAllText(legacy, File.ReadAllText(legacy)[..^8] + "AAAAAAA=");
        Assert.Throws<InvalidDataException>(() => ProtectedFile.Read(legacy, "p"));
    }
}
