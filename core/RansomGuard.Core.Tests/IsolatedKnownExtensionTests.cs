using RansomGuard.Core.Detection;
using RansomGuard.Core.Notifications;

namespace RansomGuard.Core.Tests;

/// <summary>
/// Um único arquivo com extensão do catálogo de ransomware já é fato digno de registro. Abaixo do limiar de Alta ele
/// não contém ninguém — mas também não pode passar em silêncio, como passava.
/// </summary>
public class IsolatedKnownExtensionTests
{
    private static readonly DateTime T0 = new(2026, 11, 16, 10, 0, 0, DateTimeKind.Utc);
    private static readonly IReadOnlySet<string> Catalog = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".lockbit" };

    private static DetectionEngine Engine() => new(new DetectionOptions { KnownExtensionsProvider = () => Catalog });

    private static FileEvent Write(int i, string path) =>
        new(T0.AddSeconds(i), @"CORP\ana", "10.0.9.66", @"\\FS01\Projetos", FileOp.Write, path, NewExtension: Path.GetExtension(path));

    [Fact]
    public void Um_arquivo_com_extensao_do_catalogo_vira_incidente_de_media_sem_ser_alta()
    {
        var detection = Assert.Single(Engine().Analyze(new[] { Write(0, "contrato.docx.lockbit") }));

        Assert.Contains(DetectionReason.KnownExtensionSeen, detection.Reasons);
        Assert.DoesNotContain(DetectionReason.KnownRansomExtension, detection.Reasons);
        Assert.Equal(Confidence.Medium, detection.Confidence);
    }

    [Fact]
    public void No_limiar_o_incidente_e_de_alta_e_a_razao_fraca_nao_aparece_junto()
    {
        var events = Enumerable.Range(0, new DetectionOptions().KnownExtensionThreshold).Select(i => Write(i, $"f{i}.xlsx.lockbit"));

        var detection = Assert.Single(Engine().Analyze(events));

        Assert.Contains(DetectionReason.KnownRansomExtension, detection.Reasons);
        Assert.DoesNotContain(DetectionReason.KnownExtensionSeen, detection.Reasons);
        Assert.Equal(Confidence.High, detection.Confidence);
    }

    [Fact]
    public void Extensao_fora_do_catalogo_em_um_arquivo_so_continua_sem_incidente()
        => Assert.Empty(Engine().Analyze(new[] { Write(0, "planta.dwg") }));

    [Fact]
    public void O_alerta_descreve_a_razao_em_linguagem_de_gente()
    {
        var detection = Assert.Single(Engine().Analyze(new[] { Write(0, "contrato.docx.lockbit") }));

        Assert.Contains("extensão de ransomware conhecida", AlertComposer.ForDetection(detection).ShortBody);
    }
}
