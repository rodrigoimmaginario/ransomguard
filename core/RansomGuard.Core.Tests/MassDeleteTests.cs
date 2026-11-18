using RansomGuard.Core.Detection;

namespace RansomGuard.Core.Tests;

/// <summary>
/// Exclusão em massa. No Windows real (CI, 2026-11-16) apagar e RENOMEAR um arquivo pela rede geram o mesmo
/// registro: acesso de exclusão no nome antigo. Sem um limiar para isso, um apagador não era visto, e o
/// ransomware que cifra no lugar e renomeia só aparecia pela metade.
/// </summary>
public class MassDeleteTests
{
    private static readonly DateTime T0 = new(2026, 11, 16, 9, 0, 0, DateTimeKind.Utc);

    private static List<FileEvent> Deletes(int count, string user = @"CORP\joao", int from = 0, DateTime? at = null) =>
        Enumerable.Range(from, count).Select(i =>
            new FileEvent((at ?? T0).AddMilliseconds(i), user, "10.0.4.20", @"\\FS01\Projetos", FileOp.Delete, $@"obra\planta{i}.dwg", ".dwg")).ToList();

    [Fact]
    public void Exclusao_em_massa_e_incidente_de_media_confianca()
    {
        var d = Assert.Single(new DetectionEngine().Analyze(Deletes(150)));

        Assert.Contains(DetectionReason.MassDelete, d.Reasons);
        Assert.Equal(Confidence.Medium, d.Confidence);
        Assert.Equal(150, d.AffectedFiles);
        Assert.Equal(@"CORP\joao", d.User);
    }

    [Fact]
    public void Poucas_exclusoes_nao_sao_incidente()
        => Assert.Empty(new DetectionEngine().Analyze(Deletes(30)));

    [Fact]
    public void O_mesmo_arquivo_apagado_em_varios_registros_conta_uma_vez()
    {
        var repetidos = Enumerable.Range(0, 400).Select(_ =>
            new FileEvent(T0, @"CORP\joao", "10.0.4.20", @"\\FS01\Projetos", FileOp.Delete, "unico.dwg", ".dwg")).ToList();

        Assert.Empty(new DetectionEngine().Analyze(repetidos));
    }

    [Fact]
    public void Conta_na_allowlist_pode_apagar_em_massa()
    {
        var engine = new DetectionEngine(new DetectionOptions
        {
            AllowlistedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"CORP\svc-limpeza" }
        });

        Assert.Empty(engine.Analyze(Deletes(500, user: @"CORP\svc-limpeza")));
    }

    /// <summary>Apagar devagar o bastante para não estourar um lote ainda soma na janela de 60 s.</summary>
    [Fact]
    public void Exclusao_espalhada_por_varios_lotes_soma_na_janela_de_um_minuto()
    {
        var engine = new DetectionEngine(tracker: new ActorActivityTracker());
        var detectados = new List<Detection.Detection>();

        for (var lote = 0; lote < 5; lote++)      // 5 lotes de 80 em 20 s: nenhum lote passa de 100, a soma passa de 300
            detectados.AddRange(engine.Analyze(Deletes(80, from: lote * 80, at: T0.AddSeconds(lote * 5))));

        Assert.Contains(detectados, d => d.Reasons.Contains(DetectionReason.MassDelete));
    }

    [Fact]
    public void Limiares_de_exclusao_sao_configuraveis()
    {
        var engine = new DetectionEngine(new DetectionOptions { MassDeleteThreshold = 20 });

        Assert.Contains(DetectionReason.MassDelete, Assert.Single(engine.Analyze(Deletes(25))).Reasons);
    }

    /// <summary>O padrão "cifra no lugar e renomeia": gravação e exclusão do mesmo conjunto de arquivos.</summary>
    [Fact]
    public void Gravar_e_depois_renomear_em_massa_reune_as_duas_razoes()
    {
        var eventos = new List<FileEvent>();
        for (var i = 0; i < 150; i++)
        {
            eventos.Add(new FileEvent(T0.AddMilliseconds(i), @"CORP\joao", "10.0.4.20", @"\\FS01\Projetos", FileOp.Write, $"doc{i}.xlsx", ".xlsx"));
            eventos.Add(new FileEvent(T0.AddMilliseconds(i), @"CORP\joao", "10.0.4.20", @"\\FS01\Projetos", FileOp.Delete, $"doc{i}.xlsx", ".xlsx"));
        }

        var d = Assert.Single(new DetectionEngine().Analyze(eventos));

        Assert.Contains(DetectionReason.MassRewrite, d.Reasons);
        Assert.Contains(DetectionReason.MassDelete, d.Reasons);
        Assert.Equal(150, d.AffectedFiles);
    }
}
