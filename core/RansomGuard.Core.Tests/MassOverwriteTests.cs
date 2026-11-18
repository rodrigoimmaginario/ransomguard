using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;

namespace RansomGuard.Core.Tests;

/// <summary>
/// Laboratório, sessão 3 — o ataque que pula os arquivos ocultos (e por isso nunca toca um canário) regravou 300
/// arquivos em 2 s e ficou em Média: não foi contido. A cópia legítima de 2000 arquivos teve o mesmo nível. O que separa
/// os dois não é o volume: o ataque REGRAVA arquivos que já existiam; a cópia CRIA arquivos novos.
/// </summary>
public class MassOverwriteTests
{
    private static readonly DateTime T0 = new(2026, 11, 17, 11, 0, 5, DateTimeKind.Utc);
    private const string Share = @"\\rg-fs1\Dados";

    private static FileEvent Write(int i, string user = @"RGLAB\atk09", bool overwrite = true, double second = 0) =>
        new(T0.AddSeconds(second), user, "10.88.1.40", Share, FileOp.Write, $@"a9\documento_{i:D4}.docx", ".docx", Overwrite: overwrite);

    [Fact]
    public void Regravar_em_massa_arquivos_que_ja_existiam_e_alta_e_e_contido()
    {
        var events = Enumerable.Range(0, 60).Select(i => Write(i, second: i * 0.03));

        var detection = Assert.Single(new DetectionEngine().Analyze(events));

        Assert.Contains(DetectionReason.MassOverwrite, detection.Reasons);
        Assert.Equal(Confidence.High, detection.Confidence);
        Assert.True(new ResponseLadder().Decide(detection, new ResponsePolicy { Mode = ResponseMode.Block }).Contains);
    }

    [Fact]
    public void Criar_milhares_de_arquivos_novos_continua_media()
    {
        var events = Enumerable.Range(0, 2000).Select(i => Write(i, user: @"RGLAB\ana", overwrite: false, second: i * 0.01));

        var detection = Assert.Single(new DetectionEngine().Analyze(events));

        Assert.DoesNotContain(DetectionReason.MassOverwrite, detection.Reasons);
        Assert.Equal(Confidence.Medium, detection.Confidence);
    }

    [Fact]
    public void Poucos_arquivos_regravados_nao_bastam()
    {
        var events = Enumerable.Range(0, 39).Select(i => Write(i));

        Assert.All(new DetectionEngine().Analyze(events), d => Assert.DoesNotContain(DetectionReason.MassOverwrite, d.Reasons));
    }

    [Fact]
    public void Ator_na_allowlist_regravando_em_massa_nao_vira_alta()
    {
        var engine = new DetectionEngine(new DetectionOptions { AllowlistedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"RGLAB\svc-backup" } });
        var events = Enumerable.Range(0, 200).Select(i => Write(i, user: @"RGLAB\svc-backup"));

        Assert.All(engine.Analyze(events), d => Assert.NotEqual(Confidence.High, d.Confidence));
    }

    /// <summary>Rajadas de 30 a cada 20 s (caso A6): cada lote fica abaixo do limiar; a janela de 60 s, não.</summary>
    [Fact]
    public void Regravacoes_em_rajadas_somam_na_janela_de_um_minuto()
    {
        var engine = new DetectionEngine(tracker: new ActorActivityTracker());
        Detection.Detection? last = null;

        for (var burst = 0; burst < 3; burst++)
        {
            var events = Enumerable.Range(burst * 30, 30).Select(i => Write(i, second: burst * 20 + (i % 30) * 0.05)).ToList();
            last = engine.Analyze(events).SingleOrDefault();
        }

        Assert.NotNull(last);
        Assert.Contains(DetectionReason.MassOverwrite, last!.Reasons);
        Assert.Equal(Confidence.High, last.Confidence);
    }

    [Fact]
    public void O_alerta_diz_o_que_aconteceu()
        => Assert.Contains("arquivos existentes regravados",
            Notifications.AlertComposer.ForDetection(new DetectionEngine().Analyze(Enumerable.Range(0, 60).Select(i => Write(i))).Single()).ShortBody);
}

/// <summary>
/// Laboratório, sessão 4 — 2600 arquivos lidos por sessão remota em 28 s não viraram incidente: o limiar de leitura
/// (2000) era contado só dentro de um ciclo do agente (poucos segundos), sem a janela de um minuto.
/// </summary>
public class MassReadWindowTests
{
    private static readonly DateTime T0 = new(2026, 11, 17, 12, 48, 8, DateTimeKind.Utc);

    private static List<FileEvent> Reads(int from, int count, double second) =>
        Enumerable.Range(from, count).Select(i => new FileEvent(T0.AddSeconds(second), @"RGLAB\atk16", "10.88.1.40", @"\\rg-fs1\Dados", FileOp.Read, $@"a14b\documento_{i:D4}.docx")).ToList();

    [Fact]
    public void Leituras_espalhadas_em_varios_ciclos_somam_na_janela_de_um_minuto()
    {
        var engine = new DetectionEngine(tracker: new ActorActivityTracker());
        Detection.Detection? last = null;

        for (var cycle = 0; cycle < 6; cycle++)
            last = engine.Analyze(Reads(cycle * 450, 450, cycle * 4.5)).SingleOrDefault() ?? last;

        Assert.NotNull(last);
        Assert.Contains(DetectionReason.MassRead, last!.Reasons);
    }

    [Fact]
    public void Leitura_espalhada_abaixo_do_limiar_na_janela_nao_e_incidente()
    {
        var engine = new DetectionEngine(tracker: new ActorActivityTracker());

        for (var cycle = 0; cycle < 4; cycle++)
            Assert.Empty(engine.Analyze(Reads(cycle * 300, 300, cycle * 4.5)));
    }
}
