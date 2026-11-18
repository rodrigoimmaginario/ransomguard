using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;

namespace RansomGuard.Core.Tests;

/// <summary>
/// D6 — alarmes de Alta que a operação normal de um servidor de arquivos dispararia. Em Block, Alta contém alguém:
/// cada caso aqui é um administrador de backup ou um servidor de sincronização que seria bloqueado sem motivo.
/// O sinal continua existindo (Média: registrado, com snapshot); o que muda é exigir um segundo indício para conter.
/// </summary>
public class FalseAlarmTests
{
    private static readonly DateTime T0 = new(2026, 11, 16, 3, 0, 0, DateTimeKind.Utc);
    private const string Share = @"\\FS01\Projetos";

    private static FileEvent Ev(int second, string path, FileOp op = FileOp.Write, string user = @"CORP\ana", bool canary = false) =>
        new(T0.AddSeconds(second), user, "10.0.9.66", Share, op, path, NewExtension: Path.GetExtension(path), IsCanary: canary);

    private static HostSignal Signal(HostSignalKind kind, int second = 5) => new(T0.AddSeconds(second), kind, "FS01", "detalhe");

    private static Detection.Detection Only(IEnumerable<FileEvent> events, params HostSignal[] signals) =>
        Assert.Single(new DetectionEngine().Analyze(events, signals));

    // ── cópias de sombra ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void Reducao_parcial_de_copias_de_sombra_sozinha_e_media()
    {
        var d = Only(Array.Empty<FileEvent>(), Signal(HostSignalKind.VssReduced));

        Assert.Equal(Confidence.Medium, d.Confidence);
        Assert.Contains(DetectionReason.VssReduction, d.Reasons);
    }

    [Fact]
    public void Copias_de_sombra_zeradas_continuam_sendo_alta()
        => Assert.Equal(Confidence.High, Only(Array.Empty<FileEvent>(), Signal(HostSignalKind.VssDeleted)).Confidence);

    [Fact]
    public void Reducao_de_copias_junto_com_outro_indicio_vira_alta()
    {
        // Com gravação em massa do mesmo ator na mesma janela.
        var writes = Enumerable.Range(0, 60).Select(i => Ev(i % 50, $"f{i}.xlsx"));
        Assert.Equal(Confidence.High, Only(writes, Signal(HostSignalKind.VssReduced)).Confidence);

        // Com outro sinal de pré-cifra no servidor (serviço novo instalado).
        Assert.Equal(Confidence.High, Only(Array.Empty<FileEvent>(), Signal(HostSignalKind.VssReduced), Signal(HostSignalKind.ServiceInstalled, 8)).Confidence);
    }

    // ── nota de resgate ───────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("read_me.txt")] [InlineData("How-To.docx")] [InlineData("decrypt_notes.txt")] [InlineData("!!! leia.txt")]
    public void Nome_generico_repetido_em_tres_pastas_sozinho_e_media(string name)
    {
        var d = Only(new[] { "a", "b", "c" }.Select((dir, i) => Ev(i, $@"{dir}\{name}")));

        Assert.Equal(Confidence.Medium, d.Confidence);
        Assert.Contains(DetectionReason.NoteLikeFiles, d.Reasons);
        Assert.DoesNotContain(DetectionReason.RansomNote, d.Reasons);
    }

    [Theory]
    [InlineData("HOW_TO_RESTORE_FILES.txt")] [InlineData("README_RESTORE_FILES.txt")] [InlineData("How_To_Decrypt_Files.html")]
    [InlineData("YOUR_FILES_ARE_ENCRYPTED.txt")] [InlineData("RANSOM_NOTE.txt")]
    public void Nome_que_so_nota_de_resgate_tem_repetido_em_tres_pastas_continua_alta(string name)
    {
        var d = Only(new[] { "a", "b", "c" }.Select((dir, i) => Ev(i, $@"{dir}\{name}")));

        Assert.Equal(Confidence.High, d.Confidence);
        Assert.Contains(DetectionReason.RansomNote, d.Reasons);
    }

    [Fact]
    public void Nomes_diferentes_em_pastas_diferentes_nao_formam_uma_nota()
    {
        // Três documentos distintos que por acaso casam com padrões de nota não são "a mesma nota espalhada".
        var events = new[] { Ev(0, @"a\read_me.txt"), Ev(1, @"b\how-to instalar.docx"), Ev(2, @"c\decrypt manual.pdf") };

        Assert.Empty(new DetectionEngine().Analyze(events));
    }

    [Fact]
    public void Nome_generico_junto_com_gravacao_em_massa_vira_alta()
    {
        var events = new[] { "a", "b", "c" }.Select((dir, i) => Ev(i, $@"{dir}\read_me.txt"))
            .Concat(Enumerable.Range(0, 60).Select(i => Ev(i % 50, $@"a\f{i}.xlsx")));

        Assert.Equal(Confidence.High, Only(events).Confidence);
    }

    // ── canários apagados ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Quem_so_apaga_canarios_sem_apagar_mais_nada_e_media_e_nao_e_contido()
    {
        // O que um espelhamento com purga faz: apaga o que não existe na origem — os canários — e copia o resto.
        var events = new[] { Ev(0, "!Indice.xlsx", FileOp.Delete, canary: true), Ev(1, @"2024\!Indice.xlsx", FileOp.Delete, canary: true) }
            .Concat(Enumerable.Range(0, 20).Select(i => Ev(2 + i, $"copiado{i}.docx")));

        var d = Only(events);

        Assert.Equal(Confidence.Medium, d.Confidence);
        Assert.Contains(DetectionReason.CanaryRemoved, d.Reasons);
        Assert.DoesNotContain(DetectionReason.CanaryTouched, d.Reasons);
        var decision = new ResponseLadder().Decide(d, new ResponsePolicy { Mode = ResponseMode.Block });
        Assert.DoesNotContain(decision.Actions, a => a.Step is ResponseStep.BlockIp or ResponseStep.DenyUserOnShare or ResponseStep.KillSmbSession);
    }

    [Theory]
    [InlineData(FileOp.Write)] [InlineData(FileOp.Rename)]
    public void Gravar_ou_renomear_um_canario_continua_alta(FileOp op)
        => Assert.Equal(Confidence.High, Only(new[] { Ev(0, "!Indice.xlsx", op, canary: true) }).Confidence);

    [Fact]
    public void Apagar_canario_junto_com_arquivos_do_cliente_continua_alta()
    {
        var events = new[] { Ev(0, "!Indice.xlsx", FileOp.Delete, canary: true), Ev(1, "contrato.docx", FileOp.Delete) };

        var d = Only(events);

        Assert.Equal(Confidence.High, d.Confidence);
        Assert.Contains(DetectionReason.CanaryTouched, d.Reasons);
    }

    [Fact]
    public void Canario_replantado_sozinho_e_media_e_com_outro_indicio_e_alta()
    {
        Assert.Equal(Confidence.Medium, Only(Array.Empty<FileEvent>(), Signal(HostSignalKind.CanaryMissing)).Confidence);
        Assert.Equal(Confidence.High, Only(Array.Empty<FileEvent>(), Signal(HostSignalKind.CanaryMissing), Signal(HostSignalKind.VssReduced, 9)).Confidence);
    }

    // ── utilitário de snapshot ────────────────────────────────────────────────────────────────

    [Fact]
    public void Uso_de_utilitario_de_snapshot_sozinho_e_media_e_com_outro_indicio_e_alta()
    {
        Assert.Equal(Confidence.Medium, Only(Array.Empty<FileEvent>(), Signal(HostSignalKind.RecoveryToolUsed)).Confidence);
        Assert.Equal(Confidence.High, Only(Array.Empty<FileEvent>(), Signal(HostSignalKind.RecoveryToolUsed), Signal(HostSignalKind.VssReduced, 9)).Confidence);
        Assert.Equal(Confidence.High, Only(Array.Empty<FileEvent>(), Signal(HostSignalKind.RecoveryTampering)).Confidence);   // comando destrutivo: Alta sozinho
    }

    // ── teto de snapshots (D7) ────────────────────────────────────────────────────────────────

    [Fact]
    public void Snapshot_preventivo_tem_teto_diario_por_share_e_por_servidor()
    {
        var throttle = new SnapshotThrottle(TimeSpan.FromMinutes(10), maxPerShareDaily: 3, maxPerServerDaily: 5);
        var t = T0;

        Assert.True(throttle.ShouldSnapshot(@"\\FS01\A", t));
        Assert.False(throttle.ShouldSnapshot(@"\\FS01\A", t.AddMinutes(5)));                 // janela de 10 min
        Assert.True(throttle.ShouldSnapshot(@"\\FS01\A", t.AddMinutes(11)));
        Assert.True(throttle.ShouldSnapshot(@"\\FS01\A", t.AddMinutes(22)));
        Assert.False(throttle.ShouldSnapshot(@"\\FS01\A", t.AddMinutes(33)));                // 3 no dia para este share
        Assert.Contains("teto", throttle.LastRefusal);

        Assert.True(throttle.ShouldSnapshot(@"\\FS01\B", t.AddMinutes(34)));
        Assert.True(throttle.ShouldSnapshot(@"\\FS01\C", t.AddMinutes(35)));
        Assert.False(throttle.ShouldSnapshot(@"\\FS01\D", t.AddMinutes(36)));                // 5 no dia para o servidor

        Assert.True(throttle.ShouldSnapshot(@"\\FS01\A", t.AddHours(24).AddMinutes(1)));     // o dia passou
    }
}

/// <summary>D7 — o script do snapshot confere o espaço livre antes de criar a cópia.</summary>
public class SnapshotScriptTests
{
    [Fact]
    public void O_snapshot_preventivo_confere_o_espaco_livre_do_volume_antes_de_criar()
    {
        var script = ContainmentScripts.Execute(new ResponseAction(ResponseStep.PreemptiveSnapshot, "FS01", @"\\FS01\Financeiro", "teste"))!;

        Assert.Contains("Get-Volume", script);
        Assert.Contains("0.1", script);
        Assert.True(script.IndexOf("SizeRemaining", StringComparison.Ordinal) < script.IndexOf(".Create(", StringComparison.Ordinal));   // confere ANTES
        Assert.DoesNotContain('"', script);                    // o script viaja entre aspas duplas até o PowerShell
    }
}
