using RansomGuard.Core.Detection;

namespace RansomGuard.Core.Tests;

public class DetectionEngineTests
{
    private static readonly DateTime T0 = new(2026, 7, 23, 2, 0, 0, DateTimeKind.Utc);

    private static IEnumerable<FileEvent> MassWrite(
        string user, string ip, string share, int count, bool flipExtension = false)
    {
        for (var i = 0; i < count; i++)
            yield return new FileEvent(
                At: T0.AddSeconds(i),
                User: user, SourceIp: ip, Share: share,
                Op: FileOp.Write, Path: $"doc{i}.xlsx",
                NewExtension: flipExtension ? ".locked" : null);
    }

    /// <summary>
    /// Windows real (CI, 2026-11-16): gravar UM arquivo pela rede registra duas checagens de gravação (abrir para escrita
    /// e gravar) mais leituras da pasta. O volume é medido em arquivos, não em eventos: 30 arquivos são 30, não 60.
    /// </summary>
    [Fact]
    public void Volume_e_contado_em_arquivos_e_nao_em_checagens_de_acesso()
    {
        var engine = new DetectionEngine(new DetectionOptions { MassThreshold = 40 });
        var events = new List<FileEvent>();
        for (var i = 0; i < 30; i++)
        {
            events.Add(new FileEvent(T0.AddSeconds(i), @"CORP\joao", "10.0.4.20", @"\\FS01\Projetos", FileOp.Read, "pasta"));
            events.Add(new FileEvent(T0.AddSeconds(i), @"CORP\joao", "10.0.4.20", @"\\FS01\Projetos", FileOp.Write, $"doc{i}.xlsx", ".xlsx"));
            events.Add(new FileEvent(T0.AddSeconds(i), @"CORP\joao", "10.0.4.20", @"\\FS01\Projetos", FileOp.Write, $"DOC{i}.XLSX", ".xlsx"));
        }

        Assert.Empty(engine.Analyze(events));        // 60 checagens de gravação, 30 arquivos: abaixo do limiar de 40
    }

    [Fact]
    public void Arquivos_afetados_sao_os_caminhos_alterados_e_nao_o_total_de_eventos()
    {
        var engine = new DetectionEngine(new DetectionOptions { MassThreshold = 40 });
        var events = new List<FileEvent>();
        for (var i = 0; i < 50; i++)
        {
            events.Add(new FileEvent(T0.AddSeconds(i), @"CORP\joao", "10.0.4.20", @"\\FS01\Projetos", FileOp.Read, "pasta"));
            events.Add(new FileEvent(T0.AddSeconds(i), @"CORP\joao", "10.0.4.20", @"\\FS01\Projetos", FileOp.Write, $"doc{i}.xlsx", ".xlsx"));
            events.Add(new FileEvent(T0.AddSeconds(i), @"CORP\joao", "10.0.4.20", @"\\FS01\Projetos", FileOp.Write, $"doc{i}.xlsx", ".xlsx"));
        }

        var d = Assert.Single(engine.Analyze(events));

        Assert.Contains(DetectionReason.MassRewrite, d.Reasons);
        Assert.Equal(50, d.AffectedFiles);
    }

    [Fact]
    public void Canary_touched_is_high_confidence_and_attributed()
    {
        var engine = new DetectionEngine();
        var events = new[]
        {
            new FileEvent(T0, @"CORP\maria", "10.0.4.77", @"\\FS01\Financeiro",
                FileOp.Rename, "_canary_000.docx", ".locked", IsCanary: true)
        };

        var d = Assert.Single(engine.Analyze(events));

        Assert.Equal(Confidence.High, d.Confidence);
        Assert.Contains(DetectionReason.CanaryTouched, d.Reasons);
        Assert.Equal("FS01", d.Server);
        Assert.Equal(@"CORP\maria", d.User);
        Assert.Equal("10.0.4.77", d.SourceIp);
    }

    [Fact]
    public void Mass_rewrite_over_threshold_is_medium_confidence()
    {
        var engine = new DetectionEngine(new DetectionOptions { MassThreshold = 40 });
        var events = MassWrite(@"CORP\bob", "10.0.5.20", @"\\FS02\Projetos", 60);

        var d = Assert.Single(engine.Analyze(events));

        Assert.Equal(Confidence.Medium, d.Confidence);
        Assert.Contains(DetectionReason.MassRewrite, d.Reasons);
        Assert.Equal(60, d.AffectedFiles);
    }

    [Fact]
    public void Below_threshold_does_not_detect()
    {
        var engine = new DetectionEngine(new DetectionOptions { MassThreshold = 40 });
        var events = MassWrite(@"CORP\bob", "10.0.5.20", @"\\FS02\Projetos", 10);

        Assert.Empty(engine.Analyze(events));
    }

    [Fact]
    public void Remote_encryption_over_smb_is_attributed_to_source_ip()
    {
        // Máquina comprometida (IP remoto) criptografa o share do servidor via SMB:
        // o processo malicioso nunca roda no servidor — a atribuição vem do IP de origem.
        var engine = new DetectionEngine();
        var events = MassWrite(@"CORP\svc-app", "10.0.9.66", @"\\FS01\Financeiro", 80, flipExtension: true);

        var d = Assert.Single(engine.Analyze(events));

        Assert.Equal("10.0.9.66", d.SourceIp);
        Assert.Contains(DetectionReason.ExtensionFlip, d.Reasons);
    }

    [Fact]
    public void Allowlisted_backup_account_does_not_trigger_on_volume()
    {
        // Guard-rail de falso positivo: backup noturno faz I/O em massa legítimo.
        var engine = new DetectionEngine(new DetectionOptions
        {
            MassThreshold = 40,
            AllowlistedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"CORP\svc-backup" }
        });
        var events = MassWrite(@"CORP\svc-backup", "10.0.1.9", @"\\FS01\Financeiro", 5000);

        Assert.Empty(engine.Analyze(events));
    }

    [Fact]
    public void Allowlisted_account_still_triggers_if_it_touches_a_canary()
    {
        // Nem a allowlist salva de um canário: nenhum processo legítimo mexe num canário.
        var engine = new DetectionEngine(new DetectionOptions
        {
            AllowlistedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"CORP\svc-backup" }
        });
        var events = new[]
        {
            new FileEvent(T0, @"CORP\svc-backup", "10.0.1.9", @"\\FS01\Financeiro",
                FileOp.Write, "_canary_000.docx", ".locked", IsCanary: true)
        };

        var d = Assert.Single(engine.Analyze(events));
        Assert.Equal(Confidence.High, d.Confidence);
    }

    [Fact]
    public void Vss_deletion_in_window_raises_confidence_to_high()
    {
        var engine = new DetectionEngine(new DetectionOptions { MassThreshold = 40 });
        var events = MassWrite(@"CORP\bob", "10.0.5.20", @"\\FS02\Projetos", 50).ToList();
        var signals = new[]
        {
            new HostSignal(T0.AddSeconds(30), HostSignalKind.VssDeleted, "FS02", "cópias de sombra removidas")
        };

        var d = Assert.Single(engine.Analyze(events, signals));

        Assert.Equal(Confidence.High, d.Confidence);
        Assert.Contains(DetectionReason.VssDeletion, d.Reasons);
    }

    [Fact]
    public void Two_distinct_actors_produce_two_detections()
    {
        var engine = new DetectionEngine();
        var events = MassWrite(@"CORP\a", "10.0.0.1", @"\\FS01\Sh", 60)
            .Concat(MassWrite(@"CORP\b", "10.0.0.2", @"\\FS01\Sh", 60));

        Assert.Equal(2, engine.Analyze(events).Count);
    }

    // R6 — sinal de host isolado (sem evento de arquivo no ciclo) precisa virar incidente. É o
    // cenário EDR killer / apagar shadow copies ANTES de cifrar: se o produto só olhasse eventos,
    // ficaria cego justamente no primeiro passo do playbook.
    [Fact]
    public void Isolated_vss_deletion_without_events_still_detects()
    {
        var engine = new DetectionEngine();
        var signals = new[]
        {
            new HostSignal(T0, HostSignalKind.VssDeleted, "FS01", "cópias de sombra removidas")
        };

        var d = Assert.Single(engine.Analyze(Array.Empty<FileEvent>(), signals));

        Assert.Equal("FS01", d.Server);
        Assert.Equal(Confidence.High, d.Confidence);
        Assert.Contains(DetectionReason.VssDeletion, d.Reasons);
    }

    [Fact]
    public void Isolated_agent_tamper_without_events_still_detects()
    {
        var engine = new DetectionEngine();
        var signals = new[]
        {
            new HostSignal(T0, HostSignalKind.AgentTamper, "FS03", "coletor cego")
        };

        var d = Assert.Single(engine.Analyze(Array.Empty<FileEvent>(), signals));

        Assert.Equal("FS03", d.Server);
        Assert.Equal(Confidence.High, d.Confidence);
        Assert.Contains(DetectionReason.AgentTamper, d.Reasons);
    }

    [Fact]
    public void Correlated_signal_does_not_also_produce_a_server_level_detection()
    {
        // Um sinal que casa com um grupo de evento enriquece esse grupo e NÃO gera uma segunda
        // detecção de servidor — senão o mesmo incidente apareceria duplicado.
        var engine = new DetectionEngine(new DetectionOptions { MassThreshold = 40 });
        var events = MassWrite(@"CORP\bob", "10.0.5.20", @"\\FS02\Projetos", 50).ToList();
        var signals = new[] { new HostSignal(T0.AddSeconds(30), HostSignalKind.VssDeleted, "FS02") };

        var d = Assert.Single(engine.Analyze(events, signals));
        Assert.Equal(@"CORP\bob", d.User);   // atribuído ao ator, não duplicado como servidor
    }

    [Fact]
    public void Multiple_isolated_signals_on_same_server_collapse_to_one_detection()
    {
        var engine = new DetectionEngine();
        var signals = new[]
        {
            new HostSignal(T0, HostSignalKind.VssDeleted, "FS01"),
            new HostSignal(T0.AddSeconds(5), HostSignalKind.AgentTamper, "FS01")
        };

        var d = Assert.Single(engine.Analyze(Array.Empty<FileEvent>(), signals));
        Assert.Contains(DetectionReason.VssDeletion, d.Reasons);
        Assert.Contains(DetectionReason.AgentTamper, d.Reasons);
    }
}
