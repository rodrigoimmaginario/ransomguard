using RansomGuard.Core.Detection;

namespace RansomGuard.Core.Tests;

/// <summary>
/// G1 — detecção em profundidade: contém SEM depender de um canário sortudo. Nota de resgate, extensão
/// conhecida do catálogo, share-isca (Alta); low-and-slow e anomalia de ritmo (Média); janela de 60 s
/// que atravessa ciclos de 5 s.
/// </summary>
public class DetectionDepthTests
{
    private static readonly DateTime T0 = new(2026, 10, 4, 10, 0, 0, DateTimeKind.Utc);
    private const string User = @"CORP\ana", Ip = "10.0.9.66", Share = @"\\FS01\Fin";

    private static FileEvent Ev(DateTime at, string path, FileOp op = FileOp.Write, string? newExt = null, string share = Share) =>
        new(at, User, Ip, share, op, path, newExt);

    private static Detection.Detection? Single(DetectionEngine e, IEnumerable<FileEvent> events) => e.Analyze(events).SingleOrDefault();

    // ── nota de resgate ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void Ransom_note_written_in_several_directories_is_high_confidence()
    {
        var events = new[] { "Fin\\2024", "Fin\\2025", "RH\\folha" }
            .Select((dir, i) => Ev(T0.AddSeconds(i), $"{dir}\\README_RESTORE_FILES.txt")).ToList();
        var d = Single(new DetectionEngine(), events)!;
        Assert.Contains(DetectionReason.RansomNote, d.Reasons);
        Assert.Equal(Confidence.High, d.Confidence);
    }

    [Fact]
    public void Ransom_note_in_fewer_directories_than_threshold_is_not_enough_alone()
    {
        var events = new[] { Ev(T0, "Fin\\HOW_TO_DECRYPT.txt"), Ev(T0.AddSeconds(1), "Fin\\HOW_TO_DECRYPT.txt") };
        Assert.Null(Single(new DetectionEngine(), events));
    }

    [Theory]
    [InlineData("readme.txt", false)]           // nome genérico demais sozinho
    [InlineData("!!!_READ_ME_!!!.txt", true)]
    [InlineData("How_To_Recover_Files.html", true)]
    [InlineData("DECRYPT-FILES.hta", true)]
    [InlineData("relatorio_mensal.txt", false)]
    public void Note_name_patterns(string name, bool isNote)
    {
        Assert.Equal(isNote, RansomNoteNames.Matches(name, new DetectionOptions().NoteNamePatterns));
    }

    [Fact]
    public void Ransom_note_counts_even_for_allowlisted_actor()
    {
        var opts = new DetectionOptions { AllowlistedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { User } };
        var events = Enumerable.Range(0, 3).Select(i => Ev(T0.AddSeconds(i), $"d{i}\\RECOVER-FILES.txt")).ToList();
        Assert.Equal(Confidence.High, Single(new DetectionEngine(opts), events)!.Confidence);
    }

    // ── extensão conhecida do catálogo ────────────────────────────────────────────────────────

    [Fact]
    public void Renaming_a_few_files_to_a_known_ransomware_extension_is_high_confidence()
    {
        var opts = new DetectionOptions { KnownExtensionsProvider = () => new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".lockbit", ".akira" } };
        var events = Enumerable.Range(0, 5).Select(i => Ev(T0.AddSeconds(i), $"f{i}.xlsx", FileOp.Rename, ".lockbit")).ToList();
        var d = Single(new DetectionEngine(opts), events)!;
        Assert.Contains(DetectionReason.KnownRansomExtension, d.Reasons);
        Assert.Equal(Confidence.High, d.Confidence);
    }

    [Fact]
    public void Unknown_extension_flip_below_mass_threshold_is_not_a_detection()
    {
        var opts = new DetectionOptions { KnownExtensionsProvider = () => new HashSet<string> { ".lockbit" } };
        var events = Enumerable.Range(0, 5).Select(i => Ev(T0.AddSeconds(i), $"f{i}.xlsx", FileOp.Rename, ".bak")).ToList();
        Assert.Null(Single(new DetectionEngine(opts), events));
    }

    // ── share-isca ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Any_access_to_a_decoy_share_is_high_confidence()
    {
        var opts = new DetectionOptions { DecoyShares = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"\\FS01\Backup$" } };
        var d = Single(new DetectionEngine(opts), new[] { Ev(T0, "x.docx", FileOp.Read, share: @"\\FS01\Backup$") })!;
        Assert.Contains(DetectionReason.DecoyShareTouched, d.Reasons);
        Assert.Equal(Confidence.High, d.Confidence);
    }

    // ── janela entre ciclos e low-and-slow (tracker) ─────────────────────────────────────────

    [Fact]
    public void Sixty_second_window_accumulates_across_five_second_batches()
    {
        var tracker = new ActorActivityTracker();
        var engine = new DetectionEngine(new DetectionOptions { MassThreshold = 40, RollingWindowThreshold = 120 }, tracker);
        // 25 escritas por lote de 5 s: nenhum lote sozinho chega a 40, mas em 60 s são 150 (≥ 120 da janela acumulada).
        Detection.Detection? last = null;
        for (var b = 0; b < 6; b++)
        {
            var batch = Enumerable.Range(0, 25).Select(i => Ev(T0.AddSeconds(b * 5 + i * 0.2), $"f{b}-{i}.xlsx")).ToList();
            last = engine.Analyze(batch).SingleOrDefault();
        }
        Assert.NotNull(last);
        Assert.Contains(DetectionReason.MassRewrite, last!.Reasons);
        Assert.Equal(Confidence.Medium, last.Confidence);
    }

    [Fact]
    public void Low_and_slow_is_detected_by_the_cumulative_window_with_cooldown()
    {
        var tracker = new ActorActivityTracker();
        var opts = new DetectionOptions { SlowWindow = TimeSpan.FromMinutes(30), SlowThreshold = 300, SustainedCooldown = TimeSpan.FromMinutes(10) };
        var engine = new DetectionEngine(opts, tracker);
        var detections = new List<Detection.Detection>();
        // 1 escrita a cada 5 s por 30 min = 360 — nunca cruza 40/60 s.
        for (var i = 0; i < 360; i++)
            detections.AddRange(engine.Analyze(new[] { Ev(T0.AddSeconds(i * 5), $"slow{i}.xlsx") }));
        var sustained = detections.Where(d => d.Reasons.Contains(DetectionReason.SustainedRewrite)).ToList();
        Assert.True(sustained.Count >= 1, "low-and-slow não detectado");
        Assert.True(sustained.Count <= 2, $"re-emitido demais: {sustained.Count} (cooldown)");
        Assert.All(sustained, d => Assert.Equal(Confidence.Medium, d.Confidence));
    }

    [Fact]
    public void Rate_anomaly_against_the_actor_baseline_is_medium()
    {
        var tracker = new ActorActivityTracker();
        var opts = new DetectionOptions { MassThreshold = 1000, AnomalyFactor = 8, AnomalyMinFiles = 10 };
        var engine = new DetectionEngine(opts, tracker);
        // Baseline: 1 escrita por minuto durante 2 h.
        for (var m = 0; m < 120; m++) engine.Analyze(new[] { Ev(T0.AddMinutes(m), $"n{m}.docx") });
        // Pico: 30 escritas num minuto (30× a média), ainda abaixo do MassThreshold.
        var spike = Enumerable.Range(0, 30).Select(i => Ev(T0.AddMinutes(121).AddSeconds(i), $"s{i}.docx")).ToList();
        var d = engine.Analyze(spike).SingleOrDefault();
        Assert.NotNull(d);
        Assert.Contains(DetectionReason.RateAnomaly, d!.Reasons);
        Assert.Equal(Confidence.Medium, d.Confidence);
    }

    [Fact]
    public void Rate_anomaly_needs_history_and_respects_allowlist()
    {
        var engine = new DetectionEngine(new DetectionOptions { MassThreshold = 1000 }, new ActorActivityTracker());
        var spike = Enumerable.Range(0, 30).Select(i => Ev(T0.AddSeconds(i), $"s{i}.docx")).ToList();
        Assert.Null(engine.Analyze(spike).SingleOrDefault());        // sem histórico, sem anomalia

        var allow = new DetectionOptions { MassThreshold = 1000, AllowlistedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { User } };
        var engine2 = new DetectionEngine(allow, new ActorActivityTracker());
        for (var m = 0; m < 120; m++) engine2.Analyze(new[] { Ev(T0.AddMinutes(m), $"n{m}.docx") });
        Assert.Null(engine2.Analyze(Enumerable.Range(0, 30).Select(i => Ev(T0.AddMinutes(121).AddSeconds(i), $"s{i}.docx")).ToList()).SingleOrDefault());
    }

    [Fact]
    public void Tracker_forgets_old_buckets()
    {
        var tracker = new ActorActivityTracker(retention: TimeSpan.FromHours(1));
        tracker.Record(new[] { Ev(T0, "a") });
        tracker.Record(new[] { Ev(T0.AddHours(2), "b") });
        Assert.Equal(1, tracker.CountInWindow(new ActorKey(User, Ip, Share), T0.AddHours(2), TimeSpan.FromMinutes(1)));
        Assert.Equal(0, tracker.CountInWindow(new ActorKey(User, Ip, Share), T0.AddHours(2), TimeSpan.FromHours(3)) - 1);
    }
}

/// <summary>G5 — forense: caminhos afetados viajam com a detecção; leitura em massa remota é precursor de exfiltração.</summary>
public class ForensicsTests
{
    private static readonly DateTime T0 = new(2026, 10, 4, 15, 0, 0, DateTimeKind.Utc);
    private static FileEvent Ev(int i, FileOp op, string ip = "10.0.9.66") => new(T0.AddSeconds(i * 0.1), @"CORP\u", ip, @"\\FS01\Fin", op, $"d{i % 7}\\f{i}.xlsx", op == FileOp.Rename ? ".zzz" : null);

    [Fact]
    public void Detection_carries_distinct_affected_paths_capped()
    {
        var events = Enumerable.Range(0, 700).Select(i => Ev(i, FileOp.Rename)).Concat(Enumerable.Range(0, 700).Select(i => Ev(i, FileOp.Rename))).ToList();
        var d = new DetectionEngine().Analyze(events).Single();
        Assert.Equal(Detection.Detection.MaxAffectedPaths, d.AffectedPaths!.Count);
        Assert.Equal(d.AffectedPaths.Count, d.AffectedPaths.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Contains(d.AffectedPaths, p => p.EndsWith("f0.xlsx"));
    }

    [Fact]
    public void Mass_read_over_smb_is_medium_and_reads_do_not_count_as_affected_paths()
    {
        var reads = Enumerable.Range(0, 2500).Select(i => Ev(i, FileOp.Read)).ToList();
        var d = new DetectionEngine().Analyze(reads).Single();
        Assert.Contains(DetectionReason.MassRead, d.Reasons);
        Assert.Equal(Confidence.Medium, d.Confidence);
        Assert.Empty(d.AffectedPaths!);
    }

    [Fact]
    public void Local_mass_read_and_allowlisted_reads_are_not_flagged()
    {
        Assert.Empty(new DetectionEngine().Analyze(Enumerable.Range(0, 2500).Select(i => Ev(i, FileOp.Read, ip: Detection.Detection.LocalOrigin)).ToList()));
        var opts = new DetectionOptions { AllowlistedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"CORP\u" } };
        Assert.Empty(new DetectionEngine(opts).Analyze(Enumerable.Range(0, 2500).Select(i => Ev(i, FileOp.Read)).ToList()));
    }
}
