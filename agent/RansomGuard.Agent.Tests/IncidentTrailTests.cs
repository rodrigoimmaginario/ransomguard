using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;
using RansomGuard.Core.Score;

namespace RansomGuard.Agent.Tests;

/// <summary>F32 — o lote leva a trilha real do incidente (detecção, decisão, ações e resultados).</summary>
public class IncidentTrailTests
{
    private static readonly DateTime T0 = new(2026, 10, 3, 12, 0, 0, DateTimeKind.Utc);
    private sealed class Posture : IPostureCollector { public PostureSnapshot Collect(string s) => new() { Server = s }; }
    private sealed class Events(IReadOnlyList<FileEvent> e) : IFileEventCollector { private IReadOnlyList<FileEvent> _e = e; public IReadOnlyList<FileEvent> Drain() { var r = _e; _e = Array.Empty<FileEvent>(); return r; } }
    private sealed class NoSignals : IHostSignalCollector { public IReadOnlyList<HostSignal> Drain() => Array.Empty<HostSignal>(); }
    private sealed class Sink : IBatchSink { public AgentBatch? Last; public Task<BatchResponse?> SendAsync(AgentBatch b, CancellationToken ct = default) { Last = b; return Task.FromResult<BatchResponse?>(null); } }
    private sealed class FlakyExecutor : IResponseExecutor
    {
        public Task<ResponseOutcome> ExecuteAsync(ResponseAction a, CancellationToken ct = default) =>
            Task.FromResult(a.Step == ResponseStep.BlockIp ? ResponseOutcome.Fail("firewall indisponível") : ResponseOutcome.Done());
        public Task<ResponseOutcome> RevertAsync(ResponseAction a, CancellationToken ct = default) => Task.FromResult(ResponseOutcome.Done());
    }

    private static IReadOnlyList<FileEvent> CanaryAttack() =>
        Enumerable.Range(0, 50).Select(i => new FileEvent(T0.AddSeconds(i), @"CORP\v", "10.0.9.66", @"\\FS01\Fin",
            FileOp.Rename, $"f{i}.xlsx", ".locked", IsCanary: i == 3)).ToList();

    [Fact]
    public async Task Batch_carries_incident_with_executed_and_failed_actions()
    {
        var sink = new Sink();
        var cycle = new AgentCycle("FS01", new Posture(), new Events(CanaryAttack()), new NoSignals(), sink,
            new ResponseLadder(), new ResponsePolicy { Mode = ResponseMode.Block, MaxStep = ResponseStep.DisableAdAccount },
            new FlakyExecutor());

        var result = await cycle.RunOnceAsync(T0.AddMinutes(1));

        var inc = Assert.Single(sink.Last!.Incidents!);
        Assert.Equal("Block", inc.Mode);
        Assert.True(inc.Contained);
        Assert.Equal(5, inc.Report.Actions.Count);                                   // snapshot + 4 degraus
        Assert.Equal(new[] { "fail", "execute", "execute", "execute", "execute" }, inc.Report.Actions.Select(a => a.Operation));
        Assert.Equal("PreemptiveSnapshot", inc.Report.Actions[^1].Step);   // L4: o snapshot vem depois do bloqueio
        Assert.Equal("BlockIp", inc.Report.Actions[0].Step);
        Assert.Contains("firewall", inc.Report.Actions[0].Justification);
        Assert.Equal(3, result.LocalContainments);                                   // snapshot não conta
        Assert.Equal(inc.Id, Core.Incidents.AgentIncident.ComputeId("FS01", @"CORP\v", "10.0.9.66", @"\\FS01\Fin", T0));
    }

    [Fact]
    public async Task Monitor_mode_batch_carries_incident_without_actions()
    {
        var sink = new Sink();
        var cycle = new AgentCycle("FS01", new Posture(), new Events(CanaryAttack()), new NoSignals(), sink,
            new ResponseLadder(), new ResponsePolicy { Mode = ResponseMode.Monitor }, new RecordingExecutor());
        await cycle.RunOnceAsync(T0.AddMinutes(1));
        var inc = Assert.Single(sink.Last!.Incidents!);
        Assert.False(inc.Contained);
        Assert.Empty(inc.Report.Actions);
        Assert.Equal("Monitor", inc.Mode);
    }

    [Fact]
    public async Task Quiet_cycle_sends_an_empty_incident_list_not_null()
    {
        var sink = new Sink();
        var cycle = new AgentCycle("FS01", new Posture(), new Events(Array.Empty<FileEvent>()), new NoSignals(), sink,
            new ResponseLadder(), new ResponsePolicy(), new RecordingExecutor());
        await cycle.RunOnceAsync(T0);
        Assert.NotNull(sink.Last!.Incidents);
        Assert.Empty(sink.Last.Incidents!);
    }
}

/// <summary>G7 — a extensão de um incidente de Alta vira file screen dinâmico; documento comum nunca é aprendido.</summary>
public class LearnedExtensionTests
{
    private static readonly DateTime T0 = new(2026, 10, 4, 17, 0, 0, DateTimeKind.Utc);
    private sealed class Posture : IPostureCollector { public PostureSnapshot Collect(string s) => new() { Server = s }; }
    private sealed class Events(IReadOnlyList<FileEvent> e) : IFileEventCollector { private IReadOnlyList<FileEvent> _e = e; public IReadOnlyList<FileEvent> Drain() { var r = _e; _e = Array.Empty<FileEvent>(); return r; } }
    private sealed class NoSignals : IHostSignalCollector { public IReadOnlyList<HostSignal> Drain() => Array.Empty<HostSignal>(); }
    private sealed class Sink : IBatchSink { public Task<BatchResponse?> SendAsync(AgentBatch b, CancellationToken ct = default) => Task.FromResult<BatchResponse?>(null); }

    private static async Task<AgentCycle> Run(string ext, bool canary)
    {
        var events = Enumerable.Range(0, 50).Select(i => new FileEvent(T0.AddSeconds(i), @"CORP\v", "10.0.9.66", @"\FS01\Fin", FileOp.Rename, $"f{i}.xlsx", ext, IsCanary: canary && i == 2)).ToList();
        var cycle = new AgentCycle("FS01", new Posture(), new Events(events), new NoSignals(), new Sink(), new ResponseLadder(), new ResponsePolicy(), new RecordingExecutor());
        await cycle.RunOnceAsync(T0.AddMinutes(1));
        return cycle;
    }

    [Fact]
    public async Task High_incident_extension_is_learned() => Assert.Contains(".zzq", (await Run(".zzq", canary: true)).LearnedExtensions);

    [Fact]
    public async Task Medium_incident_does_not_teach_and_common_extensions_are_never_learned()
    {
        Assert.Empty((await Run(".zzq", canary: false)).LearnedExtensions);   // só Média (volume): não aprende
        Assert.Empty((await Run(".docx", canary: true)).LearnedExtensions);  // Alta, mas extensão de documento comum
    }
    private static async Task<AgentCycle> RunEvents(IEnumerable<FileEvent> events)
    {
        var cycle = new AgentCycle("FS01", new Posture(), new Events(events.ToList()), new NoSignals(), new Sink(), new ResponseLadder(), new ResponsePolicy(), new RecordingExecutor());
        await cycle.RunOnceAsync(T0.AddMinutes(1));
        return cycle;
    }

    /// <summary>Como o coletor real entrega: a extensão que vem no evento é a do próprio arquivo.</summary>
    private static FileEvent Real(int i, FileOp op, string path, bool canary = false) =>
        new(T0.AddSeconds(i % 50), @"CORP\v", "10.0.9.66", @"\FS01\Fin", op, path, System.IO.Path.GetExtension(path), IsCanary: canary);

    /// <summary>
    /// D2 — num incidente de Alta, o que o ator gravou não é "extensão do ransomware". Antes, toda extensão fora de
    /// uma lista de 18 entrava no file screen: com o FSRM em bloqueio, o servidor passava a recusar .dwg, .psd e .sql
    /// para todos.
    /// </summary>
    [Fact]
    public async Task Trabalho_gravado_durante_um_incidente_de_Alta_nao_ensina_extensao()
    {
        var events = new[] { ".dwg", ".psd", ".sql", ".rvt", ".abc1" }
            .SelectMany((ext, k) => Enumerable.Range(0, 30).Select(i => Real(i, FileOp.Write, $"arq{k}-{i}{ext}")))
            .Append(Real(0, FileOp.Write, "!0__ransomguard_canary.docx", canary: true));

        var cycle = await RunEvents(events);

        Assert.Empty(cycle.LearnedExtensions);
    }

    [Fact]
    public async Task Troca_observada_para_extensao_desconhecida_e_aprendida_e_para_extensao_de_trabalho_nao()
    {
        IEnumerable<FileEvent> Flip(string from, string to, int count) => Enumerable.Range(0, count).SelectMany(i => new[]
        {
            Real(i, FileOp.Write, $"f{i}{from}{to}"), Real(i, FileOp.Delete, $"f{i}{from}")
        });
        var canary = Real(0, FileOp.Write, "!0__ransomguard_canary.docx", canary: true);

        Assert.Equal(new[] { ".zzq" }, (await RunEvents(Flip(".xlsx", ".zzq", 20).Append(canary))).LearnedExtensions);
        Assert.Empty((await RunEvents(Flip(".xlsx", ".dwg", 20).Append(canary))).LearnedExtensions);       // extensão de trabalho
        Assert.Empty((await RunEvents(Flip(".xlsx", ".zzq", 2).Append(canary))).LearnedExtensions);        // duas trocas não são padrão
    }

    [Fact]
    public async Task Ha_teto_para_o_que_um_agente_aprende_sozinho()
    {
        var events = Enumerable.Range(0, 40).SelectMany(k => Enumerable.Range(0, AgentCycle.MinChangesToLearn).SelectMany(i => new[]
        {
            Real(i, FileOp.Write, $"g{k}-{i}.xlsx.x{k:00}q"), Real(i, FileOp.Delete, $"g{k}-{i}.xlsx")
        })).Append(Real(0, FileOp.Write, "!0__ransomguard_canary.docx", canary: true));

        var cycle = await RunEvents(events);

        Assert.Equal(AgentCycle.MaxLearnedExtensions, cycle.LearnedExtensions.Count);
    }
}
