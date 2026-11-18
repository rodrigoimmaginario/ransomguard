using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;
using RansomGuard.Core.Score;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// E7 — depois de uma parada longa, o agente retoma o Security log de onde parou e encontra eventos de horas
/// atrás. Registrar e alertar, sim; conter, não: bloquear agora o IP ou a conta de uma atividade antiga atinge
/// quem já não está atacando (ou um usuário que só recebeu aquele endereço depois).
/// </summary>
public class StaleEventTests
{
    private static readonly DateTime Now = new(2026, 11, 16, 15, 0, 0, DateTimeKind.Utc);

    private sealed class Posture : IPostureCollector { public PostureSnapshot Collect(string s) => new() { Server = s }; }
    private sealed class CanaryAt(DateTime at) : IFileEventCollector
    {
        public IReadOnlyList<FileEvent> Drain() => new[]
        {
            new FileEvent(at, @"CORP\vendas1", "10.0.9.66", @"\\FS01\Financeiro", FileOp.Write, "!0__ransomguard_canary.docx", ".docx", IsCanary: true)
        };
    }
    private sealed class NoSignals : IHostSignalCollector { public IReadOnlyList<HostSignal> Drain() => Array.Empty<HostSignal>(); }
    private sealed class Sink : IBatchSink
    {
        public List<AgentBatch> Sent = new();
        public Task<BatchResponse?> SendAsync(AgentBatch b, CancellationToken ct = default) { Sent.Add(b); return Task.FromResult<BatchResponse?>(new BatchResponse()); }
    }

    private static (AgentCycle Cycle, RecordingExecutor Exec, Sink Sink) Agent(DateTime eventAt)
    {
        var exec = new RecordingExecutor(); var sink = new Sink();
        var cycle = new AgentCycle("FS01", new Posture(), new CanaryAt(eventAt), new NoSignals(), sink,
            new ResponseLadder(), new ResponsePolicy { Mode = ResponseMode.Block }, exec);
        return (cycle, exec, sink);
    }

    [Fact]
    public async Task Evento_antigo_e_registrado_mas_nao_contido()
    {
        var (cycle, exec, sink) = Agent(Now.AddHours(-2));

        var result = await cycle.RunOnceAsync(Now);

        Assert.Equal(1, result.Detections);
        Assert.Equal(0, result.LocalContainments);
        Assert.Empty(exec.Executed);                                  // nem snapshot: o estado de 2 h atrás já passou
        var incident = Assert.Single(sink.Sent.Single().Incidents!);
        Assert.False(incident.Contained);
        Assert.Contains("antigo", incident.Rationale, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Evento_recente_e_contido_normalmente()
    {
        var (cycle, exec, _) = Agent(Now.AddSeconds(-30));

        var result = await cycle.RunOnceAsync(Now);

        Assert.True(result.LocalContainments > 0);
        Assert.Contains(exec.Executed, a => a.Step == ResponseStep.BlockIp);
    }

    [Fact]
    public async Task O_limite_e_inclusivo_e_logo_depois_dele_nao_ha_contencao()
    {
        var (noLimite, execNoLimite, _) = Agent(Now - AgentCycle.MaxActionAge);
        await noLimite.RunOnceAsync(Now);
        Assert.NotEmpty(execNoLimite.Executed);

        var (depois, execDepois, _) = Agent(Now - AgentCycle.MaxActionAge - TimeSpan.FromSeconds(1));
        await depois.RunOnceAsync(Now);
        Assert.Empty(execDepois.Executed);
    }

    /// <summary>Relógio do evento adiantado em relação ao do agente não pode ser tratado como "antigo".</summary>
    [Fact]
    public async Task Evento_com_data_ligeiramente_no_futuro_e_contido()
    {
        var (cycle, exec, _) = Agent(Now.AddSeconds(20));

        await cycle.RunOnceAsync(Now);

        Assert.NotEmpty(exec.Executed);
    }
}
