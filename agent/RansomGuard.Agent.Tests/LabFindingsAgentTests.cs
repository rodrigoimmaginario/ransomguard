using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;
using RansomGuard.Core.Score;

namespace RansomGuard.Agent.Tests;

/// <summary>Correções do que a sessão 1 do laboratório mostrou, no agente.</summary>
public class LabFindingsAgentTests
{
    private static readonly DateTime T0 = new(2026, 11, 16, 23, 14, 0, DateTimeKind.Utc);

    private static string AuditChange(string changes, string guid = "{0CCE9244-69AE-11D9-BED3-505054503030}") =>
        "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>4719</EventID>" +
        "<TimeCreated SystemTime=\"2026-11-16T23:14:14Z\"/><Computer>rg-fs1.lab.ransomguard.test</Computer></System><EventData>" +
        "<Data Name=\"SubjectUserName\">RG-FS1$</Data><Data Name=\"SubjectDomainName\">RGLAB</Data>" +
        $"<Data Name=\"SubcategoryGuid\">{guid}</Data><Data Name=\"AuditPolicyChanges\">{changes}</Data></EventData></Event>";

    /// <summary>
    /// L2 — ao ligar a auditoria que faltava, o agente gerava o evento "política de auditoria alterada" e o lia como
    /// adulteração: todo servidor recém-instalado nascia com um incidente de Alta. Ligar auditoria não cega ninguém;
    /// o que cega é REMOVER a auditoria de sucesso. (%%8448 = sucesso removido, %%8449 = sucesso adicionado,
    /// %%8450 = falha removida, %%8451 = falha adicionada.)
    /// </summary>
    [Theory]
    [InlineData("%%8449")] [InlineData("%%8449, %%8451")] [InlineData("%%8451")]
    public void Ligar_auditoria_nao_e_adulteracao(string changes)
        => Assert.Null(VisibilityEventParser.Parse(AuditChange(changes)));

    [Theory]
    [InlineData("%%8448")] [InlineData("%%8448, %%8450")] [InlineData("%%8448, %%8451")]
    public void Remover_a_auditoria_de_sucesso_continua_sendo_adulteracao(string changes)
    {
        var signal = VisibilityEventParser.Parse(AuditChange(changes))!;

        Assert.Equal(HostSignalKind.AuditPolicyChanged, signal.Kind);
        Assert.Equal(Confidence.High, new DetectionEngine().Analyze(Array.Empty<FileEvent>(), new[] { signal }).Single().Confidence);
    }

    [Fact]
    public void Mudanca_que_o_agente_nao_sabe_ler_e_tratada_como_adulteracao()
        => Assert.NotNull(VisibilityEventParser.Parse(AuditChange("")));       // na dúvida, não fica em silêncio

    [Fact]
    public void Remover_so_a_auditoria_de_falha_nao_cega_o_agente()
        => Assert.Null(VisibilityEventParser.Parse(AuditChange("%%8450")));

    // ── L3: um ataque, um incidente ────────────────────────────────────────────────────────────

    private sealed class Posture : IPostureCollector { public PostureSnapshot Collect(string s) => new() { Server = s }; }
    private sealed class NoSignals : IHostSignalCollector { public IReadOnlyList<HostSignal> Drain() => Array.Empty<HostSignal>(); }
    private sealed class Feed : IFileEventCollector
    {
        public IReadOnlyList<FileEvent> Next { get; set; } = Array.Empty<FileEvent>();
        public IReadOnlyList<FileEvent> Drain() { var r = Next; Next = Array.Empty<FileEvent>(); return r; }
    }
    private sealed class Sink : IBatchSink
    {
        public List<AgentBatch> Sent { get; } = new();
        public Task<BatchResponse?> SendAsync(AgentBatch b, CancellationToken ct = default) { Sent.Add(b); return Task.FromResult<BatchResponse?>(new BatchResponse(null, null)); }
    }

    private static List<FileEvent> Burst(DateTime at, int offset) =>
        Enumerable.Range(0, 60).Select(i => new FileEvent(at.AddMilliseconds(i * 50), @"RGLAB\bruno", "10.88.1.40", @"\\rg-fs1\Dados", FileOp.Write, $"b1\\doc{offset + i}.docx", ".docx")).ToList();

    [Fact]
    public async Task Ciclos_seguidos_do_mesmo_ataque_enviam_o_mesmo_incidente_ao_painel()
    {
        var feed = new Feed();
        var sink = new Sink();
        var cycle = new AgentCycle("rg-fs1", new Posture(), feed, new NoSignals(), sink, new ResponseLadder(), new ResponsePolicy(), new RecordingExecutor());

        for (var c = 0; c < 3; c++)
        {
            feed.Next = Burst(T0.AddSeconds(c * 5), c * 60);
            await cycle.RunOnceAsync(T0.AddSeconds(c * 5 + 4), collectPosture: false);
        }

        var ids = sink.Sent.SelectMany(b => b.Incidents ?? Array.Empty<Core.Incidents.AgentIncident>()).Select(i => i.Id).ToList();
        Assert.Equal(3, ids.Count);
        Assert.Single(ids.Distinct());
    }
}
