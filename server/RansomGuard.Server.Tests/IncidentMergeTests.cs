using Microsoft.EntityFrameworkCore;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Incidents;
using RansomGuard.Core.Response;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Ingestion;

namespace RansomGuard.Server.Tests;

/// <summary>
/// L3 (laboratório, sessão 1) — o agente passa a mandar o mesmo identificador para os ciclos de um mesmo ataque; o
/// painel ATUALIZA o incidente em vez de criar outro ou ignorar o que chegou depois.
/// </summary>
public class IncidentMergeTests : DbTestBase
{
    private static readonly DateTime T0 = new(2026, 11, 16, 23, 28, 31, DateTimeKind.Utc);

    private static async Task<AgentIncident> IncidentAsync(Confidence confidence, int files, DateTime last, bool contained, params DetectionReason[] reasons)
    {
        var detection = new Detection("rg-fs1", @"RGLAB\bruno", "10.88.1.40", @"\\rg-fs1\Dados", confidence, reasons.ToHashSet(), files, T0, last,
            AffectedPaths: Enumerable.Range(0, 3).Select(i => $"b1\\doc-{last.Second}-{i}.docx").ToList());
        var decision = contained
            ? new ResponseLadder().Decide(detection, new ResponsePolicy { Mode = ResponseMode.Block })
            : ResponseDecision.None("monitor");
        var runner = new ResponseRunner(new RecordingExecutor());
        await runner.RunAsync(decision, last);
        return AgentIncident.From(detection, decision, runner.Audit, contained ? ResponseMode.Block : ResponseMode.Monitor, incidentId: "episodio-1");
    }

    private static AgentBatch Batch(AgentIncident incident, DateTime at) =>
        new("rg-fs1", at, null, Array.Empty<FileEvent>(), Array.Empty<HostSignal>(), new[] { incident });

    [Fact]
    public async Task O_segundo_ciclo_do_mesmo_ataque_atualiza_o_incidente_e_so_alerta_de_novo_porque_virou_alta()
    {
        var sink = new CollectingAlertSink();
        var svc = new IngestionService(Db, new AlertEngine(sink));

        var first = await svc.IngestAsync(Batch(await IncidentAsync(Confidence.Medium, 40, T0.AddSeconds(4), contained: false, DetectionReason.MassRewrite), T0.AddSeconds(5)));
        Assert.Equal(1, first.NewDetections);
        Assert.Single(sink.Sent);                                 // incidente novo: um alerta (o filtro por severidade é do canal)

        var second = await svc.IngestAsync(Batch(await IncidentAsync(Confidence.High, 30, T0.AddSeconds(9), contained: true, DetectionReason.CanaryTouched, DetectionReason.MassRewrite), T0.AddSeconds(10)));
        Assert.Equal(0, second.NewDetections);                    // é o mesmo incidente
        Assert.Equal(1, second.AlertsRaised);

        var record = await Db.Detections.Include(d => d.Actions).SingleAsync();
        Assert.Equal(Confidence.High, record.Confidence);
        Assert.Equal(70, record.AffectedFiles);
        Assert.Contains("CanaryTouched", record.Reasons);
        Assert.Contains("MassRewrite", record.Reasons);
        Assert.True(record.Contained);
        Assert.Equal(T0.AddSeconds(9), record.At);
        Assert.Contains(record.Actions, a => a.Step == "BlockIp");
        Assert.Equal(2, sink.Sent.Count);                         // o segundo é a escalada para Alta — não um alerta por ciclo
    }

    [Fact]
    public async Task Lote_reentregue_nao_soma_de_novo_nem_duplica_acoes()
    {
        var svc = new IngestionService(Db, new AlertEngine(new CollectingAlertSink()));
        var incident = await IncidentAsync(Confidence.High, 30, T0.AddSeconds(9), contained: true, DetectionReason.CanaryTouched);

        await svc.IngestAsync(Batch(incident, T0.AddSeconds(10)));
        var actions = await Db.ResponseActions.CountAsync();
        var again = await svc.IngestAsync(Batch(incident, T0.AddSeconds(10)));   // a fila do agente reenviou o mesmo lote

        Assert.Equal(0, again.NewDetections);
        Assert.Equal(0, again.AlertsRaised);
        Assert.Equal(30, (await Db.Detections.SingleAsync()).AffectedFiles);
        Assert.Equal(actions, await Db.ResponseActions.CountAsync());
    }

    [Fact]
    public async Task Incidente_que_ja_e_alta_nao_volta_a_media_nem_alerta_de_novo()
    {
        var sink = new CollectingAlertSink();
        var svc = new IngestionService(Db, new AlertEngine(sink));

        await svc.IngestAsync(Batch(await IncidentAsync(Confidence.High, 30, T0.AddSeconds(4), contained: true, DetectionReason.CanaryTouched), T0.AddSeconds(5)));
        var later = await svc.IngestAsync(Batch(await IncidentAsync(Confidence.Medium, 50, T0.AddSeconds(9), contained: false, DetectionReason.MassDelete), T0.AddSeconds(10)));

        var record = await Db.Detections.SingleAsync();
        Assert.Equal(Confidence.High, record.Confidence);
        Assert.True(record.Contained);
        Assert.Equal(80, record.AffectedFiles);
        Assert.Contains("MassDelete", record.Reasons);
        Assert.Equal(0, later.AlertsRaised);
        Assert.Single(sink.Sent);
    }
}
