using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Score;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Data;
using RansomGuard.Server.Ingestion;

namespace RansomGuard.Server.Tests;

/// <summary>Cria um DbContext SQLite in-memory real (fiel ao provider de produção).</summary>
public abstract class DbTestBase : IDisposable
{
    private readonly SqliteConnection _conn;
    protected readonly RansomGuardDb Db;

    protected DbTestBase()
    {
        _conn = new SqliteConnection("DataSource=:memory:");
        _conn.Open();
        var options = new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite(_conn).Options;
        Db = new RansomGuardDb(options);
        Db.Database.EnsureCreated();
    }

    public void Dispose() { Db.Dispose(); _conn.Dispose(); }
}

public class IngestionTests : DbTestBase
{
    private static readonly DateTime T0 = new(2026, 7, 23, 2, 0, 0, DateTimeKind.Utc);

    private static PostureSnapshot BadPosture(string server) => new()
    {
        Server = server,
        SharesWritableByEveryone = true,
        VssEnabled = false,
        BackupServiceRunning = false,
        FsrmActive = false,
        AgentInstalled = true,
        SmbSigningRequired = true,
        SmbAuthRateLimiter = true,
        BackupsProtected = true,
        ShareAuditingEnabled = true,
        CanariesPlanted = true
    };

    private static IReadOnlyList<FileEvent> RemoteAttack(string share) =>
        Enumerable.Range(0, 80).Select(i =>
            new FileEvent(T0.AddSeconds(i), @"CORP\vendas", "10.0.9.66", share,
                FileOp.Rename, $"f{i}.xlsx", ".locked")).ToList();

    [Fact]
    public async Task Batch_with_posture_persists_score_on_server()
    {
        var sink = new CollectingAlertSink();
        var svc = new IngestionService(Db, new AlertEngine(sink));

        var result = await svc.IngestAsync(new AgentBatch(
            "FS01", T0, BadPosture("FS01"), Array.Empty<FileEvent>(), Array.Empty<HostSignal>()));

        var server = await Db.Servers.SingleAsync();
        Assert.Equal("FS01", server.Name);
        // Postura viola share-everyone(11)+vss(8)+backup(8)+fsrm(5) = -32 → 68/100.
        Assert.Equal(68, server.LastScore);
        Assert.Equal(server.LastScore, result.Score);
        Assert.Single(Db.PostureRecords);
    }

    [Fact]
    public async Task Remote_smb_attack_creates_attributed_detection_and_alerts()
    {
        var sink = new CollectingAlertSink();
        var svc = new IngestionService(Db, new AlertEngine(sink));

        // Ataque remoto com deleção de VSS → alta confiança → alerta.
        var signals = new[] { new HostSignal(T0.AddSeconds(5), HostSignalKind.VssDeleted, "FS01") };
        var result = await svc.IngestAsync(new AgentBatch(
            "FS01", T0, null, RemoteAttack(@"\\FS01\Financeiro"), signals));

        var det = await Db.Detections.SingleAsync();
        Assert.Equal("10.0.9.66", det.SourceIp);          // atribuído ao IP remoto
        Assert.Equal(Confidence.High, det.Confidence);
        Assert.True(det.Alerted);
        Assert.Equal(1, result.AlertsRaised);
        Assert.Single(sink.Sent);
        Assert.Contains("Incidente", sink.Sent[0].Subject);
    }

    [Fact]
    public async Task Medium_confidence_does_not_alert()
    {
        var sink = new CollectingAlertSink();
        var svc = new IngestionService(Db, new AlertEngine(sink));

        // Só volume (sem canário/VSS) → Medium → sem alerta (evita ruído no free).
        await svc.IngestAsync(new AgentBatch(
            "FS02", T0, null, RemoteAttack(@"\\FS02\Sh"), Array.Empty<HostSignal>()));

        var det = await Db.Detections.SingleAsync();
        Assert.Equal(Confidence.Medium, det.Confidence);
        Assert.False(det.Alerted);
        Assert.Empty(sink.Sent);
    }

    /// <summary>Serviço com o relógio do PAINEL controlado pelo teste.</summary>
    private (IngestionService Svc, Action<DateTime> SetNow) WithClock(CollectingAlertSink? sink = null)
    {
        var now = T0;
        return (new IngestionService(Db, new AlertEngine(sink ?? new CollectingAlertSink()), clock: () => now), t => now = t);
    }

    [Fact]
    public async Task Heartbeat_is_recorded_and_refreshed()
    {
        var (svc, setNow) = WithClock();
        await svc.IngestAsync(AgentBatch.Heartbeat("FS01", T0));
        setNow(T0.AddMinutes(5));
        await svc.IngestAsync(AgentBatch.Heartbeat("FS01", T0.AddMinutes(5)));

        var hb = await Db.Heartbeats.SingleAsync();
        Assert.Equal(T0.AddMinutes(5), hb.LastBeat);
    }

    /// <summary>
    /// B3 — o batimento é a hora em que o PAINEL recebeu o lote, não a que o agente declarou. Um agente com o relógio
    /// adiantado (ou um lote forjado com data futura) mantinha o batimento "fresco" para sempre e o alerta de agente
    /// silencioso nunca disparava.
    /// </summary>
    [Fact]
    public async Task Relogio_adiantado_do_agente_nao_esconde_o_silencio()
    {
        var sink = new CollectingAlertSink();
        var (svc, _) = WithClock(sink);
        await svc.IngestAsync(AgentBatch.Heartbeat("FS01", T0.AddDays(30)));      // o agente diz que é daqui a um mês

        var hb = await Db.Heartbeats.SingleAsync();
        Assert.Equal(T0, hb.LastBeat);
        Assert.Equal(T0, (await Db.Servers.SingleAsync()).LastSeen);

        Assert.Equal(1, await svc.CheckHeartbeatsAsync(T0.AddMinutes(20), TimeSpan.FromMinutes(10)));
    }

    /// <summary>E o inverso: relógio atrasado não faz um agente vivo parecer morto.</summary>
    [Fact]
    public async Task Relogio_atrasado_do_agente_nao_gera_alerta_falso_de_silencio()
    {
        var (svc, _) = WithClock();
        await svc.IngestAsync(AgentBatch.Heartbeat("FS01", T0.AddHours(-3)));

        Assert.Equal(0, await svc.CheckHeartbeatsAsync(T0.AddMinutes(5), TimeSpan.FromMinutes(10)));
    }

    [Fact]
    public async Task Silent_agent_raises_tamper_alert_once()
    {
        var sink = new CollectingAlertSink();
        var (svc, _) = WithClock(sink);
        await svc.IngestAsync(AgentBatch.Heartbeat("FS01", T0));

        // 20 min depois, com limite de 10 min → tamper.
        var raised = await svc.CheckHeartbeatsAsync(T0.AddMinutes(20), TimeSpan.FromMinutes(10));
        Assert.Equal(1, raised);
        Assert.Contains("tamper", sink.Sent[0].Subject);

        // Repetir não deve alertar de novo (idempotente).
        var again = await svc.CheckHeartbeatsAsync(T0.AddMinutes(30), TimeSpan.FromMinutes(10));
        Assert.Equal(0, again);
    }

    [Fact]
    public async Task Recovered_heartbeat_clears_tamper_state()
    {
        var sink = new CollectingAlertSink();
        var (svc, setNow) = WithClock(sink);
        await svc.IngestAsync(AgentBatch.Heartbeat("FS01", T0));
        await svc.CheckHeartbeatsAsync(T0.AddMinutes(20), TimeSpan.FromMinutes(10));

        // Agente volta a bater → estado de tamper limpa → novo silêncio alerta de novo.
        setNow(T0.AddMinutes(25));
        await svc.IngestAsync(AgentBatch.Heartbeat("FS01", T0.AddMinutes(25)));
        var raised = await svc.CheckHeartbeatsAsync(T0.AddMinutes(40), TimeSpan.FromMinutes(10));
        Assert.Equal(1, raised);
    }
}
