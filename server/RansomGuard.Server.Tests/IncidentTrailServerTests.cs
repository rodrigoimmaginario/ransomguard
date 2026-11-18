using System.Net.Http.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Incidents;
using RansomGuard.Core.Response;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Data;
using RansomGuard.Server.Ingestion;

namespace RansomGuard.Server.Tests;

/// <summary>F32 — o painel persiste a trilha real do agente; não re-analisa quando a verdade chega.</summary>
public sealed class IncidentTrailServerTests : IDisposable
{
    private static readonly DateTime T0 = new(2026, 10, 3, 12, 0, 0, DateTimeKind.Utc);
    private readonly SqliteConnection _conn;
    private readonly RansomGuardDb _db;
    private readonly CollectingAlertSink _sink = new();

    public IncidentTrailServerTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:");
        _conn.Open();
        _db = new RansomGuardDb(new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite(_conn).Options);
        _db.Database.EnsureCreated();
    }
    public void Dispose() { _db.Dispose(); _conn.Dispose(); }

    private static Detection Det() => new("FS01", @"CORP\ana", "10.0.9.66", @"\\FS01\Fin", Confidence.High,
        new HashSet<DetectionReason> { DetectionReason.CanaryTouched, DetectionReason.MassRename }, 120, T0, T0.AddSeconds(30));

    private static async Task<AgentIncident> ContainedIncident()
    {
        var decision = new ResponseLadder().Decide(Det(), new ResponsePolicy { Mode = ResponseMode.Block, MaxStep = ResponseStep.DisableAdAccount });
        var runner = new ResponseRunner(new FlakyExecutor());
        await runner.RunAsync(decision, T0.AddSeconds(31));
        return AgentIncident.From(Det(), decision, runner.Audit, ResponseMode.Block);
    }

    private static IReadOnlyList<FileEvent> RawAttack() =>
        Enumerable.Range(0, 60).Select(i => new FileEvent(T0.AddSeconds(i), @"CORP\ana", "10.0.9.66", @"\\FS01\Fin", FileOp.Rename, $"f{i}.xlsx", ".locked", IsCanary: i == 2)).ToList();

    [Fact]
    public async Task Agent_incident_is_persisted_with_its_action_trail_and_alerted()
    {
        var inc = await ContainedIncident();
        var svc = new IngestionService(_db, new AlertEngine(_sink));

        var result = await svc.IngestAsync(new AgentBatch("FS01", T0.AddMinutes(1), null, RawAttack(), Array.Empty<HostSignal>(), new[] { inc }));

        Assert.Equal(1, result.NewDetections);
        var rec = await _db.Detections.Include(d => d.Actions).SingleAsync();
        Assert.Equal(inc.Id, rec.IncidentId);
        Assert.Equal("agent", rec.Source);
        Assert.Equal("Block", rec.Mode);
        Assert.True(rec.Contained);
        Assert.True(rec.Alerted);
        Assert.Equal(5, rec.Actions.Count);
        Assert.Equal(new[] { "fail", "execute", "execute", "execute", "execute" }, rec.Actions.OrderBy(a => a.Id).Select(a => a.Operation));
        Assert.Contains(DetectionReason.CanaryTouched.ToString(), rec.Reasons);
        Assert.Single(_sink.Sent);
    }

    [Fact]
    public async Task Same_incident_sent_twice_is_stored_once()
    {
        var inc = await ContainedIncident();
        var svc = new IngestionService(_db, new AlertEngine(_sink));
        await svc.IngestAsync(new AgentBatch("FS01", T0.AddMinutes(1), null, RawAttack(), Array.Empty<HostSignal>(), new[] { inc }));
        var second = await svc.IngestAsync(new AgentBatch("FS01", T0.AddMinutes(2), null, Array.Empty<FileEvent>(), Array.Empty<HostSignal>(), new[] { inc }));

        Assert.Equal(0, second.NewDetections);
        Assert.Equal(1, await _db.Detections.CountAsync());
        Assert.Equal(5, await _db.ResponseActions.CountAsync());
        Assert.Single(_sink.Sent);
    }

    [Fact]
    public async Task When_agent_sends_incidents_the_panel_does_not_reanalyze_raw_events()
    {
        // eventos crus que o painel detectaria sozinho, mas o agente diz "nenhum incidente" (ex.: allowlist no agente)
        var svc = new IngestionService(_db, new AlertEngine(_sink));
        var result = await svc.IngestAsync(new AgentBatch("FS01", T0.AddMinutes(1), null, RawAttack(), Array.Empty<HostSignal>(), Array.Empty<AgentIncident>()));
        Assert.Equal(0, result.NewDetections);
        Assert.Equal(0, await _db.Detections.CountAsync());
    }

    [Fact]
    public async Task Legacy_agent_without_incident_list_still_gets_panel_side_analysis_marked_as_panel()
    {
        var svc = new IngestionService(_db, new AlertEngine(_sink));
        var result = await svc.IngestAsync(new AgentBatch("FS01", T0.AddMinutes(1), null, RawAttack(), Array.Empty<HostSignal>()));
        Assert.Equal(1, result.NewDetections);
        var rec = await _db.Detections.SingleAsync();
        Assert.Equal("panel", rec.Source);
        Assert.Null(rec.IncidentId);
    }

    [Fact]
    public async Task Additive_schema_upgrades_a_database_created_before_f32()
    {
        // simula banco antigo: tabela Detections sem as colunas F32 e sem ResponseActions
        await using var conn = new SqliteConnection("DataSource=:memory:");
        await conn.OpenAsync();
        await using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = """
                CREATE TABLE "Servers" ("Id" INTEGER PRIMARY KEY AUTOINCREMENT, "Name" TEXT NOT NULL, "FirstSeen" TEXT NOT NULL, "LastSeen" TEXT NOT NULL, "LastScore" INTEGER NOT NULL, "LastBand" INTEGER NOT NULL);
                CREATE TABLE "Detections" ("Id" INTEGER PRIMARY KEY AUTOINCREMENT, "ServerId" INTEGER NOT NULL, "At" TEXT NOT NULL, "User" TEXT NOT NULL, "SourceIp" TEXT NOT NULL, "Share" TEXT NOT NULL, "Confidence" INTEGER NOT NULL, "AffectedFiles" INTEGER NOT NULL, "Reasons" TEXT NOT NULL, "Alerted" INTEGER NOT NULL);
                INSERT INTO "Servers" VALUES (1, 'FS01', '2026-01-01', '2026-01-01', 50, 1);
                INSERT INTO "Detections" ("ServerId","At","User","SourceIp","Share","Confidence","AffectedFiles","Reasons","Alerted") VALUES (1, '2026-01-01', 'u', '10.0.0.1', 's', 1, 5, 'MassRewrite', 1);
                """;
            await cmd.ExecuteNonQueryAsync();
        }
        var db = new RansomGuardDb(new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite(conn).Options);

        await IncidentSchema.EnsureAsync(db);
        await IncidentSchema.EnsureAsync(db);   // idempotente

        var old = await db.Detections.Include(d => d.Actions).SingleAsync();
        Assert.Equal("panel", old.Source);
        Assert.Null(old.IncidentId);
        Assert.Empty(old.Actions);
        db.ResponseActions.Add(new ResponseActionRecord { DetectionId = old.Id, At = T0, Actor = "x", Operation = "execute", Step = "BlockIp", Target = "10.0.0.1" });
        await db.SaveChangesAsync();
        Assert.Equal(1, await db.ResponseActions.CountAsync());
    }

    private sealed class FlakyExecutor : IResponseExecutor
    {
        public Task<ResponseOutcome> ExecuteAsync(ResponseAction a, CancellationToken ct = default) =>
            Task.FromResult(a.Step == ResponseStep.BlockIp ? ResponseOutcome.Fail("firewall indisponível") : ResponseOutcome.Done());
        public Task<ResponseOutcome> RevertAsync(ResponseAction a, CancellationToken ct = default) => Task.FromResult(ResponseOutcome.Done());
    }
}

/// <summary>Contrato de fio: o JSON que o agente produz precisa ser aceito pelo tipo que o painel desserializa.</summary>
public sealed class WireContractTests
{
    [Fact]
    public void Agent_batch_with_posture_and_incidents_round_trips_through_json()
    {
        var posture = new RansomGuard.Core.Score.PostureSnapshot { Server = "FS01", UnknownChecks = new HashSet<string> { "fsrm" } };
        var det = new Detection("FS01", "u", "10.0.0.1", "s", Confidence.High, new HashSet<DetectionReason> { DetectionReason.CanaryTouched }, 1, DateTime.UtcNow, DateTime.UtcNow);
        var inc = AgentIncident.From(det, ResponseDecision.None("x"), Array.Empty<AuditEntry>(), ResponseMode.Monitor);
        var agentSide = new RansomGuard.Agent.AgentBatch("FS01", DateTime.UtcNow, posture, Array.Empty<FileEvent>(), Array.Empty<HostSignal>(), new[] { inc });

        var json = System.Text.Json.JsonSerializer.Serialize(agentSide);
        var panelSide = System.Text.Json.JsonSerializer.Deserialize<AgentBatch>(json);

        Assert.NotNull(panelSide);
        Assert.Contains("fsrm", panelSide!.Posture!.UnknownChecks);
        Assert.Equal(inc.Id, panelSide.Incidents!.Single().Id);
    }
}

/// <summary>
/// O caminho que o agente real percorre: HTTP POST do JSON do lote no /api/ingest. Teria pego o bug do
/// IReadOnlySet antes do piloto. Usa o painel inteiro (WebApplicationFactory) com o banco padrão de Development.
/// </summary>
public sealed class IngestHttpContractTests : IClassFixture<IsolatedPanelFactory>
{
    private readonly IsolatedPanelFactory _factory;
    public IngestHttpContractTests(IsolatedPanelFactory factory) => _factory = factory;

    [Fact]
    public async Task Real_agent_batch_with_posture_and_incident_is_accepted_and_the_reply_carries_no_license_fields()
    {
        var posture = new RansomGuard.Core.Score.PostureSnapshot { Server = "FS-HTTP", UnknownChecks = new HashSet<string> { "fsrm" } };
        var det = new Detection("FS-HTTP", "u", "10.0.0.1", "s", Confidence.High, new HashSet<DetectionReason> { DetectionReason.CanaryTouched }, 1, DateTime.UtcNow, DateTime.UtcNow);
        var inc = AgentIncident.From(det, ResponseDecision.None("x"), Array.Empty<AuditEntry>(), ResponseMode.Monitor);
        var agentSide = new RansomGuard.Agent.AgentBatch("FS-HTTP", DateTime.UtcNow, posture, Array.Empty<FileEvent>(), Array.Empty<HostSignal>(), new[] { inc });

        var client = _factory.CreateAgentClient("FS-HTTP");   // B1: lote assinado por agente enrolado
        var resp = await client.PostAsJsonAsync("/api/ingest", agentSide);

        Assert.Equal(System.Net.HttpStatusCode.OK, resp.StatusCode);
        var raw = await resp.Content.ReadAsStringAsync();
        using var doc = System.Text.Json.JsonDocument.Parse(raw);
        var names = doc.RootElement.EnumerateObject().Select(p => p.Name).ToList();
        Assert.Equal(System.Text.Json.JsonValueKind.Number, doc.RootElement.GetProperty("score").ValueKind);   // postura chegou e foi pontuada
        Assert.DoesNotContain("licensedForResponse", names);   // produto gratuito: o painel não responde "pode conter"
        Assert.DoesNotContain("assertion", names);
        Assert.Contains("policy", names);
        Assert.Contains("commands", names);
    }
}

/// <summary>F35 — retenção: incidentes e postura antigos saem; o registro de postura mais recente de cada servidor fica.</summary>
public sealed class RetentionTests
{
    private static readonly DateTime T0 = new(2026, 10, 4, 15, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task Purge_removes_old_rows_but_keeps_latest_posture_per_server()
    {
        await using var conn = new SqliteConnection("DataSource=:memory:"); await conn.OpenAsync();
        await using var db = new RansomGuardDb(new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite(conn).Options);
        await db.Database.EnsureCreatedAsync();
        var srv = new ServerEntity { Name = "FS01", FirstSeen = T0.AddDays(-200), LastSeen = T0 };
        db.Servers.Add(srv);
        db.Detections.Add(new DetectionRecord { Server = srv, At = T0.AddDays(-100), User = "u", SourceIp = "i", Share = "s", Actions = { new ResponseActionRecord { At = T0.AddDays(-100), Actor = "a", Operation = "execute", Step = "BlockIp", Target = "10.0.0.1" } } });
        db.Detections.Add(new DetectionRecord { Server = srv, At = T0.AddDays(-10), User = "u", SourceIp = "i", Share = "s" });
        db.PostureRecords.Add(new PostureRecord { Server = srv, At = T0.AddDays(-60), Score = 50, FindingsJson = "[]", UnknownJson = "[]" });
        db.PostureRecords.Add(new PostureRecord { Server = srv, At = T0.AddDays(-40), Score = 60, FindingsJson = "[]", UnknownJson = "[]" });   // mais recente, mas antigo: fica
        await db.SaveChangesAsync();

        var (i, p) = await Retention.PurgeAsync(db, T0, incidentDays: 90, postureDays: 30);

        Assert.Equal(1, i); Assert.Equal(1, p);
        Assert.Equal(1, await db.Detections.CountAsync());
        Assert.Equal(0, await db.ResponseActions.CountAsync());                 // cascata
        Assert.Equal(60, (await db.PostureRecords.SingleAsync()).Score);
    }
}
