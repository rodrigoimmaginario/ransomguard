using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RansomGuard.Agent;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;
using RansomGuard.Core.Score;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Data;
using RansomGuard.Server.Ingestion;
using AgentSideBatch = RansomGuard.Agent.AgentBatch;
using PanelSideBatch = RansomGuard.Server.Ingestion.AgentBatch;
using System.Text.Json;

// IncidentTrailSimulator — portão de regressão da F32 (verdade única do incidente), ponta a ponta:
// ataque de ensaio → AgentCycle detecta, decide e executa (um degrau falha) → lote vai ao painel →
// IngestionService persiste a trilha (idempotente) → o painel mostra exatamente o que o agente fez.
// exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;
var failures = new List<string>();
void Check(string name, bool ok, string detail)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}");
    if (!ok) failures.Add(name);
}
Console.WriteLine("RansomGuard · IncidentTrailSimulator (F32)");

var t0 = new DateTime(2026, 10, 3, 12, 0, 0, DateTimeKind.Utc);
var attack = Enumerable.Range(0, 80).Select(i => new FileEvent(t0.AddSeconds(i), @"CORP\vendas1", "10.0.9.66", @"\\FS01\Financeiro",
    FileOp.Rename, $"planilha{i}.xlsx", ".locked", IsCanary: i == 5)).ToList();

// Agente em Block, licenciado, executor em que o firewall falha (cenário real: regra recusada).
var sink = new CapturingSink();
var cycle = new AgentCycle("FS01", new Posture(), new Events(attack), new NoSignals(), sink,
    new ResponseLadder(), new ResponsePolicy { Mode = ResponseMode.Block, MaxStep = ResponseStep.DisableAdAccount },
    new FlakyExecutor());
var result = await cycle.RunOnceAsync(t0.AddMinutes(1));
var agentBatch = sink.Last!;
var inc = agentBatch.Incidents!.Single();

// Atravessa a fronteira como o HTTP: JSON do agente → contrato do painel (prova de compatibilidade do lote).
var wire = JsonSerializer.Serialize(agentBatch);
var batch = JsonSerializer.Deserialize<PanelSideBatch>(wire)!;
Check("contrato do lote atravessa o JSON sem perder a trilha", batch.Incidents?.Count == 1 && batch.Incidents[0].Report.Actions.Count == 5 && batch.Incidents[0].Id == inc.Id, $"{wire.Length} bytes");

Check("agente detectou e conteve", result.Detections == 1 && result.LocalContainments == 3, $"detecções={result.Detections} contenções reais={result.LocalContainments} (snapshot não conta)");
Check("lote leva a trilha (IP falha, sessão, usuário no share, conta, snapshot)", inc.Report.Actions.Select(a => a.Operation).SequenceEqual(new[] { "fail", "execute", "execute", "execute", "execute" }),
    string.Join(" → ", inc.Report.Actions.Select(a => $"{a.Step}:{a.Operation}")));

// Painel
var conn = new SqliteConnection("DataSource=:memory:"); conn.Open();
using var db = new RansomGuardDb(new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite(conn).Options);
db.Database.EnsureCreated();
var alerts = new List<string>();
var svc = new IngestionService(db, new AlertEngine(new ListSink(alerts)));

var r1 = await svc.IngestAsync(batch);
var rec = await db.Detections.Include(d => d.Actions).SingleAsync();
Check("painel persistiu o incidente do agente", r1.NewDetections == 1 && rec.Source == "agent" && rec.IncidentId == inc.Id && rec.Contained, $"id={rec.IncidentId} source={rec.Source}");
Check("trilha no painel = trilha do agente", rec.Actions.Count == 5 && rec.Actions.Count(a => a.Operation == "fail") == 1
    && rec.Actions.Single(a => a.Operation == "fail").Step == "BlockIp", $"{rec.Actions.Count} ações; falha em {rec.Actions.FirstOrDefault(a => a.Operation == "fail")?.Step}");
Check("alerta disparado uma vez", alerts.Count == 1 && rec.Alerted, $"alertas={alerts.Count}");

// Reenvio (agente retentou o mesmo lote): nada duplica.
var r2 = await svc.IngestAsync(batch);
Check("reenvio do mesmo incidente é idempotente", r2.NewDetections == 0 && await db.Detections.CountAsync() == 1 && await db.ResponseActions.CountAsync() == 5 && alerts.Count == 1, "1 incidente, 5 ações, 1 alerta");

// Painel NÃO re-analisa quando o agente manda a verdade (ex.: agente em allowlist diz "nenhum incidente").
var quiet = new PanelSideBatch("FS01", t0.AddMinutes(2), null, attack, Array.Empty<HostSignal>(), Array.Empty<RansomGuard.Core.Incidents.AgentIncident>());
var r3 = await svc.IngestAsync(quiet);
Check("painel não inventa incidente quando o agente diz que não houve", r3.NewDetections == 0 && await db.Detections.CountAsync() == 1, "sem re-análise");

// Agente antigo (sem lista): fallback marcado como 'panel'.
var legacy = new PanelSideBatch("FS02", t0.AddMinutes(3), null, attack.Select(e => e with { Share = @"\\FS02\Dados" }).ToList(), Array.Empty<HostSignal>());
var r4 = await svc.IngestAsync(legacy);
var legacyRec = await db.Detections.Where(d => d.Share == @"\\FS02\Dados").SingleAsync();
Check("agente antigo ainda gera incidente, marcado como derivado pelo painel", r4.NewDetections == 1 && legacyRec.Source == "panel" && legacyRec.IncidentId is null, $"source={legacyRec.Source}");

// Operador pede reversão: fica registrado para o agente executar (F33 entrega o comando).
var executed = rec.Actions.First(a => a.Operation == "execute");
executed.RevertRequestedAt = t0.AddMinutes(5);
await db.SaveChangesAsync();
var pending = await db.ResponseActions.CountAsync(a => a.RevertRequestedAt != null && a.RevertedAt == null);
Check("pedido de reversão fica pendente para o agente", pending == 1, $"pendentes={pending}");

Console.WriteLine(failures.Count == 0
    ? "\nVERDE — o painel mostra exatamente o que o agente detectou, decidiu e executou; sem duplicar, sem inventar."
    : $"\nVERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return failures.Count == 0 ? 0 : 1;

sealed class Posture : IPostureCollector { public PostureSnapshot Collect(string s) => new() { Server = s }; }
sealed class Events(IReadOnlyList<FileEvent> e) : IFileEventCollector { private IReadOnlyList<FileEvent> _e = e; public IReadOnlyList<FileEvent> Drain() { var r = _e; _e = Array.Empty<FileEvent>(); return r; } }
sealed class NoSignals : IHostSignalCollector { public IReadOnlyList<HostSignal> Drain() => Array.Empty<HostSignal>(); }
sealed class CapturingSink : IBatchSink
{
    public AgentSideBatch? Last;
    public Task<BatchResponse?> SendAsync(AgentSideBatch b, CancellationToken ct = default) { Last = b; return Task.FromResult<BatchResponse?>(null); }
}
sealed class FlakyExecutor : IResponseExecutor
{
    public Task<ResponseOutcome> ExecuteAsync(ResponseAction a, CancellationToken ct = default) =>
        Task.FromResult(a.Step == ResponseStep.BlockIp ? ResponseOutcome.Fail("New-NetFirewallRule recusado (política de grupo)") : ResponseOutcome.Done());
    public Task<ResponseOutcome> RevertAsync(ResponseAction a, CancellationToken ct = default) => Task.FromResult(ResponseOutcome.Done());
}
sealed class ListSink(List<string> sent) : IAlertSink
{
    public Task SendAsync(string subject, string body, CancellationToken ct = default) { sent.Add(subject); return Task.CompletedTask; }
}
