using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RansomGuard.Agent;
using RansomGuard.Agent.Queue;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;
using RansomGuard.Core.Score;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Data;
using RansomGuard.Server.Ingestion;
using System.Text.Json;
using AgentSideBatch = RansomGuard.Agent.AgentBatch;
using PanelSideBatch = RansomGuard.Server.Ingestion.AgentBatch;

// OutageSimulator — portão de regressão da F34 (fila durável) + G5 (forense) + F35 (retenção), com o painel real em
// processo. O painel cai no meio de um ataque, fica fora por vários ciclos e volta: todos os lotes chegam, em ordem,
// sem duplicar incidentes; a lista de arquivos afetados está no painel; a retenção limpa o que é velho. exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;
var failures = new List<string>();
void Check(string name, bool ok, string detail) { Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}"); if (!ok) failures.Add(name); }
Console.WriteLine("RansomGuard · OutageSimulator (F34/G5/F35)");

var t0 = new DateTime(2026, 10, 4, 15, 0, 0, DateTimeKind.Utc);
var conn = new SqliteConnection("DataSource=:memory:"); conn.Open();
using var db = new RansomGuardDb(new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite(conn).Options);
db.Database.EnsureCreated();
var ingest = new IngestionService(db, new AlertEngine(new NullSink()));
var panel = new FlakyPanel(ingest);

var feed = new Feed();
var queue = new InMemoryBatchQueue();
var cycle = new AgentCycle("FS01", new Posture(), feed, new NoSignals(), panel, new ResponseLadder(),
    new ResponsePolicy { Mode = ResponseMode.Block }, new RecordingExecutor(), queue: queue);

FileEvent[] Attack(int wave) => Enumerable.Range(0, 60).Select(i =>
    new FileEvent(t0.AddSeconds(wave * 5 + i * 0.05), @"CORP\vitima", "10.0.9.66", @"\\FS01\Fin", FileOp.Rename, $"w{wave}\\f{i}.xlsx", ".locked", IsCanary: i == 1)).ToArray();

// Ciclo 0: painel de pé, ataque começa → incidente entregue.
feed.Next(Attack(0)); await cycle.RunOnceAsync(t0, collectPosture: false);
Check("incidente da 1ª onda entregue", await db.Detections.CountAsync() == 1 && panel.Delivered == 1, $"{panel.Delivered} lote(s)");

// Ciclos 1–4: painel CAI; o ataque continua (4 ondas); nada chega, tudo fica na fila.
panel.Down = true;
for (var w = 1; w <= 4; w++) { feed.Next(Attack(w)); await cycle.RunOnceAsync(t0.AddSeconds(w * 5), collectPosture: false); }
Check("painel fora: 4 lotes na fila, nenhum perdido", cycle.QueuedBatches == 4 && cycle.DroppedBatches == 0 && panel.Delivered == 1, $"fila={cycle.QueuedBatches}");

// Sessão 5 do laboratório: depois de uma falha o agente não toca a rede até passar a espera (15 s, dobrando até 2 min),
// para que um painel que não responde não prenda o ciclo de detecção. Falhou aos 5 s e aos 20 s: a próxima tentativa é aos 50 s.
panel.Down = false;
feed.Next(); await cycle.RunOnceAsync(t0.AddSeconds(25), collectPosture: false);
Check("painel voltou, mas o agente ainda está na espera: não tenta a rede", panel.Delivered == 1 && cycle.QueuedBatches == 4, $"entregues={panel.Delivered}");

// Ciclo 5: passada a espera, a 5ª onda chega junto com a fila, em ordem.
feed.Next(Attack(5)); await cycle.RunOnceAsync(t0.AddSeconds(50), collectPosture: false);
Check("painel voltou: fila drenada em ordem + lote atual", cycle.QueuedBatches == 0 && panel.Delivered == 6
    && panel.Order.SequenceEqual(new[] { 0, 5, 10, 15, 20, 50 }.Select(s => t0.AddSeconds(s))), $"entregues={panel.Delivered} ordem={string.Join(",", panel.Order.Select(a => (a - t0).TotalSeconds))}");
// L3 (laboratório): as seis ondas são do mesmo ator, em ciclos seguidos — UM incidente, que acumula as seis.
var merged = await db.Detections.SingleAsync();
Check("6 ondas do mesmo ataque = 1 incidente com as 6 somadas", merged.AffectedFiles == 360, $"{await db.Detections.CountAsync()} incidente, {merged.AffectedFiles} arquivos");

// Reentrega do mesmo lote (ex.: painel respondeu mas o agente não recebeu): idempotente.
await panel.SendAsync(panel.Last!);
await db.Entry(merged).ReloadAsync();
Check("reentrega acidental do mesmo lote não duplica nem soma de novo", await db.Detections.CountAsync() == 1 && merged.AffectedFiles == 360, "idempotente por IncidentId e instante");

// G5 — forense: a lista de arquivos afetados de cada incidente está no painel.
var first = await db.Detections.OrderBy(d => d.Id).FirstAsync();
var paths = JsonSerializer.Deserialize<string[]>(first.AffectedPathsJson ?? "[]")!;
Check("lista de arquivos afetados das seis ondas persistida (restore)", paths.Length == 360 && Enumerable.Range(0, 6).All(w => paths.Any(p => p.StartsWith($"w{w}\\"))), $"{paths.Length} caminhos");

// F35 — retenção: incidentes com mais de 90 dias somem; os recentes ficam.
db.Detections.Add(new DetectionRecord { ServerId = first.ServerId, At = t0, User = @"CORP\outro", SourceIp = "10.0.0.9", Share = "s", Confidence = first.Confidence, Reasons = "MassRewrite", IncidentId = "recente", Source = "agent" });
first.At = t0.AddDays(-120);
await db.SaveChangesAsync();
var (purgedI, _) = await Retention.PurgeAsync(db, t0.AddDays(1), incidentDays: 90, postureDays: 30);
Check("retenção remove só o que é velho", purgedI == 1 && await db.Detections.CountAsync() == 1, $"{purgedI} removido, {await db.Detections.CountAsync()} ficou");

// Teto da fila: painel fora por muito tempo descarta o mais ANTIGO, nunca o mais novo.
var q = new InMemoryBatchQueue();
for (var i = 0; i < 2_010; i++) q.Enqueue(new AgentSideBatch("FS01", t0.AddSeconds(i), null, new[] { new FileEvent(t0, "u", "1.1.1.1", "s", FileOp.Write, $"p{i}") }, Array.Empty<HostSignal>()));
var dropped = q.Prune(t0.AddHours(3), BatchQueuePolicy.MaxQueuedBatches, BatchQueuePolicy.MaxAge);
Check("teto da fila descarta os mais antigos", dropped == 10 && q.Peek(1)[0].Events[0].Path == "p10", $"{dropped} descartados; primeiro restante p10");

Console.WriteLine(failures.Count == 0
    ? "\nVERDE — painel fora do ar não perde nem duplica nada; o restore tem a lista; o banco não cresce para sempre."
    : $"\nVERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return failures.Count == 0 ? 0 : 1;

sealed class Posture : IPostureCollector { public PostureSnapshot Collect(string s) => new() { Server = s }; }
sealed class Feed : IFileEventCollector
{
    private readonly Queue<IReadOnlyList<FileEvent>> _q = new();
    public void Next(params FileEvent[] e) => _q.Enqueue(e);
    public IReadOnlyList<FileEvent> Drain() => _q.Count > 0 ? _q.Dequeue() : Array.Empty<FileEvent>();
}
sealed class NoSignals : IHostSignalCollector { public IReadOnlyList<HostSignal> Drain() => Array.Empty<HostSignal>(); }
sealed class NullSink : IAlertSink { public Task SendAsync(string s, string b, CancellationToken ct = default) => Task.CompletedTask; }
/// <summary>Painel real em processo que pode "cair" (sem resposta), atravessando a fronteira como o HTTP.</summary>
sealed class FlakyPanel(IngestionService ingest) : IBatchSink
{
    public bool Down;
    public int Delivered;
    public readonly List<DateTime> Order = new();
    public AgentSideBatch? Last;
    public async Task<BatchResponse?> SendAsync(AgentSideBatch b, CancellationToken ct = default)
    {
        if (Down) return null;
        var wire = JsonSerializer.Deserialize<PanelSideBatch>(JsonSerializer.Serialize(b))!;
        var r = await ingest.IngestAsync(wire, ct);
        Delivered++; Order.Add(b.At); Last = b;
        return new BatchResponse(r.Policy, r.Commands);
    }
}
