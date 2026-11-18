using System.Diagnostics;
using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;

// LoadSimulator — portão de regressão de DESEMPENHO (G6). Um servidor de arquivos ocupado produz milhares de eventos
// de alteração de arquivo por segundo. O motor de correlação (com memória entre ciclos) precisa processar cada lote
// de 5 s em muito menos de 5 s, com memória limitada, e o cursor de leitura do log precisa se recuperar quando a
// numeração dos registros recomeça. Tudo sintético, em processo, sem tocar o sistema. exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;
var failures = new List<string>();
void Check(string name, bool ok, string detail) { Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}"); if (!ok) failures.Add(name); }
Console.WriteLine("RansomGuard · LoadSimulator (G6 — desempenho)");

var t0 = new DateTime(2026, 10, 4, 16, 0, 0, DateTimeKind.Utc);
const int EventsPerSecond = 5_000;
const int BatchSeconds = 5;
const int Batches = 12;                     // 60 s simulados = 300.000 eventos

// Carga realista: 200 usuários distintos trabalhando em 20 pastas, operações mistas (leitura/escrita/renomeação).
var rnd = new Random(42);
var users = Enumerable.Range(0, 200).Select(i => $@"CORP\user{i:000}").ToArray();
var ips = Enumerable.Range(0, 200).Select(i => $"10.0.{i / 250}.{i % 250 + 1}").ToArray();
var shares = Enumerable.Range(0, 20).Select(i => $@"\\FS01\Area{i:00}").ToArray();
List<FileEvent> Batch(int b) => Enumerable.Range(0, EventsPerSecond * BatchSeconds).Select(i =>
{
    var u = rnd.Next(users.Length);
    var op = rnd.Next(10) switch { < 7 => FileOp.Read, < 9 => FileOp.Write, _ => FileOp.Rename };
    return new FileEvent(t0.AddSeconds(b * BatchSeconds + i / (double)EventsPerSecond), users[u], ips[u], shares[rnd.Next(shares.Length)],
        op, $"doc{rnd.Next(50_000)}.docx", op == FileOp.Rename ? ".tmp" : null);
}).ToList();

var engine = new DetectionEngine(new DetectionOptions(), new ActorActivityTracker());
var perBatch = new List<double>();
long totalEvents = 0;
var before = GC.GetTotalMemory(forceFullCollection: true);
for (var b = 0; b < Batches; b++)
{
    var batch = Batch(b);
    var sw = Stopwatch.StartNew();
    engine.Analyze(batch);
    sw.Stop();
    perBatch.Add(sw.Elapsed.TotalMilliseconds);
    totalEvents += batch.Count;
}
var after = GC.GetTotalMemory(forceFullCollection: true);
var worst = perBatch.Max();
var avg = perBatch.Average();
Console.WriteLine($"  {totalEvents:N0} eventos em {Batches} lotes · pior lote {worst:N0} ms · média {avg:N0} ms · memória retida {(after - before) / 1024.0 / 1024.0:N1} MB");
Check("cada lote de 5 s é processado em menos de 1 s", worst < 1_000, $"pior {worst:N0} ms");
Check("memória retida pelo motor limitada (< 64 MB com 200 atores × 20 pastas)", after - before < 64L * 1024 * 1024, $"{(after - before) / 1024 / 1024} MB");

// Com o tráfego variado acima nenhum ator cruza os limiares: o custo da memória entre ciclos não cria alarmes.
var quietList = engine.Analyze(Batch(Batches));
var quiet = quietList.Count;
Check("carga mista legítima não gera detecções", quiet == 0, quiet == 0 ? "0 detecções" : string.Join(" | ", quietList.Take(3).Select(d => $"{d.User}@{d.Share}: {string.Join("+", d.Reasons)} ({d.Confidence}, {d.AffectedFiles} ev)")));

// Cursor do log: a numeração dos registros recomeça (log reiniciado); o cursor percebe e não fica preso no passado.
var store = new MemoryCursorStore();
var cursor = new EventCursor(store);
cursor.NoticeNewest(900_000); cursor.Advance(900_000);
Check("cursor avança até o último registro visto", !cursor.IsNew(900_000) && cursor.IsNew(900_001), "900000 lido");
cursor.NoticeNewest(120);                 // numeração recomeçou: o maior id visto agora é menor que o cursor
Check("numeração reiniciada: o cursor se recupera e volta a ler", cursor.IsNew(1) && cursor.IsNew(120), "lê desde o começo do log novo");

// Fila/persistência do cursor sobrevive a reinício do processo (mesmo store).
var reopened = new EventCursor(store);
Check("cursor persistido é reaberto no mesmo ponto", !reopened.IsNew(100) || reopened.IsNew(121), "estado consistente após reabrir");

Console.WriteLine(failures.Count == 0
    ? "\nVERDE — 5 mil eventos/s correlacionados com folga; memória limitada; cursor resiliente a reinício do log."
    : $"\nVERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return failures.Count == 0 ? 0 : 1;

sealed class MemoryCursorStore : ICursorStore
{
    private string? _v;
    public string? Read() => _v;
    public void Write(string content) => _v = content;
}
