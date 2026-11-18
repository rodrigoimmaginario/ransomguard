using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Score;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Data;
using RansomGuard.Server.Ingestion;

// IngestSimulator — portão de regressão da Fatia 2. Exercita a camada REAL de ingestão do backend
// (IngestionService + EF/SQLite) ponta a ponta: um "agente" monta lotes (postura + ataque remoto
// via SMB + heartbeat), envia à ingestão, e verificamos que o score é persistido, o incidente é
// atribuído ao IP de origem, o alerta dispara e o heartbeat perdido vira tamper. exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;

var conn = new SqliteConnection("DataSource=:memory:");
conn.Open();
var options = new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite(conn).Options;
using var db = new RansomGuardDb(options);
db.Database.EnsureCreated();

var sink = new CollectingAlertSink();
var now = DateTime.UtcNow;
// B3: o painel carimba o batimento com o PRÓPRIO relógio; o simulador controla esse relógio para encenar o silêncio.
var panelNow = now.AddMinutes(-6);
var svc = new IngestionService(db, new AlertEngine(sink), clock: () => panelNow);

var failures = new List<string>();
void Check(string name, bool ok, string detail)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}");
    if (!ok) failures.Add(name);
}

Console.WriteLine("RansomGuard · IngestSimulator");
Console.WriteLine(new string('─', 60));

// Lote 1: postura ruim de FS01.
Console.WriteLine("\nLote 1 · Postura de FS01 (mal configurado)");
var r1 = await svc.IngestAsync(new AgentBatch("FS01", now.AddMinutes(-6),
    new PostureSnapshot
    {
        Server = "FS01",
        SmbV1Enabled = true, SmbSigningRequired = false, NtlmUnrestricted = true,
        SharesWritableByEveryone = true, VssEnabled = false, BackupServiceRunning = false,
        FsrmActive = false, ShareAuditingEnabled = false, CanariesPlanted = false,
        AgentInstalled = true, RdpExposed = true, OsEndOfLifeOrUnpatched = true
    },
    Array.Empty<FileEvent>(), Array.Empty<HostSignal>()));
Check("score-persistido", r1.Score is > 0 and < 40, $"score {r1.Score} (crítico)");

// Lote 2: ataque remoto via SMB + VSS deletado → incidente High + alerta.
Console.WriteLine("\nLote 2 · Ataque remoto via SMB em FS01");
var attack = Enumerable.Range(0, 120).Select(i =>
    new FileEvent(now.AddMinutes(-5).AddSeconds(i), @"CORP\vendas1", "10.0.9.66",
        @"\\FS01\Financeiro", FileOp.Rename, $"rel{i}.xlsx", ".locked")).ToList();
panelNow = now.AddMinutes(-5);
var r2 = await svc.IngestAsync(new AgentBatch("FS01", now.AddMinutes(-5), null, attack,
    new[] { new HostSignal(now.AddMinutes(-5), HostSignalKind.VssDeleted, "FS01") }));
Check("incidente-criado", r2.NewDetections == 1, $"{r2.NewDetections} detecção");
Check("alerta-disparado", r2.AlertsRaised == 1 && sink.Sent.Count == 1, "1 alerta enviado");

var det = await db.Detections.FirstAsync();
Check("atribuido-ao-ip", det.SourceIp == "10.0.9.66", $"origem {det.SourceIp}");
Check("confianca-alta", det.Confidence == Confidence.High, $"confiança {det.Confidence}");

// Lote 3: heartbeat de FS02 e depois silêncio → tamper.
Console.WriteLine("\nLote 3 · Heartbeat de FS02 e silêncio");
panelNow = now.AddMinutes(-30);
await svc.IngestAsync(AgentBatch.Heartbeat("FS02", now.AddMinutes(-30)));
var tamper = await svc.CheckHeartbeatsAsync(now, TimeSpan.FromMinutes(10));
Check("tamper-detectado", tamper == 1, "agente silencioso → alerta de tamper");

// Estado final agregado.
Console.WriteLine("\nEstado final do backend");
var servers = await db.Servers.CountAsync();
var incidents = await db.Detections.CountAsync();
Console.WriteLine($"  Servidores: {servers} · Incidentes: {incidents} · Alertas: {sink.Sent.Count}");
Check("estado-consistente", servers == 2 && incidents == 1, $"{servers} servidores, {incidents} incidente");

Console.WriteLine("\n" + new string('─', 60));
if (failures.Count == 0) { Console.WriteLine("VERDE — ingestão ponta a ponta validada."); return 0; }
Console.WriteLine($"VERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return 1;
