using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RansomGuard.Agent;
using RansomGuard.Agent.Auth;
using RansomGuard.Core.Auth;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Policy;
using RansomGuard.Core.Response;
using RansomGuard.Core.Score;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Auth;
using RansomGuard.Server.Data;
using RansomGuard.Server.Ingestion;
using RansomGuard.Server.Policy;
using System.Text.Json;
using AgentSideBatch = RansomGuard.Agent.AgentBatch;
using PanelSideBatch = RansomGuard.Server.Ingestion.AgentBatch;

// PolicyRolloutSimulator — portão de regressão da F33, ponta a ponta com o painel real em processo:
// o operador salva a política no painel → o lote seguinte leva a política assinada → o agente (em Monitor
// pelo registro) passa a Block com allowlist; um "painel" falso e um rollback são ignorados; o operador pede
// Desfazer → comando assinado → agente reverte uma vez → painel fecha a ação. exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;
var failures = new List<string>();
void Check(string name, bool ok, string detail) { Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}"); if (!ok) failures.Add(name); }
Console.WriteLine("RansomGuard · PolicyRolloutSimulator (F33)");

var t0 = new DateTime(2026, 10, 4, 9, 0, 0, DateTimeKind.Utc);
var dir = Path.Combine(Path.GetTempPath(), "rg-policy-sim-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
var conn = new SqliteConnection("DataSource=:memory:"); conn.Open();
using var db = new RansomGuardDb(new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite(conn).Options);
db.Database.EnsureCreated(); await AgentPolicyService.EnsureSchemaAsync(db);
var keys = new FileInstallKeyStore(Path.Combine(dir, "install-key.json"));
var policies = new AgentPolicyService(db, keys);
var ingest = new IngestionService(db, new AlertEngine(new NullSink()), policies: policies);

// Agente: confia na chave real do painel (TOFU). Sem licença: o modo vem da política.
var trust = new PanelTrust(new InMemoryPanelKeyStore());
trust.TryPin((await keys.GetOrCreateAsync()).PublicKeyFileContent);
var exec = new RecordingExecutor();
var sink = new PanelSink(ingest);
var cycle = new AgentCycle("FS01", new Posture(), new Events(), new NoSignals(), sink, new ResponseLadder(),
    new ResponsePolicy { Mode = ResponseMode.Monitor }, exec, trust: trust);

// 1. Sem política no painel: agente fica no registro (Monitor).
await cycle.RunOnceAsync(t0);
Check("sem política publicada, agente mantém o registro", cycle.Policy.Mode == ResponseMode.Monitor && cycle.LastPolicyOutcome is null, "Monitor");

// 2. Operador salva política padrão Block + allowlist do backup.
await policies.SaveAsync(new AgentPolicyEntity { Server = "*", Mode = "Block", MaxStep = "DenyUserOnShare", AllowlistedUsers = @"CORP\svc-backup" }, t0);
await cycle.RunOnceAsync(t0.AddSeconds(5));
Check("política assinada aplicada no lote seguinte", cycle.LastPolicyOutcome == PolicyOutcome.Valid && cycle.Policy.Mode == ResponseMode.Block && cycle.Policy.AllowlistedUsers.Contains(@"CORP\svc-backup"),
    $"{cycle.LastPolicyOutcome} → {cycle.Policy.Mode}, allowlist {cycle.Policy.AllowlistedUsers.Count}");

// 3. Política específica do servidor vence a padrão.
await policies.SaveAsync(new AgentPolicyEntity { Server = "FS01", Mode = "Alert" }, t0.AddSeconds(6));
await cycle.RunOnceAsync(t0.AddSeconds(10));
Check("política específica do servidor vence a padrão", cycle.Policy.Mode == ResponseMode.Alert, $"{cycle.Policy.Mode}");

// 4. Painel falso tenta publicar Block com DisableAdAccount: ignorado.
var evilSeed = Enumerable.Range(99, 32).Select(i => (byte)i).ToArray();
var evilKeyId = new byte[] { 9, 9, 9, 9, 9, 9, 9, 9 };
var forged = AgentPolicyDocument.Sign(new AgentPolicyDocument("*", 999, "Block", "DisableAdAccount", Array.Empty<string>(), Array.Empty<string>(), false, t0), evilSeed, evilKeyId);
var evilCycle = new AgentCycle("FS01", new Posture(), new Events(), new NoSignals(), new FixedSink(new BatchResponse(Policy: forged)),
    new ResponseLadder(), cycle.Policy, exec, trust: trust);
await evilCycle.RunOnceAsync(t0.AddSeconds(15));
Check("política forjada é ignorada", evilCycle.LastPolicyOutcome == PolicyOutcome.InvalidSignature && evilCycle.Policy.Mode == ResponseMode.Alert, $"{evilCycle.LastPolicyOutcome}");

// 5. Rollback: um proxy reapresenta a versão 1 (Block padrão) depois da 2 (Alert): ignorado.
var key = await keys.GetOrCreateAsync();
var old = AgentPolicyDocument.Sign(new AgentPolicyDocument("*", 1, "Block", "IsolateShare", Array.Empty<string>(), Array.Empty<string>(), false, t0), key.Seed, key.KeyId);
var replay = new AgentCycle("FS01", new Posture(), new Events(), new NoSignals(), new FixedSink(new BatchResponse(Policy: old)),
    new ResponseLadder(), cycle.Policy, exec, trust: trust);
await replay.RunOnceAsync(t0.AddSeconds(20));
Check("rollback de versão é ignorado", replay.LastPolicyOutcome == PolicyOutcome.Rollback && replay.Policy.Mode == ResponseMode.Alert, $"{replay.LastPolicyOutcome}");

// 6. Reversão: ação executada num incidente → operador pede Desfazer → comando assinado → agente reverte → painel fecha.
var srv = await db.Servers.SingleAsync(s => s.Name == "FS01");
var det = new DetectionRecord { Server = srv, At = t0, User = @"CORP\ana", SourceIp = "10.0.9.66", Share = @"\\FS01\Fin", Confidence = Confidence.High, Source = "agent", IncidentId = "sim-1" };
var action = new ResponseActionRecord { Detection = det, At = t0, Actor = "RansomGuard", Operation = "execute", Step = "DenyUserOnShare", Target = @"\\FS01\Fin", Account = @"CORP\ana", Justification = "r", RevertRequestedAt = t0.AddSeconds(25) };
db.ResponseActions.Add(action); await db.SaveChangesAsync();

await cycle.RunOnceAsync(t0.AddSeconds(30));   // recebe o comando e reverte
await cycle.RunOnceAsync(t0.AddSeconds(35));   // devolve o resultado
var reverted = exec.Reverted.SingleOrDefault();
var closed = await db.ResponseActions.SingleAsync(a => a.Id == action.Id);
Check("Desfazer no painel vira reversão no agente, uma vez", reverted is not null && reverted.Step == ResponseStep.DenyUserOnShare && reverted.Account == @"CORP\ana" && exec.Reverted.Count == 1,
    $"{exec.Reverted.Count} reversão(ões)");
Check("painel fecha a ação com o resultado do agente", closed.RevertStatus == "Executed" && closed.RevertedAt is not null, $"{closed.RevertStatus} em {closed.RevertedAt:HH:mm:ss}");
await cycle.RunOnceAsync(t0.AddSeconds(40));
Check("comando fechado não é reenviado nem reexecutado", exec.Reverted.Count == 1 && cycle.LastCommandsOutcome == PolicyOutcome.Valid, "idempotente");

// 7. G4b — blocklist de rede: FS01 contém um ataque remoto; FS02 (outro agente, política própria) passa a bloquear o IP.
var fs02exec = new RecordingExecutor();
var fs02 = new AgentCycle("FS02", new Posture(), new Events(), new NoSignals(), new PanelSink(ingest), new ResponseLadder(),
    new ResponsePolicy(), fs02exec, trust: trust);
await fs02.RunOnceAsync(t0.AddSeconds(45));
Check("antes do incidente, FS02 não bloqueia nada", fs02.AppliedBlocklist.Count == 0, "blocklist vazia");

var attackDet = new Detection("FS01", @"CORP\vitima", "10.0.9.66", @"\\FS01\Fin", Confidence.High, new HashSet<DetectionReason> { DetectionReason.CanaryTouched }, 90, t0.AddSeconds(50), t0.AddSeconds(55));
var attackDecision = new ResponseLadder().Decide(attackDet, new ResponsePolicy { Mode = ResponseMode.Block });
var attackRunner = new ResponseRunner(new RecordingExecutor()); await attackRunner.RunAsync(attackDecision, t0.AddSeconds(56));
var contained = RansomGuard.Core.Incidents.AgentIncident.From(attackDet, attackDecision, attackRunner.Audit, ResponseMode.Block);
await ingest.IngestAsync(new PanelSideBatch("FS01", t0.AddSeconds(57), null, Array.Empty<FileEvent>(), Array.Empty<HostSignal>(), new[] { contained }));

await fs02.RunOnceAsync(t0.AddSeconds(60));
Check("FS01 conteve → FS02 bloqueia o IP no próximo lote (política assinada)", fs02.AppliedBlocklist.Contains("10.0.9.66") && fs02exec.Executed.Any(a => a.Step == ResponseStep.BlockIp && a.Target == "10.0.9.66"), $"blocklist FS02 = [{string.Join(",", fs02.AppliedBlocklist)}]");
Check("política específica de FS01 (Alert) continua intacta", cycle.Policy.Mode == ResponseMode.Alert, $"{cycle.Policy.Mode}");

await policies.RemoveFromNetworkBlocklistAsync("10.0.9.66", t0.AddSeconds(65));
await fs02.RunOnceAsync(t0.AddSeconds(70));
Check("operador libera no painel → FS02 remove a regra", fs02.AppliedBlocklist.Count == 0 && fs02exec.Reverted.Any(a => a.Target == "10.0.9.66"), "revertido");

Directory.Delete(dir, true);
Console.WriteLine(failures.Count == 0
    ? "\nVERDE — política e reversões saem do painel assinadas; o agente obedece só ao painel legítimo e nunca regride."
    : $"\nVERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return failures.Count == 0 ? 0 : 1;

sealed class Posture : IPostureCollector { public PostureSnapshot Collect(string s) => new() { Server = s }; }
sealed class Events : IFileEventCollector { public IReadOnlyList<FileEvent> Drain() => Array.Empty<FileEvent>(); }
sealed class NoSignals : IHostSignalCollector { public IReadOnlyList<HostSignal> Drain() => Array.Empty<HostSignal>(); }
sealed class NullSink : IAlertSink { public Task SendAsync(string s, string b, CancellationToken ct = default) => Task.CompletedTask; }
sealed class FixedSink(BatchResponse reply) : IBatchSink { public Task<BatchResponse?> SendAsync(AgentSideBatch b, CancellationToken ct = default) => Task.FromResult<BatchResponse?>(reply); }
/// <summary>Atravessa a fronteira como o HTTP: JSON do agente → painel real em processo → JSON de volta.</summary>
sealed class PanelSink(IngestionService ingest) : IBatchSink
{
    public async Task<BatchResponse?> SendAsync(AgentSideBatch b, CancellationToken ct = default)
    {
        var wire = JsonSerializer.Deserialize<PanelSideBatch>(JsonSerializer.Serialize(b))!;
        var r = await ingest.IngestAsync(wire, ct);
        var back = JsonSerializer.Deserialize<Reply>(JsonSerializer.Serialize(r))!;
        return new BatchResponse(back.Policy, back.Commands);
    }
    private sealed record Reply(bool LicensedForResponse, SignedAssertion? Assertion, SignedAssertion? Policy, SignedAssertion? Commands);
}
