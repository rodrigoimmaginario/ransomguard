using RansomGuard.Agent;
using RansomGuard.Agent.Auth;
using RansomGuard.Core.Auth;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Policy;
using RansomGuard.Core.Response;
using RansomGuard.Core.Score;
using RansomGuard.Core.Signing;

// SpoofedPanelSimulator — portão de regressão da F38. Um "painel" posicionado na rede tenta mudar o
// comportamento do agente respondendo aos lotes. O produto é gratuito: não há licença para forjar. O que o
// painel pode mudar é a POLÍTICA (modo, teto, allowlist), e só com a assinatura da chave da instalação
// fixada no agente. Um painel falso não liga nem desliga a contenção. exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;
var failures = new List<string>();
void Check(string name, bool ok, string detail)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}");
    if (!ok) failures.Add(name);
}

var t0 = new DateTime(2026, 10, 3, 12, 0, 0, DateTimeKind.Utc);
var keyId = new byte[] { 7, 7, 7, 7, 7, 7, 7, 7 };
var panelSeed = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
var spoofSeed = Enumerable.Range(101, 32).Select(i => (byte)i).ToArray();
string Pub(byte[] seed) => MinisignPublicKey.FromRaw(keyId, Minisign.PublicKeyFromSeed(seed)).ToFileContent("sim");
SignedAssertion Policy(long version, string mode, byte[] seed, string server = "*", DateTime? issued = null) =>
    AgentPolicyDocument.Sign(new AgentPolicyDocument(server, version, mode, "DenyUserOnShare",
        Array.Empty<string>(), Array.Empty<string>(), false, issued ?? t0), seed, keyId);

var trust = new PanelTrust(new InMemoryPanelKeyStore());
Console.WriteLine("RansomGuard · SpoofedPanelSimulator (F38)");

// Cenário 0 — primeiro contato: o painel LEGÍTIMO publica a chave; o agente fixa (TOFU).
Check("TOFU fixa a chave do painel legítimo", trust.TryPin(Pub(panelSeed)) && trust.HasKey, $"keyId {trust.KeyIdHex}");
Check("painel falso não consegue trocar a chave fixada", !trust.TryPin(Pub(spoofSeed)), "chave diferente recusada");

// Um agente só, em Monitor, sofrendo um toque em canário a cada ciclo. O que muda é a resposta do "painel".
var sink = new Sink();
var exec = new CountingExecutor();
var cycle = new AgentCycle("FS01", new Posture(), new CanaryHit(t0), new NoSignals(), sink,
    new ResponseLadder(), new ResponsePolicy { Mode = ResponseMode.Monitor }, exec, trust: trust);

async Task<(PolicyOutcome? Outcome, int Contained)> Round(BatchResponse? reply, DateTime now)
{
    sink.Reply = reply;
    await cycle.RunOnceAsync(now);                       // recebe a resposta
    exec.Executed = 0;
    await cycle.RunOnceAsync(now.AddSeconds(5));         // age (ou não) com a política resultante
    return (cycle.LastPolicyOutcome, exec.Executed);
}

// Cenário 1 — resposta sem política nenhuma (o ataque de antes da F38 era um booleano em claro; hoje nem existe).
var r1 = await Round(new BatchResponse(), t0);
Check("resposta sem política não liga a contenção", cycle.Policy.Mode == ResponseMode.Monitor && r1.Contained == 0, "segue em Monitor");

// Cenário 2 — painel falso assina "Block" com a própria chave.
var r2 = await Round(new BatchResponse(Policy: Policy(1, "Block", spoofSeed)), t0.AddMinutes(1));
Check("política de chave estranha é recusada", r2.Outcome == PolicyOutcome.InvalidSignature && cycle.Policy.Mode == ResponseMode.Monitor && r2.Contained == 0, $"{r2.Outcome}");

// Cenário 3 — painel legítimo liga a contenção.
var r3 = await Round(new BatchResponse(Policy: Policy(2, "Block", panelSeed)), t0.AddMinutes(2));
Check("painel legítimo liga a contenção", r3.Outcome == PolicyOutcome.Valid && cycle.Policy.Mode == ResponseMode.Block && r3.Contained > 0, $"{r3.Outcome}, {r3.Contained} ação(ões)");

// Cenário 4 — painel falso tenta DESLIGAR (cegar a contenção antes de cifrar).
var r4 = await Round(new BatchResponse(Policy: Policy(3, "Monitor", spoofSeed)), t0.AddMinutes(3));
Check("painel falso não desliga a contenção", r4.Outcome == PolicyOutcome.InvalidSignature && cycle.Policy.Mode == ResponseMode.Block && r4.Contained > 0, $"{r4.Outcome}");

// Cenário 5 — atacante reapresenta uma política ANTIGA e legítima (versão menor) que desligava.
var oldOff = Policy(1, "Monitor", panelSeed);
var r5 = await Round(new BatchResponse(Policy: oldOff), t0.AddMinutes(4));
Check("replay de política antiga é ignorado", r5.Outcome == PolicyOutcome.Rollback && cycle.Policy.Mode == ResponseMode.Block, $"{r5.Outcome}");

// Cenário 6 — política legítima emitida para OUTRO servidor (reaproveitada contra FS01).
var r6 = await Round(new BatchResponse(Policy: Policy(9, "Monitor", panelSeed, server: "FS02")), t0.AddMinutes(5));
Check("política de outro servidor é ignorada", r6.Outcome == PolicyOutcome.WrongServer && cycle.Policy.Mode == ResponseMode.Block, $"{r6.Outcome}");

// Cenário 7 — política com data de emissão no futuro (relógio do "painel" adulterado).
var r7 = await Round(new BatchResponse(Policy: Policy(10, "Monitor", panelSeed, issued: t0.AddHours(6))), t0.AddMinutes(6));
Check("política emitida no futuro é ignorada", r7.Outcome == PolicyOutcome.NotYetValid && cycle.Policy.Mode == ResponseMode.Block, $"{r7.Outcome}");

// Cenário 8 — sem contato (painel fora): a política vigente continua valendo.
var r8 = await Round(null, t0.AddMinutes(7));
Check("sem contato mantém a política vigente", cycle.Policy.Mode == ResponseMode.Block && r8.Contained > 0, "fail-safe: segue contendo");

// Cenário 9 — o painel legítimo é quem desliga.
var r9 = await Round(new BatchResponse(Policy: Policy(11, "Monitor", panelSeed)), t0.AddMinutes(8));
Check("painel legítimo desliga a contenção", r9.Outcome == PolicyOutcome.Valid && cycle.Policy.Mode == ResponseMode.Monitor && r9.Contained == 0, $"{r9.Outcome}");

Console.WriteLine(failures.Count == 0
    ? "\nVERDE — painel falso não liga nem desliga a contenção; só o painel legítimo, sem replay."
    : $"\nVERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return failures.Count == 0 ? 0 : 1;

sealed class Posture : IPostureCollector { public PostureSnapshot Collect(string s) => new() { Server = s }; }
sealed class CanaryHit(DateTime at) : IFileEventCollector
{
    public IReadOnlyList<FileEvent> Drain() => new[]
    {
        new FileEvent(at, @"CORP\vendas1", "10.0.9.66", @"\\FS01\Financeiro", FileOp.Write, "!0__ransomguard_canary.docx", ".docx", IsCanary: true)
    };
}
sealed class NoSignals : IHostSignalCollector { public IReadOnlyList<HostSignal> Drain() => Array.Empty<HostSignal>(); }
sealed class CountingExecutor : IResponseExecutor
{
    public int Executed;
    public Task<ResponseOutcome> ExecuteAsync(ResponseAction a, CancellationToken ct = default) { Executed++; return Task.FromResult(ResponseOutcome.Done()); }
    public Task<ResponseOutcome> RevertAsync(ResponseAction a, CancellationToken ct = default) => Task.FromResult(ResponseOutcome.Done());
}
sealed class Sink : IBatchSink
{
    public BatchResponse? Reply;
    public Task<BatchResponse?> SendAsync(AgentBatch b, CancellationToken ct = default) => Task.FromResult(Reply);
}
