using System.Text;
using RansomGuard.Core.Signing;
using RansomGuard.Core.Updates;

// UpdateSimulator — portão de regressão do auto-update (Fatia 3). Prova que o agente só aplica um
// update assinado, cuja versão avança (anti-downgrade) e cujos arquivos batem o SHA-256. Chaves de
// TESTE geradas em runtime. exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;

var failures = new List<string>();
void Check(string name, bool ok, string detail)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}");
    if (!ok) failures.Add(name);
}

var seed = Enumerable.Range(50, 32).Select(i => (byte)i).ToArray();
var keyId = new byte[] { 7, 7, 7, 7, 8, 8, 8, 8 };
var pub = MinisignPublicKey.FromRaw(keyId, Minisign.PublicKeyFromSeed(seed));

var agentV2 = Encoding.UTF8.GetBytes("RANSOMGUARD-AGENT-BINARY-v2");
string ManifestJson(int v, byte[] payload) => new ReleaseManifest
{
    Version = v,
    Files = new[] { new ReleaseFile("agent.msi", ReleaseManifest.Sha256Hex(payload)) }
}.ToJson();
string Sign(string json, int v) => Minisign.Sign(Encoding.UTF8.GetBytes(json), seed, keyId, $"release v{v}");

Console.WriteLine("RansomGuard · UpdateSimulator");
Console.WriteLine(new string('─', 60));

// 1. Update legítimo v2 (estamos na v1) com hash correto → aceito.
Console.WriteLine("\nCenário 1 · Update assinado v2, hash correto");
var v = new ReleaseManifestVerifier(pub, currentVersion: 1);
var json2 = ManifestJson(2, agentV2);
var r1 = v.TryApply(json2, Sign(json2, 2), _ => agentV2);
Check("update-aceito", r1.Accepted && v.CurrentVersion == 2, $"status {r1.Status}, versão {v.CurrentVersion}");

// 2. Pacote adulterado (hash não confere) → recusado.
Console.WriteLine("\nCenário 2 · Pacote adulterado (trojan)");
var v2 = new ReleaseManifestVerifier(pub, currentVersion: 1);
var r2 = v2.TryApply(json2, Sign(json2, 2), _ => Encoding.UTF8.GetBytes("RANSOMGUARD-AGENT-BINARY-v2-TROJAN"));
Check("hash-mismatch-recusado", r2.Status == UpdateStatus.HashMismatch, $"status {r2.Status}");

// 3. Anti-downgrade: manifesto v1 quando já estamos na v3 → recusado.
Console.WriteLine("\nCenário 3 · Anti-downgrade (v1 sobre v3)");
var v3 = new ReleaseManifestVerifier(pub, currentVersion: 3);
var json1 = ManifestJson(1, agentV2);
var r3 = v3.TryApply(json1, Sign(json1, 1), _ => agentV2);
Check("downgrade-recusado", r3.Status == UpdateStatus.Downgrade, $"status {r3.Status}");

// 4. Assinatura ausente/inválida → recusado.
Console.WriteLine("\nCenário 4 · Manifesto sem assinatura válida");
var v4 = new ReleaseManifestVerifier(pub, currentVersion: 1);
var r4 = v4.TryApply(json2, "isto não é um minisig", _ => agentV2);
Check("sem-assinatura-recusado", r4.Status == UpdateStatus.InvalidFormat, $"status {r4.Status}");

Console.WriteLine("\n" + new string('─', 60));
if (failures.Count == 0) { Console.WriteLine("VERDE — auto-update validado."); return 0; }
Console.WriteLine($"VERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return 1;
