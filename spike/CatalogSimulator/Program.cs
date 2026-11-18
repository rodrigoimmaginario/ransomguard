using System.Text;
using RansomGuard.Core.Catalog;
using RansomGuard.Core.Fsrm;
using RansomGuard.Core.Signing;

// CatalogSimulator — portão de regressão da Fatia 3. Gera um par de chaves de TESTE em runtime
// (nunca commitado), assina um catálogo, e prova que o agente só confia em lista assinada e não
// regride de versão. Cenários: válido → aceito + FSRM regenerado; 1 byte alterado → recusado;
// versão menor → anti-rollback; chave errada → recusado. exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;

var failures = new List<string>();
void Check(string name, bool ok, string detail)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}");
    if (!ok) failures.Add(name);
}

// Par de chaves de TESTE (seed e keyId efêmeros — nunca é a chave de produção do owner).
var seed = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
var keyId = new byte[] { 42, 42, 7, 7, 1, 2, 3, 4 };
var pub = MinisignPublicKey.FromRaw(keyId, Minisign.PublicKeyFromSeed(seed));

string CatalogJson(int v) => new RansomwareCatalog
{
    Version = v,
    Patterns = new[] { "*.locked", "*.crypted", "HOW_TO_DECRYPT*" }
}.ToJson();
string Sign(string json, int v) => Minisign.Sign(Encoding.UTF8.GetBytes(json), seed, keyId, $"ransomware catalog v{v}");

Console.WriteLine("RansomGuard · CatalogSimulator");
Console.WriteLine(new string('─', 60));

// 1. Catálogo assinado válido → aceito, e só então vira defesa (plano FSRM).
Console.WriteLine("\nCenário 1 · Catálogo v5 assinado corretamente");
var verifier = new CatalogVerifier(pub);
var json5 = CatalogJson(5);
var r1 = verifier.TryLoad(json5, Sign(json5, 5));
Check("valido-aceito", r1.Accepted, $"status {r1.Status}");
var plan = r1.Accepted ? FsrmPlan.BuildPowerShell(r1.Catalog!, new[] { @"D:\Shares\Financeiro" }) : "";
Check("gera-defesa-fsrm", plan.Contains("'*.locked'"), "catálogo verificado regenerou o FSRM");

// 2. 1 byte alterado → assinatura quebra → recusado (e nenhuma defesa é aplicada).
Console.WriteLine("\nCenário 2 · Adulteração de 1 byte");
var tampered = json5.Replace("*.crypted", "*.crypte_");
var r2 = verifier.TryLoad(tampered, Sign(json5, 5));
Check("adulterado-recusado", r2.Status == CatalogLoadStatus.BadSignature, $"status {r2.Status}");
Check("adulterado-sem-catalogo", r2.Catalog is null, "catálogo recusado não vira defesa");

// 3. Versão menor → anti-rollback (atacante não força uma lista mais fraca).
Console.WriteLine("\nCenário 3 · Anti-rollback (versão 3 após v5)");
var json3 = CatalogJson(3);
var r3 = verifier.TryLoad(json3, Sign(json3, 3));
Check("rollback-recusado", r3.Status == CatalogLoadStatus.Rollback, $"status {r3.Status}");
Check("versao-preservada", verifier.LastAcceptedVersion == 5, $"última aceita = {verifier.LastAcceptedVersion}");

// 4. Assinado por outra chave → keyId não confere → recusado.
Console.WriteLine("\nCenário 4 · Assinado por chave desconhecida");
var otherSeed = Enumerable.Range(100, 32).Select(i => (byte)i).ToArray();
var otherKeyId = new byte[] { 1, 1, 1, 1, 1, 1, 1, 1 };
var json6 = CatalogJson(6);
var foreignSig = Minisign.Sign(Encoding.UTF8.GetBytes(json6), otherSeed, otherKeyId, "v6 falsa");
var r4 = verifier.TryLoad(json6, foreignSig);
Check("chave-errada-recusada", r4.Status == CatalogLoadStatus.BadSignature, $"status {r4.Status}");

// 5. Versão nova legítima → aceita e avança.
Console.WriteLine("\nCenário 5 · Atualização legítima para v6");
var r5 = verifier.TryLoad(json6, Sign(json6, 6));
Check("update-aceito", r5.Accepted && verifier.LastAcceptedVersion == 6, $"aceito, versão {verifier.LastAcceptedVersion}");

Console.WriteLine("\n" + new string('─', 60));
if (failures.Count == 0) { Console.WriteLine("VERDE — catálogo assinado validado."); return 0; }
Console.WriteLine($"VERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return 1;
