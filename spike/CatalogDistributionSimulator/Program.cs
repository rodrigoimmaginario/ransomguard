using System.Text;
using RansomGuard.Agent.Catalog;
using RansomGuard.Core.Fsrm;
using RansomGuard.Core.Signing;

// CatalogDistributionSimulator — portão de regressão do elo de distribuição do catálogo (F18,
// AUD-1 lado do código). Prova a cadeia completa com chaves de TESTE, sem rede nem painel real:
//
//   semente → v1 assinado aplicado → reinício mantém v1 → adulterado/rollback recusados
//   (mantêm v1) → v2 aplicado.
//
// Diferente do SecurityAuditSimulator (que aponta o furo enquanto o artefato não é publicado),
// este prova que o CÓDIGO que busca/verifica/aplica existe e funciona. exit 0 = verde.

Console.OutputEncoding = Encoding.UTF8;

var failures = new List<string>();
void Check(string name, bool ok, string detail)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}");
    if (!ok) failures.Add(name);
}

var seed = Enumerable.Range(11, 32).Select(i => (byte)i).ToArray();
var keyId = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
var pub = MinisignPublicKey.FromRaw(keyId, Minisign.PublicKeyFromSeed(seed));

(string Json, string Sig) Signed(int version, params string[] patterns)
{
    var json = new RansomwareCatalog { Version = version, Patterns = patterns }.ToJson();
    return (json, Minisign.Sign(Encoding.UTF8.GetBytes(json), seed, keyId, $"catalog v{version}"));
}

// Origem controlada pelo teste (o "painel"): devolve o par configurado.
var source = new ScriptedSource();
var store = new MemoryStore();

Console.WriteLine("RansomGuard · CatalogDistributionSimulator");
Console.WriteLine(new string('─', 64));

// 1. Sem catálogo persistido → começa na semente.
Console.WriteLine("\nCenário 1 · Partida sem catálogo → semente");
var coord = new CatalogCoordinator(source, store, pub);
coord.Initialize();
Check("comeca-na-semente", coord.State == CatalogState.Seed && coord.Active.Version == SeedCatalog.Version,
    $"estado {coord.State}, v{coord.Active.Version}");

// 2. Catálogo v1 assinado → verificado, persistido, aplicado.
Console.WriteLine("\nCenário 2 · v1 assinado aplicado");
source.Next = Signed(1, "*.locked", "*.lockbit", "HOW_TO_DECRYPT*");
var changed1 = await coord.RefreshAsync();
Check("v1-aplicado", changed1 && coord.Active.Version == 1 && coord.Active.Patterns.Contains("*.lockbit"),
    $"estado {coord.State}, v{coord.Active.Version}");
Check("v1-persistido", store.Version == 1 && store.Saved is not null, "último bom gravado");
Check("v1-vira-file-screen",
    FsrmPlan.BuildPowerShell(coord.Active, new[] { @"D:\Shares\Financeiro" }).Contains("*.lockbit"),
    "catálogo aceito chega ao FSRM");

// 3. Reinício: novo coordenador lê o último bom persistido.
Console.WriteLine("\nCenário 3 · Reinício mantém v1");
var reborn = new CatalogCoordinator(source, store, pub);
reborn.Initialize();
Check("reinicio-carrega-v1", reborn.State == CatalogState.Cached && reborn.Active.Version == 1,
    $"estado {reborn.State}, v{reborn.Active.Version}");

// 4. Adulteração de 1 byte → recusada, mantém v1.
Console.WriteLine("\nCenário 4 · Adulterado recusado");
var (j3, s3) = Signed(3, "*.locked", "*.evil");
source.Next = (j3.Replace("*.evil", "*.EVIL"), s3);
var changed2 = await reborn.RefreshAsync();
Check("adulterado-recusado", !changed2 && reborn.State == CatalogState.Rejected && reborn.Active.Version == 1,
    $"estado {reborn.State}, v{reborn.Active.Version}");

// 5. Rollback para v0/antigo → recusado (anti-rollback persistente).
Console.WriteLine("\nCenário 5 · Rollback recusado");
source.Next = Signed(1, "*.locked");   // mesma versão que já aceitou
var changed3 = await reborn.RefreshAsync();
Check("rollback-recusado", !changed3 && reborn.Active.Version == 1, $"v{reborn.Active.Version}");

// 6. Catálogo perigoso (curinga universal) assinado → recusado pela policy.
Console.WriteLine("\nCenário 6 · Assinado porém perigoso recusado");
source.Next = Signed(9, "*");
var changed4 = await reborn.RefreshAsync();
Check("curinga-recusado", !changed4 && reborn.Active.Version == 1, $"v{reborn.Active.Version} (curinga não aplicado)");

// 7. v2 legítimo → aplicado por cima do v1.
Console.WriteLine("\nCenário 7 · v2 legítimo aplicado");
source.Next = Signed(2, "*.locked", "*.akira", "*.qilin");
var changed5 = await reborn.RefreshAsync();
Check("v2-aplicado", changed5 && reborn.Active.Version == 2 && reborn.Active.Patterns.Contains("*.akira"),
    $"estado {reborn.State}, v{reborn.Active.Version}");

Console.WriteLine("\n" + new string('─', 64));
if (failures.Count == 0) { Console.WriteLine("VERDE — elo de distribuição do catálogo validado."); return 0; }
Console.WriteLine($"VERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return 1;

// ── fontes/armazenamento de teste ────────────────────────────────────────────────────────────
sealed class ScriptedSource : ICatalogSource
{
    public (string Json, string Sig)? Next;
    public Task<CatalogArtifact?> FetchAsync(CancellationToken ct = default)
        => Task.FromResult(Next is { } n ? new CatalogArtifact(n.Json, n.Sig) : null);
}

sealed class MemoryStore : ICatalogStore
{
    public CatalogArtifact? Saved;
    public int Version;
    public CatalogArtifact? Load() => Saved;
    public int LoadVersion() => Version;
    public void Save(CatalogArtifact artifact, int version) { Saved = artifact; Version = version; }
}
