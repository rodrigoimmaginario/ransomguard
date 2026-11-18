using System.Text;
using RansomGuard.Agent.Catalog;
using RansomGuard.Core.Fsrm;
using RansomGuard.Core.Signing;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// F18b — o coordenador é o elo que faltava (AUD-1, lado do agente): busca do painel, verifica
/// (assinatura + anti-rollback + policy) e aplica, sempre fail-safe. Estas provas exercem o
/// coordenador com chaves de TESTE e fontes/armazenamento fake, sem rede nem disco.
///
/// A garantia central: nenhuma falha (rede, assinatura, versão, semântica, persistência) pode
/// apagar ou rebaixar o último catálogo bom. Na ausência de qualquer catálogo válido, vale a
/// semente conservadora compilada.
/// </summary>
public class CatalogCoordinatorTests
{
    // Par de chaves de teste, gerado em runtime (nunca commitado).
    private static readonly byte[] Seed = Enumerable.Range(11, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] KeyId = { 1, 2, 3, 4, 5, 6, 7, 8 };
    private static MinisignPublicKey Pub() => MinisignPublicKey.FromRaw(KeyId, Minisign.PublicKeyFromSeed(Seed));

    private static (string Json, string Sig) Signed(int version, params string[] patterns)
    {
        var json = new RansomwareCatalog { Version = version, Patterns = patterns }.ToJson();
        var sig = Minisign.Sign(Encoding.UTF8.GetBytes(json), Seed, KeyId, $"catalog v{version}");
        return (json, sig);
    }

    /// <summary>Fonte fake: devolve o par que o teste configurar (ou nada, simulando painel mudo).</summary>
    private sealed class FakeSource : ICatalogSource
    {
        public (string Json, string Sig)? Next;
        public bool Throw;
        public Task<CatalogArtifact?> FetchAsync(CancellationToken ct = default)
        {
            if (Throw) throw new InvalidOperationException("painel inacessível");
            return Task.FromResult(Next is { } n ? new CatalogArtifact(n.Json, n.Sig) : null);
        }
    }

    /// <summary>Armazenamento fake em memória — fiel ao contrato do store real (último bom + versão).</summary>
    private sealed class MemoryStore : ICatalogStore
    {
        public CatalogArtifact? Saved;
        public int Version;
        public CatalogArtifact? Load() => Saved;
        public int LoadVersion() => Version;
        public void Save(CatalogArtifact artifact, int version) { Saved = artifact; Version = version; }
    }

    private static CatalogCoordinator Make(FakeSource src, MemoryStore store)
        => new(src, store, Pub());

    [Fact]
    public void Without_stored_catalog_starts_on_the_seed()
    {
        var coord = Make(new FakeSource(), new MemoryStore());
        coord.Initialize();

        Assert.Equal(CatalogState.Seed, coord.State);
        Assert.Equal(SeedCatalog.Version, coord.Active.Version);
    }

    [Fact]
    public async Task Signed_newer_catalog_is_verified_persisted_and_applied()
    {
        var src = new FakeSource { Next = Signed(1, "*.locked", "*.lockbit") };
        var store = new MemoryStore();
        var coord = Make(src, store);
        coord.Initialize();

        var changed = await coord.RefreshAsync();

        Assert.True(changed);
        Assert.Equal(CatalogState.Updated, coord.State);
        Assert.Equal(1, coord.Active.Version);
        Assert.Contains("*.lockbit", coord.Active.Patterns);
        Assert.Equal(1, store.Version);          // persistido para o anti-rollback entre reinícios
        Assert.NotNull(store.Saved);
    }

    [Fact]
    public async Task Tampered_catalog_is_refused_and_last_good_is_kept()
    {
        var src = new FakeSource { Next = Signed(2, "*.locked") };
        var store = new MemoryStore();
        var coord = Make(src, store);
        coord.Initialize();
        await coord.RefreshAsync();               // aceita v2

        // Adultera um byte mantendo a assinatura antiga.
        var (json, sig) = Signed(3, "*.locked", "*.evil");
        src.Next = (json.Replace("*.evil", "*.EVIL"), sig);
        var changed = await coord.RefreshAsync();

        Assert.False(changed);
        Assert.Equal(CatalogState.Rejected, coord.State);
        Assert.Equal(2, coord.Active.Version);    // manteve o último bom
    }

    [Fact]
    public async Task Rollback_to_older_version_is_refused_even_after_restart()
    {
        var store = new MemoryStore();
        var src = new FakeSource { Next = Signed(5, "*.locked") };
        var coord = Make(src, store);
        coord.Initialize();
        await coord.RefreshAsync();               // aceita v5

        // Simula reinício: novo coordenador lê o último bom e a versão do store.
        var reborn = Make(src, store);
        reborn.Initialize();
        Assert.Equal(5, reborn.Active.Version);   // carregou o último bom persistido

        src.Next = Signed(4, "*.locked");         // painel devolve versão antiga legítima
        var changed = await reborn.RefreshAsync();

        Assert.False(changed);
        Assert.Equal(CatalogState.Rejected, reborn.State);
        Assert.Equal(5, reborn.Active.Version);
    }

    [Fact]
    public async Task Signed_but_dangerous_catalog_is_refused_by_policy()
    {
        var src = new FakeSource { Next = Signed(1, "*") };   // curinga universal, assinado
        var coord = Make(src, new MemoryStore());
        coord.Initialize();

        var changed = await coord.RefreshAsync();

        Assert.False(changed);
        Assert.Equal(CatalogState.Rejected, coord.State);
        Assert.Equal(SeedCatalog.Version, coord.Active.Version);   // ficou na semente
    }

    [Fact]
    public async Task Panel_unreachable_keeps_current_catalog()
    {
        var src = new FakeSource { Throw = true };
        var coord = Make(src, new MemoryStore());
        coord.Initialize();

        var changed = await coord.RefreshAsync();

        Assert.False(changed);
        Assert.Equal(CatalogState.Seed, coord.State);   // sem rede: segue na semente, sem erro
        Assert.Equal(SeedCatalog.Version, coord.Active.Version);
    }

    [Fact]
    public async Task Corrupt_stored_catalog_falls_back_to_seed_on_init()
    {
        var store = new MemoryStore { Saved = new CatalogArtifact("{ not json", "nope"), Version = 9 };
        var coord = Make(new FakeSource(), store);
        coord.Initialize();

        // Último bom ilegível não pode derrubar o agente nem fingir versão 9: cai na semente.
        Assert.Equal(CatalogState.Seed, coord.State);
        Assert.Equal(SeedCatalog.Version, coord.Active.Version);
    }
}
