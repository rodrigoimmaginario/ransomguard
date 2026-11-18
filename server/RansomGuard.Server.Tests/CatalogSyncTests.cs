using System.Text;
using RansomGuard.Core.Fsrm;
using RansomGuard.Core.Signing;
using RansomGuard.Server.Catalog;

namespace RansomGuard.Server.Tests;

/// <summary>
/// F28 — o painel é o relay do catálogo: só ele fala com a origem pública, verifica e faz cache; o
/// agente pega do painel. Estas provas exercem o serviço de sync com chaves de TESTE e uma origem
/// fake, sem rede nem disco real (o cache é um store em memória injetado).
///
/// Invariante fail-safe (a mesma do agente): nenhuma falha — rede, assinatura, versão, policy —
/// pode apagar ou rebaixar o cache válido. Verificação acontece ANTES de promover.
/// </summary>
public class CatalogSyncTests
{
    private static readonly byte[] Seed = Enumerable.Range(21, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] KeyId = { 8, 7, 6, 5, 4, 3, 2, 1 };
    private static MinisignPublicKey Pub() => MinisignPublicKey.FromRaw(KeyId, Minisign.PublicKeyFromSeed(Seed));

    private static (string Json, string Sig) Signed(int version, params string[] patterns)
    {
        var json = new RansomwareCatalog { Version = version, Patterns = patterns }.ToJson();
        return (json, Minisign.Sign(Encoding.UTF8.GetBytes(json), Seed, KeyId, $"catalog v{version}"));
    }

    private sealed class FakeOrigin : ICatalogOrigin
    {
        public (string Json, string Sig)? Next;
        public bool Throw;
        public Task<CatalogBytes?> FetchAsync(CancellationToken ct = default)
        {
            if (Throw) throw new HttpRequestException("origem inacessível");
            return Task.FromResult(Next is { } n ? new CatalogBytes(n.Json, n.Sig) : null);
        }
    }

    private sealed class MemoryCache : ICatalogCache
    {
        public CatalogBytes? Stored;
        public int Version;
        public CatalogBytes? Load() => Stored;
        public int LoadVersion() => Version;
        public void Save(CatalogBytes bytes, int version) { Stored = bytes; Version = version; }
    }

    private static CatalogSyncService Make(FakeOrigin origin, MemoryCache cache)
        => new(origin, cache, Pub());

    [Fact]
    public async Task Signed_newer_catalog_is_verified_and_cached()
    {
        var origin = new FakeOrigin { Next = Signed(1, "*.locked", "*.lockbit") };
        var cache = new MemoryCache();
        var changed = await Make(origin, cache).SyncAsync();

        Assert.True(changed);
        Assert.Equal(1, cache.Version);
        Assert.NotNull(cache.Stored);
        Assert.Contains("*.lockbit", cache.Stored!.Json);
    }

    [Fact]
    public async Task Tampered_catalog_is_refused_and_cache_kept()
    {
        var origin = new FakeOrigin { Next = Signed(2, "*.locked") };
        var cache = new MemoryCache();
        await Make(origin, cache).SyncAsync();               // cacheia v2

        var (json, sig) = Signed(3, "*.locked", "*.x");
        origin.Next = (json.Replace("*.x", "*.Y"), sig);     // 1 byte alterado
        var changed = await Make(origin, cache).SyncAsync();

        Assert.False(changed);
        Assert.Equal(2, cache.Version);                      // manteve o cache bom
    }

    [Fact]
    public async Task Rollback_is_refused()
    {
        var origin = new FakeOrigin { Next = Signed(5, "*.locked") };
        var cache = new MemoryCache();
        await Make(origin, cache).SyncAsync();               // cacheia v5

        origin.Next = Signed(4, "*.locked");                 // versão antiga legítima
        var changed = await Make(origin, cache).SyncAsync();

        Assert.False(changed);
        Assert.Equal(5, cache.Version);
    }

    [Fact]
    public async Task Signed_but_dangerous_catalog_is_refused_by_policy()
    {
        var origin = new FakeOrigin { Next = Signed(1, "*") };   // curinga universal, assinado
        var cache = new MemoryCache();
        var changed = await Make(origin, cache).SyncAsync();

        Assert.False(changed);
        Assert.Equal(0, cache.Version);                      // nada entrou no cache
    }

    [Fact]
    public async Task Origin_unreachable_keeps_cache()
    {
        var cache = new MemoryCache { Stored = null, Version = 0 };
        var origin = new FakeOrigin { Throw = true };
        var changed = await Make(origin, cache).SyncAsync();

        Assert.False(changed);
        Assert.Equal(0, cache.Version);                      // sem rede: nada muda, sem exceção
    }

    [Fact]
    public async Task Origin_without_catalog_is_a_noop()
    {
        var origin = new FakeOrigin { Next = null };
        var cache = new MemoryCache();
        var changed = await Make(origin, cache).SyncAsync();

        Assert.False(changed);
        Assert.Null(cache.Stored);
    }
}
