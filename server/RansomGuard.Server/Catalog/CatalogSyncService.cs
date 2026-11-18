using RansomGuard.Core.Catalog;
using RansomGuard.Core.Fsrm;
using RansomGuard.Core.Signing;

namespace RansomGuard.Server.Catalog;

/// <summary>Os bytes exatos do catálogo assinado: JSON (o que foi assinado) e o .minisig.</summary>
public sealed record CatalogBytes(string Json, string Signature);

/// <summary>De onde o painel busca o catálogo publicado. HTTP real no fio; fake nos testes.</summary>
public interface ICatalogOrigin
{
    Task<CatalogBytes?> FetchAsync(CancellationToken ct = default);
}

/// <summary>O cache local do painel (o que o relay serve ao agente) + a maior versão aceita.</summary>
public interface ICatalogCache
{
    CatalogBytes? Load();
    int LoadVersion();
    void Save(CatalogBytes bytes, int version);
}

/// <summary>
/// F28 — fecha o relay do catálogo no painel. Só o painel fala com a origem pública; ele busca,
/// verifica de forma independente (assinatura + anti-rollback + <see cref="CatalogPolicy"/>) e faz
/// cache. O agente pega do painel e verifica de novo (defesa em profundidade). Isto preserva a
/// promessa de que o agente só conversa com o painel self-hosted.
///
/// Invariante fail-safe (a mesma do coordenador do agente): a verificação acontece ANTES de
/// promover, e nenhuma falha — rede, assinatura, versão, policy — apaga ou rebaixa o cache válido.
/// Lógica pura orquestrando o Core; o HTTP/disco reais ficam no fio (origem + cache de arquivo).
/// </summary>
public sealed class CatalogSyncService
{
    private readonly ICatalogOrigin _origin;
    private readonly ICatalogCache _cache;
    private readonly MinisignPublicKey _trustedKey;

    public CatalogSyncService(ICatalogOrigin origin, ICatalogCache cache, MinisignPublicKey trustedKey)
    {
        _origin = origin;
        _cache = cache;
        _trustedKey = trustedKey;
    }

    /// <summary>
    /// Busca a origem e promove um catálogo mais novo e válido para o cache. Fail-safe em toda falha.
    /// </summary>
    /// <returns><c>true</c> se o cache mudou.</returns>
    public async Task<bool> SyncAsync(CancellationToken ct = default)
    {
        CatalogBytes? fetched;
        try
        {
            fetched = await _origin.FetchAsync(ct);
        }
        catch
        {
            return false;   // origem inacessível: mantém o cache, sem erro
        }

        if (fetched is null) return false;

        var floor = _cache.LoadVersion();
        if (!TryVerify(fetched, floor, out var version))
            return false;   // assinatura/versão/policy reprovadas: cache preservado

        _cache.Save(fetched, version);
        return true;
    }

    /// <summary>
    /// Verificação independente e sem efeito colateral: assinatura, anti-rollback (versão &gt;
    /// <paramref name="floor"/>) e <see cref="CatalogPolicy"/>. Verificador local à checagem.
    /// </summary>
    private bool TryVerify(CatalogBytes bytes, int floor, out int version)
    {
        version = 0;
        try
        {
            var verifier = new CatalogVerifier(_trustedKey, lastAcceptedVersion: Math.Max(floor, 0));
            var result = verifier.TryLoad(bytes.Json, bytes.Signature);
            if (!result.Accepted || result.Catalog is null) return false;
            if (!CatalogPolicy.Check(result.Catalog).Ok) return false;
            version = result.Catalog.Version;
            return true;
        }
        catch
        {
            return false;
        }
    }
}
