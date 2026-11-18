namespace RansomGuard.Server.Catalog;

/// <summary>
/// Origem de um par fixo (JSON + assinatura), para a importação manual (F28c) reusar exatamente o
/// mesmo caminho de verificação do sync automático: assinatura + anti-rollback + policy. Assim o
/// ambiente sem egress não tem uma porta de entrada mais fraca que a origem pública.
/// </summary>
public sealed class StaticCatalogOrigin : ICatalogOrigin
{
    private readonly CatalogBytes _bytes;
    public StaticCatalogOrigin(string json, string signature) => _bytes = new CatalogBytes(json, signature);
    public Task<CatalogBytes?> FetchAsync(CancellationToken ct = default) => Task.FromResult<CatalogBytes?>(_bytes);
}
