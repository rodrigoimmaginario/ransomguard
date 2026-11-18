using System.Text;
using RansomGuard.Core.Fsrm;
using RansomGuard.Core.Signing;

namespace RansomGuard.Core.Catalog;

/// <summary>Resultado da tentativa de carregar um catálogo assinado.</summary>
public enum CatalogLoadStatus
{
    Accepted,
    BadSignature,
    Rollback,
    InvalidFormat
}

/// <param name="Status">Desfecho.</param>
/// <param name="Catalog">Catálogo aceito (null se recusado).</param>
/// <param name="Version">Versão do catálogo recusado/aceito, quando legível.</param>
/// <param name="Detail">Motivo legível.</param>
public sealed record CatalogLoadResult(
    CatalogLoadStatus Status, RansomwareCatalog? Catalog, int Version, string Detail)
{
    public bool Accepted => Status == CatalogLoadStatus.Accepted;
}

/// <summary>
/// Porta de entrada do catálogo no agente: só aceita uma lista **assinada** por uma chave confiável
/// e cuja versão **não regrida** (anti-rollback). É o que torna o agente "burro e seguro" — ele
/// nunca confia numa lista sem prova criptográfica. Fail-safe: recusar não apaga o último bom.
/// Lógica pura e determinística.
/// </summary>
public sealed class CatalogVerifier
{
    private readonly MinisignPublicKey _trustedKey;

    /// <summary>Maior versão já aceita (anti-rollback). O chamador persiste e reinjeta entre execuções.</summary>
    public int LastAcceptedVersion { get; private set; }

    public CatalogVerifier(MinisignPublicKey trustedKey, int lastAcceptedVersion = 0)
    {
        _trustedKey = trustedKey;
        LastAcceptedVersion = lastAcceptedVersion;
    }

    /// <summary>
    /// Verifica e (se OK) aceita um catálogo. <paramref name="catalogJson"/> é o conteúdo exato do
    /// arquivo (o mesmo bytes que foi assinado); <paramref name="minisig"/> é o .minisig ao lado.
    /// </summary>
    public CatalogLoadResult TryLoad(string catalogJson, string minisig)
    {
        RansomwareCatalog catalog;
        MinisignSignature signature;
        try
        {
            catalog = RansomwareCatalog.FromJson(catalogJson);
            signature = MinisignSignature.Parse(minisig);
        }
        catch (FormatException ex)
        {
            return new CatalogLoadResult(CatalogLoadStatus.InvalidFormat, null, 0, ex.Message);
        }

        var verdict = Minisign.Verify(Encoding.UTF8.GetBytes(catalogJson), signature, _trustedKey);
        if (verdict != MinisignVerificationResult.Valid)
            return new CatalogLoadResult(CatalogLoadStatus.BadSignature, null, catalog.Version,
                $"Assinatura inválida: {verdict}");

        // Anti-rollback: recusa versão menor OU igual à última aceita (uma versão nova é obrigatória).
        if (catalog.Version <= LastAcceptedVersion)
            return new CatalogLoadResult(CatalogLoadStatus.Rollback, null, catalog.Version,
                $"Anti-rollback: versão {catalog.Version} ≤ última aceita {LastAcceptedVersion}.");

        LastAcceptedVersion = catalog.Version;
        return new CatalogLoadResult(CatalogLoadStatus.Accepted, catalog, catalog.Version, "OK");
    }
}
