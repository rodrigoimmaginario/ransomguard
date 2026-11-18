using System.Text;
using RansomGuard.Core.Catalog;
using RansomGuard.Core.Fsrm;
using RansomGuard.Core.Signing;

namespace RansomGuard.Agent.Catalog;

/// <summary>Os bytes exatos de um catálogo assinado: o JSON (o que foi assinado) e o .minisig.</summary>
public sealed record CatalogArtifact(string Json, string Signature);

/// <summary>De onde o agente busca o catálogo. Em produção, o painel (relay); nos testes, um fake.</summary>
public interface ICatalogSource
{
    /// <returns>O artefato disponível, ou <c>null</c> se a origem não tem catálogo agora.</returns>
    Task<CatalogArtifact?> FetchAsync(CancellationToken ct = default);
}

/// <summary>Onde o agente persiste o último catálogo bom e a maior versão aceita (anti-rollback).</summary>
public interface ICatalogStore
{
    CatalogArtifact? Load();
    int LoadVersion();
    void Save(CatalogArtifact artifact, int version);
}

/// <summary>De onde vem o catálogo ativo agora.</summary>
public enum CatalogState
{
    /// <summary>Semente compilada — nenhum catálogo assinado válido ainda.</summary>
    Seed,
    /// <summary>Último bom carregado do armazenamento na partida.</summary>
    Cached,
    /// <summary>Atualizado nesta sessão a partir da origem.</summary>
    Updated,
    /// <summary>A última tentativa foi recusada; o ativo é o anterior (bom ou semente).</summary>
    Rejected
}

/// <summary>
/// F18 — o elo que faltava do catálogo (AUD-1, lado do agente). Busca da origem (o painel), verifica
/// de forma independente (assinatura + anti-rollback + <see cref="CatalogPolicy"/>), persiste o
/// último bom e expõe o catálogo ativo para o <c>ProtectionApplier</c> aplicar no FSRM.
///
/// Invariante de segurança: <b>nenhuma falha rebaixa a defesa</b>. Rede muda, assinatura inválida,
/// versão que regride, catálogo perigoso ou persistência ilegível — em todos os casos o ativo
/// permanece o último catálogo bom, ou a semente conservadora se nunca houve um.
///
/// O coordenador é a autoridade do anti-rollback: mantém a maior versão aceita e só promove um
/// catálogo que passe assinatura E policy, evitando que a verificação avance o estado antes de a
/// policy aprovar. Lógica pura orquestrando o Core; o HTTP/disco reais ficam no serviço.
/// </summary>
public sealed class CatalogCoordinator
{
    private readonly ICatalogSource _source;
    private readonly ICatalogStore _store;
    private readonly MinisignPublicKey _trustedKey;

    public RansomwareCatalog Active { get; private set; } = SeedCatalog.AsCatalog;
    public CatalogState State { get; private set; } = CatalogState.Seed;

    /// <summary>Maior versão já aceita — piso do anti-rollback, persistido entre reinícios.</summary>
    private int _acceptedVersion;

    public CatalogCoordinator(ICatalogSource source, ICatalogStore store, MinisignPublicKey trustedKey)
    {
        _source = source;
        _store = store;
        _trustedKey = trustedKey;
    }

    /// <summary>
    /// Carrega o último bom persistido. Se ausente ou ilegível, cai na semente — nunca lança, nunca
    /// finge uma versão que não conseguiu validar.
    /// </summary>
    public void Initialize()
    {
        var stored = _store.Load();
        var storedVersion = _store.LoadVersion();

        if (stored is not null && TryVerify(stored, floor: storedVersion - 1, out var catalog)
            && catalog.Version >= 1)
        {
            Active = catalog;
            _acceptedVersion = catalog.Version;
            State = CatalogState.Cached;
            return;
        }

        // Sem bom persistido (ou ilegível): semente. O anti-rollback recomeça do zero, o que é
        // seguro — a semente é versão 0 e qualquer catálogo publicado (>=1) a supera.
        Active = SeedCatalog.AsCatalog;
        _acceptedVersion = 0;
        State = CatalogState.Seed;
    }

    /// <summary>
    /// Busca a origem e tenta promover um catálogo mais novo e válido. Fail-safe em toda falha.
    /// </summary>
    /// <returns><c>true</c> se o catálogo ativo mudou.</returns>
    public async Task<bool> RefreshAsync(CancellationToken ct = default)
    {
        CatalogArtifact? artifact;
        try
        {
            artifact = await _source.FetchAsync(ct);
        }
        catch
        {
            // Origem inacessível não é erro do agente: segue com o ativo, sem mudar de estado.
            return false;
        }

        if (artifact is null) return false;

        if (!TryVerify(artifact, floor: _acceptedVersion, out var catalog))
        {
            State = CatalogState.Rejected;
            return false;
        }

        // Promove: novo ativo, versão persistida para o anti-rollback sobreviver ao reinício.
        Active = catalog;
        _acceptedVersion = catalog.Version;
        _store.Save(artifact, catalog.Version);
        State = CatalogState.Updated;
        return true;
    }

    /// <summary>
    /// Verificação independente e sem efeito colateral: assinatura (chave embutida), anti-rollback
    /// (versão &gt; <paramref name="floor"/>) e <see cref="CatalogPolicy"/>. O verificador é local
    /// à checagem, para não avançar estado antes de a policy aprovar.
    /// </summary>
    private bool TryVerify(CatalogArtifact artifact, int floor, out RansomwareCatalog catalog)
    {
        catalog = SeedCatalog.AsCatalog;
        try
        {
            var verifier = new CatalogVerifier(_trustedKey, lastAcceptedVersion: Math.Max(floor, 0));
            var result = verifier.TryLoad(artifact.Json, artifact.Signature);
            if (!result.Accepted || result.Catalog is null) return false;

            if (!CatalogPolicy.Check(result.Catalog).Ok) return false;

            catalog = result.Catalog;
            return true;
        }
        catch
        {
            // JSON/assinatura corrompidos de forma inesperada não podem derrubar o agente nem ser
            // aceitos: tratamos como recusa e o chamador mantém o último bom ou a semente.
            return false;
        }
    }
}
