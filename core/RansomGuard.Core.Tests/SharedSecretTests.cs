using RansomGuard.Core.Auth;

namespace RansomGuard.Core.Tests;

/// <summary>
/// O segredo do `/api/ingest` fecha a última superfície aberta do painel. Os dois comportamentos
/// que importam: opt-in (não quebrar quem não configurou) e recusar de verdade quando ligado.
/// </summary>
public class SharedSecretTests
{
    // ── Opt-in: sem segredo configurado, aceita tudo ────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Sem_segredo_configurado_aceita_qualquer_requisicao(string? configured)
    {
        Assert.True(SharedSecret.IsAuthorized(configured, "qualquer-coisa"));
        Assert.True(SharedSecret.IsAuthorized(configured, null));
        Assert.False(SharedSecret.IsProtectionEnabled(configured));
    }

    // ── Ligado: exige o token certo ─────────────────────────────────────────────────────────

    [Fact]
    public void Com_segredo_o_token_certo_e_aceito()
    {
        Assert.True(SharedSecret.IsAuthorized("tk-secreto-123", "tk-secreto-123"));
        Assert.True(SharedSecret.IsProtectionEnabled("tk-secreto-123"));
    }

    [Fact]
    public void Com_segredo_o_token_errado_e_recusado()
        => Assert.False(SharedSecret.IsAuthorized("tk-secreto-123", "tk-errado"));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Com_segredo_a_ausencia_de_token_e_recusada(string? presented)
        => Assert.False(SharedSecret.IsAuthorized("tk-secreto-123", presented));

    /// <summary>Prefixo correto não basta — a comparação é do valor inteiro.</summary>
    [Fact]
    public void Prefixo_correto_nao_engana()
    {
        Assert.False(SharedSecret.IsAuthorized("tk-secreto-123", "tk-secreto-12"));
        Assert.False(SharedSecret.IsAuthorized("tk-secreto-123", "tk-secreto-1234"));
    }

    [Fact]
    public void Diferenca_de_caixa_e_recusada()
        => Assert.False(SharedSecret.IsAuthorized("TokenABC", "tokenabc"));
}
