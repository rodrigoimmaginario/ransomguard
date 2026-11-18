using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace RansomGuard.Server.Tests;

/// <summary>
/// R1 — endpoints que expõem metadado sensível (relatório executivo, export SIEM) precisam exigir
/// login. A verificação é feita sobre os metadados de autorização das rotas registradas: se alguém
/// remover o RequireAuthorization no futuro, o teste quebra aqui, antes de ir para produção.
///
/// A ingestão do agente (/api/ingest) é máquina-para-máquina e NÃO usa cookie de propósito — sua
/// proteção é o segredo compartilhado (F17b), não autorização por login. O teste fixa esse contrato
/// para os dois lados não regredirem.
/// </summary>
public sealed class EndpointAuthorizationTests
    : IClassFixture<IsolatedPanelFactory>
{
    private readonly IsolatedPanelFactory _factory;

    public EndpointAuthorizationTests(IsolatedPanelFactory factory) => _factory = factory;

    private bool HasAuthorization(string routePattern)
    {
        using var scope = _factory.Services.CreateScope();
        var sources = scope.ServiceProvider.GetRequiredService<EndpointDataSource>();
        var endpoint = sources.Endpoints
            .OfType<RouteEndpoint>()
            .FirstOrDefault(e => e.RoutePattern.RawText == routePattern);

        Assert.NotNull(endpoint);
        return endpoint!.Metadata.GetMetadata<IAuthorizeData>() is not null;
    }

    [Fact]
    public void Report_endpoint_requires_authorization()
        => Assert.True(HasAuthorization("/relatorio"));

    [Fact]
    public void Siem_endpoint_requires_authorization()
        => Assert.True(HasAuthorization("/siem/incidentes"));

    [Fact]
    public void Agent_ingest_is_intentionally_not_cookie_authorized()
        => Assert.False(HasAuthorization("/api/ingest"));
}
