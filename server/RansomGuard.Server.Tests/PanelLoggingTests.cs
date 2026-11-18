using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace RansomGuard.Server.Tests;

/// <summary>
/// O painel só escreve no Log de Eventos do Windows quando roda como serviço — a fonte "RansomGuardPanel" é criada pelo
/// instalador. Fora do serviço (testes, execução interativa), escrever numa fonte inexistente falhava de vez em quando
/// com "Access is denied" e derrubava testes sem relação com log (CI de 2026-11-17 e 2026-11-18).
/// </summary>
public sealed class PanelLoggingTests : IClassFixture<IsolatedPanelFactory>
{
    private readonly IsolatedPanelFactory _factory;
    public PanelLoggingTests(IsolatedPanelFactory factory) => _factory = factory;

    [Fact]
    public void Fora_do_servico_o_painel_nao_registra_o_log_de_eventos_do_windows()
    {
        var providers = _factory.Services.GetServices<ILoggerProvider>().Select(p => p.GetType().Name).ToList();

        Assert.DoesNotContain("EventLogLoggerProvider", providers);
        Assert.Contains("ConsoleLoggerProvider", providers);
    }
}
