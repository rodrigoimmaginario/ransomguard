using RansomGuard.Core.Auth;

namespace RansomGuard.Core.Tests;

/// <summary>
/// R9 — o canal agente→painel precisa ser honesto sobre sua própria postura. Em claro (http) numa
/// rede real, um lote de detecção pode ser espionado ou forjado; sem segredo de ingestão, qualquer
/// um na LAN posta lotes falsos. Estas provas fixam quando o produto deve avisar — sem bloquear o
/// piloto atual (o endurecimento obrigatório é decisão de empacotamento do RC).
/// </summary>
public class TransportPostureTests
{
    [Fact]
    public void Https_with_secret_is_secure()
    {
        var p = TransportPosture.Evaluate("https://painel.corp:5001", enrolled: true);
        Assert.True(p.Secure);
        Assert.Empty(p.Warnings);
    }

    [Fact]
    public void Plain_http_on_lan_warns_about_cleartext()
    {
        var p = TransportPosture.Evaluate("http://painel.corp:5000", enrolled: true);
        Assert.False(p.Secure);
        Assert.Contains(p.Warnings, w => w.Contains("claro", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Agent_not_enrolled_warns_that_batches_will_be_refused()
    {
        var p = TransportPosture.Evaluate("https://painel.corp:5001", enrolled: false);
        Assert.False(p.Secure);
        Assert.Contains(p.Warnings, w => w.Contains("enrolado", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Loopback_http_is_not_flagged()
    {
        // Dev/local legítimo: não poluir com aviso.
        var p = TransportPosture.Evaluate("http://localhost:5000", enrolled: false);
        Assert.DoesNotContain(p.Warnings, w => w.Contains("claro", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("http://127.0.0.1:5000")]
    [InlineData("http://[::1]:5000")]
    public void Loopback_addresses_are_local(string url)
        => Assert.DoesNotContain(TransportPosture.Evaluate(url, enrolled: false).Warnings,
            w => w.Contains("claro", StringComparison.OrdinalIgnoreCase));

    [Fact]
    public void Malformed_url_warns_without_throwing()
    {
        var p = TransportPosture.Evaluate("not a url", enrolled: true);
        Assert.False(p.Secure);   // não conseguimos garantir https → avisa
    }
}
