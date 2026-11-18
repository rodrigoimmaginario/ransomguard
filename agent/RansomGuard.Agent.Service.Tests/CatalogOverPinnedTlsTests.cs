using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RansomGuard.Agent.Service.Windows;

namespace RansomGuard.Agent.Service.Tests;

/// <summary>
/// D8 — o catálogo assinado precisa chegar ao agente pelo painel REAL, que nasce em HTTPS com certificado
/// autoassinado. Um painel em miniatura (Kestrel + certificado autoassinado) serve o relay; o teste mostra o
/// defeito (cliente comum recusa o certificado) e a correção (cliente com pin obtém o catálogo).
/// </summary>
public sealed class CatalogOverPinnedTlsTests : IAsyncLifetime
{
    private const string CatalogJson = "{\"version\":2,\"patterns\":[\"*.locked\"]}";
    private const string CatalogSig = "untrusted comment: teste\nRWQ=";

    private WebApplication _panel = null!;
    private X509Certificate2 _cert = null!;
    private string _url = "";
    private string _pinPath = "";

    public async Task InitializeAsync()
    {
        _cert = SelfSigned();
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0, l => l.UseHttps(_cert)));
        _panel = builder.Build();
        _panel.MapGet("/api/catalog/catalog.json", () => CatalogJson);
        _panel.MapGet("/api/catalog/catalog.json.minisig", () => CatalogSig);
        await _panel.StartAsync();
        _url = _panel.Urls.First();
        _pinPath = Path.Combine(Path.GetTempPath(), "rg-pin-" + Guid.NewGuid().ToString("N"), "panel-cert.sha256");
    }

    public async Task DisposeAsync()
    {
        await _panel.StopAsync();
        await _panel.DisposeAsync();
        _cert.Dispose();
        var dir = Path.GetDirectoryName(_pinPath)!;
        if (Directory.Exists(dir)) Directory.Delete(dir, true);
    }

    private static X509Certificate2 SelfSigned()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=painel-de-teste", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost"); san.AddIpAddress(IPAddress.Loopback);
        req.CertificateExtensions.Add(san.Build());
        using var ephemeral = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        // No Windows a chave efêmera não serve ao TLS do servidor; exportar e reimportar a torna utilizável.
        return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable);
    }

    private string Thumbprint => Convert.ToHexString(SHA256.HashData(_cert.RawData));

    [Fact]
    public async Task Cliente_comum_recusa_o_certificado_do_painel_e_fica_sem_catalogo()
    {
        var comum = new HttpCatalogSource(new HttpClient { BaseAddress = new Uri(_url) }, NullLogger<HttpCatalogSource>.Instance);

        Assert.Null(await comum.FetchAsync());
    }

    [Fact]
    public async Task Cliente_com_pin_obtem_o_catalogo_e_fixa_o_certificado_no_primeiro_contato()
    {
        var log = NullLogger<HttpCatalogSource>.Instance;
        var comPin = new HttpCatalogSource(AgentHttp.CreatePinned(_url, _pinPath, null, log), log);

        var artefato = await comPin.FetchAsync();

        Assert.NotNull(artefato);
        Assert.Equal(CatalogJson, artefato!.Json);
        Assert.Equal(CatalogSig, artefato.Signature);
        Assert.Equal(Thumbprint, File.ReadAllText(_pinPath).Trim());
    }

    [Fact]
    public async Task Com_o_certificado_configurado_so_aquele_painel_serve_o_catalogo()
    {
        var log = NullLogger<HttpCatalogSource>.Instance;
        var certo = new HttpCatalogSource(AgentHttp.CreatePinned(_url, _pinPath, Thumbprint, log), log);
        var errado = new HttpCatalogSource(AgentHttp.CreatePinned(_url, _pinPath, new string('A', 64), log), log);

        Assert.NotNull(await certo.FetchAsync());
        Assert.Null(await errado.FetchAsync());
    }

    [Fact]
    public async Task Painel_trocado_depois_do_pin_e_recusado()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_pinPath)!);
        File.WriteAllText(_pinPath, new string('B', 64));   // pin de outro certificado, fixado antes
        var log = NullLogger<HttpCatalogSource>.Instance;

        Assert.Null(await new HttpCatalogSource(AgentHttp.CreatePinned(_url, _pinPath, null, log), log).FetchAsync());
    }
}
