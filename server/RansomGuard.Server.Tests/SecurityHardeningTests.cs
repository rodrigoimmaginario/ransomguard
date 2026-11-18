using System.Net;
using System.Text.Json;
using RansomGuard.Core.Signing;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Auth;
using RansomGuard.Server.Ingestion;

namespace RansomGuard.Server.Tests;

/// <summary>Identidade da instalação: um GUID criado uma vez e reutilizado (publicado em /api/identity).</summary>
public class InstallIdentityTests : DbTestBase
{
    private static readonly DateTime Now = new(2026, 7, 24, 0, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task Generates_id_once_and_reuses_it()
    {
        var id1 = new InstallIdentity(Db, () => "fixed-id");
        var a = await id1.GetOrCreateAsync(Now);
        var b = await id1.GetOrCreateAsync(Now);
        Assert.Equal("fixed-id", a);
        Assert.Equal(a, b);
        Assert.Single(Db.Installations);
    }
}

/// <summary>F38 — chave Ed25519 da instalação: assina política, comandos e relatórios; o agente fixa a pública.</summary>
public sealed class InstallKeyStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rg-f38-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    [Fact]
    public async Task Key_store_creates_once_and_reloads_the_same_key()
    {
        var path = Path.Combine(_dir, "install-key.json");
        var k1 = await new FileInstallKeyStore(path).GetOrCreateAsync();
        var k2 = await new FileInstallKeyStore(path).GetOrCreateAsync();   // nova instância = reload do disco

        Assert.True(File.Exists(path));
        Assert.Equal(k1.Seed, k2.Seed);
        Assert.Equal(k1.KeyId, k2.KeyId);
        Assert.Equal(k1.PublicKeyFileContent, k2.PublicKeyFileContent);
    }

    [Fact]
    public async Task Public_key_file_content_parses_as_minisign_pub()
    {
        var key = await new FileInstallKeyStore(Path.Combine(_dir, "k.json")).GetOrCreateAsync();
        var parsed = MinisignPublicKey.Parse(key.PublicKeyFileContent);
        Assert.Equal(key.PublicKey.KeyIdHex, parsed.KeyIdHex);
    }
}

/// <summary>
/// O produto é gratuito: o painel não decide "se pode conter" por licença. A resposta da ingestão leva só o que o
/// agente verifica por assinatura — política e comandos — e nenhum campo de licença.
/// </summary>
public class IngestReplyWithoutLicenseTests : DbTestBase
{
    private static readonly DateTime Now = new(2026, 7, 27, 0, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task Resposta_da_ingestao_nao_tem_campos_de_licenca()
    {
        var svc = new IngestionService(Db, new AlertEngine(new CollectingAlertSink()));

        var r = await svc.IngestAsync(new AgentBatch("FS01", Now, null,
            Array.Empty<RansomGuard.Core.Detection.FileEvent>(), Array.Empty<RansomGuard.Core.Detection.HostSignal>()));

        var json = JsonSerializer.Serialize(r, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        using var doc = JsonDocument.Parse(json);
        var names = doc.RootElement.EnumerateObject().Select(p => p.Name).ToList();
        Assert.DoesNotContain(names, n => n.Contains("licens", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain("assertion", names);
        Assert.Contains("policy", names);
        Assert.Contains("commands", names);
    }
}

/// <summary>As superfícies de venda saíram do painel: tela de licença e webhook de pagamento não existem mais.</summary>
public class LicensingSurfaceRemovedTests : IClassFixture<IsolatedPanelFactory>
{
    private readonly IsolatedPanelFactory _factory;
    public LicensingSurfaceRemovedTests(IsolatedPanelFactory factory) => _factory = factory;

    [Fact]
    public async Task Webhook_de_pagamento_nao_existe()
    {
        var client = _factory.CreateClient(new() { AllowAutoRedirect = false });

        var r = await client.PostAsync("/api/payment/webhook", new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
    }

    [Fact]
    public async Task Menu_do_painel_nao_oferece_licenca()
    {
        var layout = await File.ReadAllTextAsync(Path.Combine(RepoRoot(), "server", "RansomGuard.Server", "Components", "Layout", "MainLayout.razor"));

        Assert.DoesNotContain("/licenca", layout);
        Assert.False(File.Exists(Path.Combine(RepoRoot(), "server", "RansomGuard.Server", "Components", "Pages", "Licenca.razor")));
    }

    /// <summary>
    /// M4 (abertura): o convite para registrar o uso é só um link que o administrador escolhe abrir. O painel não faz
    /// chamada de rede por conta própria (N4: sem telemetria).
    /// </summary>
    [Fact]
    public async Task Convite_de_registro_de_uso_e_so_um_link_opcional()
    {
        var layout = await File.ReadAllTextAsync(Path.Combine(RepoRoot(), "server", "RansomGuard.Server", "Components", "Layout", "MainLayout.razor"));

        Assert.Contains("href=\"https://www.ransomguard.com.br/#registro\"", layout);
        Assert.Contains("target=\"_blank\"", layout);
        Assert.Contains("rel=\"noopener noreferrer\"", layout);
    }

    /// <summary>
    /// M4 (abertura): o catálogo assinado passa a sair do repositório público do projeto (pasta list/). O repositório
    /// de distribuição antigo é arquivado; servir dele congelaria o catálogo.
    /// </summary>
    [Fact]
    public void Origem_padrao_do_catalogo_e_o_repositorio_publico()
    {
        Assert.Equal("https://raw.githubusercontent.com/rodrigoimmaginario/ransomguard/main/list",
            RansomGuard.Server.Catalog.HttpCatalogOrigin.DefaultOriginUrl);
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "RansomGuard.sln"))) dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("raiz do repositório não encontrada");
    }
}
