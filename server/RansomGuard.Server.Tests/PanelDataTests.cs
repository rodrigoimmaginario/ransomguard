using System.IO.Compression;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using RansomGuard.Server.Auth;
using RansomGuard.Server.Security;

namespace RansomGuard.Server.Tests;

/// <summary>A4 — onde o painel guarda banco, chave e segredos.</summary>
public class PanelPathsTests
{
    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.ToDictionary(v => v.Key, v => (string?)v.Value)).Build();

    [Fact]
    public void Instalado_guarda_os_dados_em_ProgramData_e_nao_ao_lado_do_executavel()
    {
        var paths = PanelPaths.Resolve(Config(), contentRoot: @"C:\Program Files\RansomGuard\Painel", development: false, programData: @"C:\ProgramData");

        Assert.Equal(@"C:\ProgramData\RansomGuard\Painel", paths.DataDirectory);
        Assert.Equal(@"C:\ProgramData\RansomGuard\Painel\ransomguard.db", paths.Database);
        Assert.Equal(@"C:\ProgramData\RansomGuard\Painel\install-key.json", paths.InstallKey);
        Assert.Equal(@"C:\ProgramData\RansomGuard\Painel\install-secrets.json", paths.InstallSecrets);
        Assert.Equal(@"C:\ProgramData\RansomGuard\Painel\catalog-cache", paths.CatalogCache);
        Assert.Equal(@"C:\ProgramData\RansomGuard\Painel\token-de-setup.txt", paths.SetupToken);
        Assert.True(paths.Managed);
    }

    [Fact]
    public void Em_desenvolvimento_fica_na_pasta_do_projeto_e_a_permissao_dela_nao_e_tocada()
    {
        var paths = PanelPaths.Resolve(Config(), contentRoot: @"C:\src\painel", development: true, programData: @"C:\ProgramData");

        Assert.Equal(@"C:\src\painel", paths.DataDirectory);
        Assert.Equal(@"C:\src\painel\ransomguard.db", paths.Database);
        Assert.False(paths.Managed);
    }

    [Fact]
    public void Pasta_de_dados_configurada_vale_tambem_em_desenvolvimento()
    {
        var paths = PanelPaths.Resolve(Config(("Panel:DataDir", @"D:\rg")), contentRoot: @"C:\src\painel", development: true, programData: @"C:\ProgramData");

        Assert.Equal(@"D:\rg", paths.DataDirectory);
        Assert.Equal(@"D:\rg\catalog-cache", paths.CatalogCache);
        Assert.True(paths.Managed);
    }

    [Fact]
    public void Caminhos_individuais_configurados_prevalecem_e_o_token_acompanha_os_segredos()
    {
        var paths = PanelPaths.Resolve(
            Config(("Database:Path", @"E:\db\x.db"), ("InstallKey:Path", @"E:\k\key.json"), ("InstallSecrets:Path", @"E:\s\sec.json")),
            contentRoot: @"C:\app", development: false, programData: @"C:\ProgramData");

        Assert.Equal(@"E:\db\x.db", paths.Database);
        Assert.Equal(@"E:\k\key.json", paths.InstallKey);
        Assert.Equal(@"E:\s\sec.json", paths.InstallSecrets);
        Assert.Equal(@"E:\s\token-de-setup.txt", paths.SetupToken);
    }
}

/// <summary>B2 — o que fica em disco não é legível, e um arquivo que não abre nunca é trocado por um novo.</summary>
public sealed class ProtectedSecretsTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rg-b2-" + Guid.NewGuid().ToString("N"));
    public ProtectedSecretsTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    [Fact]
    public void Conteudo_gravado_nao_aparece_no_arquivo_e_volta_igual()
    {
        var path = Path.Combine(_dir, "a.json");

        ProtectedFile.Write(path, "{\"Seed\":\"segredo-muito-reconhecivel\"}");

        var raw = File.ReadAllText(path);
        Assert.DoesNotContain("segredo-muito-reconhecivel", raw);
        Assert.DoesNotContain("Seed", raw);
        Assert.True(ProtectedFile.IsProtected(path));
        Assert.Equal("{\"Seed\":\"segredo-muito-reconhecivel\"}", ProtectedFile.Read(path));
        Assert.Equal(new[] { "a.json" }, Directory.GetFiles(_dir).Select(Path.GetFileName));   // sem arquivo temporário para trás
    }

    [Fact]
    public void Arquivo_que_nao_existe_e_nulo_e_arquivo_adulterado_e_erro()
    {
        Assert.Null(ProtectedFile.Read(Path.Combine(_dir, "nao-existe.json")));

        var path = Path.Combine(_dir, "ruim.json");
        ProtectedFile.Write(path, "conteudo");
        var raw = File.ReadAllText(path);
        File.WriteAllText(path, raw[..^8] + "AAAAAAA=");

        Assert.Throws<InvalidDataException>(() => ProtectedFile.Read(path));
    }

    [Fact]
    public void Texto_de_versao_anterior_e_lido_e_regravado_protegido()
    {
        var path = Path.Combine(_dir, "antigo.json");
        File.WriteAllText(path, "{\"x\":1}");
        Assert.False(ProtectedFile.IsProtected(path));

        Assert.Equal("{\"x\":1}", ProtectedFile.ReadAndSeal(path));

        Assert.True(ProtectedFile.IsProtected(path));
        Assert.Equal("{\"x\":1}", ProtectedFile.Read(path));
    }

    [Fact]
    public async Task Chave_da_instalacao_nao_fica_legivel_em_disco_e_sobrevive_a_reabrir()
    {
        var path = Path.Combine(_dir, "install-key.json");

        var created = await new FileInstallKeyStore(path).GetOrCreateAsync();

        var raw = await File.ReadAllTextAsync(path);
        Assert.DoesNotContain(Convert.ToBase64String(created.Seed), raw);
        Assert.True(ProtectedFile.IsProtected(path));
        var reopened = await new FileInstallKeyStore(path).GetOrCreateAsync();
        Assert.Equal(created.PublicKeyFileContent, reopened.PublicKeyFileContent);
    }

    [Fact]
    public async Task Chave_em_texto_de_versao_anterior_continua_a_mesma_e_passa_a_ficar_protegida()
    {
        var path = Path.Combine(_dir, "install-key.json");
        var old = InstallSigningKey.Generate();
        var seed = Convert.ToBase64String(old.Seed);
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new { Seed = seed, KeyId = Convert.ToBase64String(old.KeyId), CreatedAt = DateTime.UtcNow }));

        var loaded = await new FileInstallKeyStore(path).GetOrCreateAsync();

        Assert.Equal(old.PublicKeyFileContent, loaded.PublicKeyFileContent);   // os agentes fixaram esta chave
        Assert.DoesNotContain(seed, await File.ReadAllTextAsync(path));
        Assert.True(ProtectedFile.IsProtected(path));
    }

    /// <summary>
    /// Trocar a chave em silêncio faria todos os agentes recusarem a política sem que ninguém soubesse por quê — e
    /// apagaria a única cópia do que talvez ainda fosse recuperável.
    /// </summary>
    [Fact]
    public async Task Chave_que_nao_abre_nunca_e_substituida_por_uma_nova()
    {
        var path = Path.Combine(_dir, "install-key.json");
        await new FileInstallKeyStore(path).GetOrCreateAsync();
        var raw = await File.ReadAllTextAsync(path);
        var broken = raw[..^8] + "AAAAAAA=";
        await File.WriteAllTextAsync(path, broken);

        await Assert.ThrowsAsync<InvalidDataException>(() => new FileInstallKeyStore(path).GetOrCreateAsync());

        Assert.Equal(broken, await File.ReadAllTextAsync(path));
    }

    [Fact]
    public void Segredos_da_instalacao_nao_ficam_legiveis_e_o_certificado_continua_utilizavel()
    {
        var path = Path.Combine(_dir, "install-secrets.json");

        var created = new InstallSecretsStore(path).GetOrCreate("FS01", DateTime.UtcNow);

        var raw = File.ReadAllText(path);
        Assert.DoesNotContain(created.SetupToken, raw);
        Assert.DoesNotContain(created.CertificatePassword, raw);
        Assert.DoesNotContain("CertificatePfxBase64", raw);
        var store = new InstallSecretsStore(path);
        var reopened = store.GetOrCreate("FS01", DateTime.UtcNow.AddDays(1));
        Assert.Equal(created.SetupToken, reopened.SetupToken);
        using var cert = store.LoadCertificate(reopened);
        Assert.True(cert.HasPrivateKey);
    }

    [Fact]
    public void Segredos_em_texto_de_versao_anterior_sao_mantidos_e_protegidos_e_os_que_nao_abrem_param_o_painel()
    {
        var path = Path.Combine(_dir, "install-secrets.json");
        var old = new InstallSecrets { IngestSecret = "ingest-antigo-0123456789", SetupToken = "token-antigo", CreatedAt = DateTime.UtcNow };
        File.WriteAllText(path, JsonSerializer.Serialize(old));

        var loaded = new InstallSecretsStore(path).GetOrCreate("FS01", DateTime.UtcNow);

        Assert.Equal("ingest-antigo-0123456789", loaded.IngestSecret);
        Assert.DoesNotContain("ingest-antigo-0123456789", File.ReadAllText(path));

        var broken = File.ReadAllText(path)[..^8] + "AAAAAAA=";
        File.WriteAllText(path, broken);
        Assert.Throws<InvalidDataException>(() => new InstallSecretsStore(path).GetOrCreate("FS01", DateTime.UtcNow));
        Assert.Equal(broken, File.ReadAllText(path));
    }
}

/// <summary>O token de primeira execução existe em arquivo só enquanto serve para alguma coisa.</summary>
public sealed class SetupTokenFileTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rg-token-" + Guid.NewGuid().ToString("N"));
    public SetupTokenFileTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    private static async Task<(HttpClient Client, string SetupPage, string Antiforgery)> OpenSetupAsync(IsolatedPanelFactory factory)
    {
        var client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var page = await (await client.GetAsync("/setup")).Content.ReadAsStringAsync();
        return (client, page, Regex.Match(page, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
    }

    private static Task<HttpResponseMessage> CreateAccountAsync(HttpClient client, string antiforgery, string token) =>
        client.PostAsync("/auth/setup", new FormUrlEncodedContent(new Dictionary<string, string>
            { ["__RequestVerificationToken"] = antiforgery, ["username"] = "admin", ["password"] = "senha-forte-123", ["token"] = token }));

    [Fact]
    public void Sem_conta_o_arquivo_traz_o_token_e_com_conta_ele_some()
    {
        var path = Path.Combine(_dir, "token-de-setup.txt");

        SetupTokenFile.Sync(path, "tok-123", accountExists: false);
        Assert.Contains("tok-123", File.ReadAllText(path));

        SetupTokenFile.Sync(path, "tok-123", accountExists: true);
        Assert.False(File.Exists(path));

        SetupTokenFile.Sync(path, "tok-123", accountExists: true);   // repetir não falha
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task No_painel_o_token_fica_no_arquivo_ate_a_conta_ser_criada()
    {
        using var factory = new IsolatedPanelFactory();
        var (client, setupPage, antiforgery) = await OpenSetupAsync(factory);
        var tokenFile = Path.Combine(factory.DataDir, "token-de-setup.txt");

        Assert.Contains(factory.SetupToken, await File.ReadAllTextAsync(tokenFile));
        Assert.Contains("token-de-setup.txt", setupPage);                        // a tela diz onde procurar

        var created = await CreateAccountAsync(client, antiforgery, factory.SetupToken);

        Assert.Equal(HttpStatusCode.Redirect, created.StatusCode);
        Assert.False(File.Exists(tokenFile));
    }

    /// <summary>O arquivo protegido só abre na máquina de origem; o backup precisa servir para restaurar em outra.</summary>
    [Fact]
    public async Task Backup_leva_chave_e_segredos_em_forma_que_outra_instalacao_consegue_abrir()
    {
        using var factory = new IsolatedPanelFactory();
        var (client, _, antiforgery) = await OpenSetupAsync(factory);
        await CreateAccountAsync(client, antiforgery, factory.SetupToken);
        var current = await factory.Services.GetRequiredService<IInstallKeyStore>().GetOrCreateAsync();

        var backup = await client.GetAsync("/backup/ransomguard-backup.zip");

        Assert.Equal(HttpStatusCode.OK, backup.StatusCode);
        var keyCopy = Path.Combine(_dir, "install-key.json");
        var secretsCopy = Path.Combine(_dir, "install-secrets.json");
        using (var zip = new ZipArchive(await backup.Content.ReadAsStreamAsync()))
        {
            Assert.Contains(zip.Entries, e => e.Name == "ransomguard.db");
            zip.GetEntry("install-key.json")!.ExtractToFile(keyCopy);
            zip.GetEntry("install-secrets.json")!.ExtractToFile(secretsCopy);
        }
        Assert.False(ProtectedFile.IsProtected(keyCopy));

        var restored = await new FileInstallKeyStore(keyCopy).GetOrCreateAsync();
        Assert.Equal(current.PublicKeyFileContent, restored.PublicKeyFileContent);
        Assert.True(ProtectedFile.IsProtected(keyCopy));                         // ao restaurar, volta a ficar protegida
        Assert.Equal(factory.Services.GetRequiredService<InstallSecrets>().CertificateThumbprint,
            new InstallSecretsStore(secretsCopy).GetOrCreate("x", DateTime.UtcNow).CertificateThumbprint);
    }
}
