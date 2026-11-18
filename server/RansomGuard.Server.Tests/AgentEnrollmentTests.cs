using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using RansomGuard.Agent;
using RansomGuard.Core.Auth;
using RansomGuard.Core.Detection;
using RansomGuard.Server.Agents;
using RansomGuard.Server.Auth;
using RansomGuard.Server.Data;
using RansomGuard.Server.Policy;

namespace RansomGuard.Server.Tests;

/// <summary>
/// B1 — enrolamento por agente. O token só serve para apresentar a chave do agente ao painel; quem autentica os
/// lotes, dali em diante, é a chave que nunca sai do servidor monitorado.
/// </summary>
public class AgentEnrollmentServiceTests : DbTestBase
{
    private static readonly DateTime T0 = new(2026, 11, 16, 12, 0, 0, DateTimeKind.Utc);
    private readonly AgentEnrollmentService _svc;

    public AgentEnrollmentServiceTests()
    {
        AgentEnrollmentService.EnsureSchemaAsync(Db).GetAwaiter().GetResult();
        _svc = new AgentEnrollmentService(Db);
    }

    private static string Key() => AgentKey.Generate().PublicKeyBase64;

    [Fact]
    public async Task Token_de_uso_unico_enrola_um_servidor_e_nao_serve_para_o_segundo()
    {
        var token = await _svc.CreateTokenAsync(maxUses: 1, TimeSpan.FromHours(1), "admin", T0);

        Assert.Equal(EnrollOutcome.Enrolled, await _svc.EnrollAsync(token, "FS01", Key(), "10.0.0.5", T0.AddMinutes(1)));
        Assert.Equal(EnrollOutcome.InvalidToken, await _svc.EnrollAsync(token, "FS02", Key(), "10.0.0.6", T0.AddMinutes(2)));

        var agent = await _svc.FindAsync("fs01");
        Assert.NotNull(agent);
        Assert.Equal("FS01", agent!.Server);
        Assert.Null(await _svc.FindAsync("FS02"));
    }

    [Fact]
    public async Task Token_para_varios_servidores_vale_ate_o_limite_e_ate_expirar()
    {
        var token = await _svc.CreateTokenAsync(maxUses: 2, TimeSpan.FromHours(1), "admin", T0);

        Assert.Equal(EnrollOutcome.Enrolled, await _svc.EnrollAsync(token, "FS01", Key(), "", T0));
        Assert.Equal(EnrollOutcome.Enrolled, await _svc.EnrollAsync(token, "FS02", Key(), "", T0));
        Assert.Equal(EnrollOutcome.InvalidToken, await _svc.EnrollAsync(token, "FS03", Key(), "", T0));

        var late = await _svc.CreateTokenAsync(maxUses: 5, TimeSpan.FromHours(1), "admin", T0);
        Assert.Equal(EnrollOutcome.InvalidToken, await _svc.EnrollAsync(late, "FS04", Key(), "", T0.AddHours(1).AddSeconds(1)));
        Assert.Equal(EnrollOutcome.InvalidToken, await _svc.EnrollAsync("token-que-nunca-existiu", "FS05", Key(), "", T0));
        Assert.Equal(EnrollOutcome.InvalidToken, await _svc.EnrollAsync("", "FS05", Key(), "", T0));
    }

    [Fact]
    public async Task Nome_ja_enrolado_nao_e_tomado_por_outra_chave_nem_com_token_valido()
    {
        var first = Key();
        Assert.Equal(EnrollOutcome.Enrolled, await _svc.EnrollAsync(await _svc.CreateTokenAsync(1, TimeSpan.FromHours(1), "admin", T0), "FS01", first, "", T0));
        var fresh = await _svc.CreateTokenAsync(1, TimeSpan.FromHours(1), "admin", T0);

        Assert.Equal(EnrollOutcome.NameTaken, await _svc.EnrollAsync(fresh, "fs01", Key(), "", T0));
        Assert.Equal(first, (await _svc.FindAsync("FS01"))!.PublicKey);

        // O token não foi gasto pela tentativa recusada, e o mesmo agente repetindo o pedido não gasta outro.
        Assert.Equal(EnrollOutcome.AlreadyEnrolled, await _svc.EnrollAsync("qualquer-coisa", "FS01", first, "", T0));
        Assert.Equal(EnrollOutcome.Enrolled, await _svc.EnrollAsync(fresh, "FS02", Key(), "", T0));
    }

    [Theory]
    [InlineData("", true)] [InlineData("FS 01", true)] [InlineData("FS01;x", true)] [InlineData("FS01", false)]
    public async Task Pedido_malformado_e_recusado_sem_gastar_o_token(string server, bool validKey)
    {
        var token = await _svc.CreateTokenAsync(1, TimeSpan.FromHours(1), "admin", T0);

        Assert.Equal(EnrollOutcome.InvalidRequest, await _svc.EnrollAsync(token, server, validKey ? Key() : "AAAA", "", T0));
        Assert.Equal(EnrollOutcome.Enrolled, await _svc.EnrollAsync(token, "FS09", Key(), "", T0));
    }

    [Fact]
    public async Task O_banco_guarda_so_o_resumo_do_token_e_os_limites_sao_impostos()
    {
        var token = await _svc.CreateTokenAsync(maxUses: 100_000, TimeSpan.FromDays(365), "admin", T0);

        var stored = await Db.EnrollmentTokens.AsNoTracking().SingleAsync();
        Assert.DoesNotContain(token, stored.TokenHash);
        Assert.Equal(AgentEnrollmentService.MaxTokenUses, stored.MaxUses);
        Assert.Equal(T0 + AgentEnrollmentService.MaxTokenLifetime, stored.ExpiresAt);
        Assert.True(token.Length >= 30);
    }

    [Fact]
    public async Task Revogar_tira_a_identidade_e_o_servidor_precisa_de_token_novo()
    {
        var key = Key();
        await _svc.EnrollAsync(await _svc.CreateTokenAsync(1, TimeSpan.FromHours(1), "admin", T0), "FS01", key, "", T0);

        Assert.True(await _svc.RevokeAsync("fs01"));
        Assert.False(await _svc.RevokeAsync("fs01"));
        Assert.Null(await _svc.FindAsync("FS01"));
        Assert.Equal(EnrollOutcome.InvalidToken, await _svc.EnrollAsync("sem-token", "FS01", key, "", T0));
        Assert.Equal(EnrollOutcome.Enrolled, await _svc.EnrollAsync(await _svc.CreateTokenAsync(1, TimeSpan.FromHours(1), "admin", T0), "FS01", Key(), "", T0));
    }

    [Fact]
    public void Lote_repetido_e_reconhecido_dentro_da_janela()
    {
        var replay = new BatchReplayGuard();

        Assert.True(replay.TryRegister("FS01", "assinatura-1", T0));
        Assert.False(replay.TryRegister("fs01", "assinatura-1", T0.AddSeconds(30)));
        Assert.True(replay.TryRegister("FS01", "assinatura-2", T0.AddSeconds(30)));
        Assert.True(replay.TryRegister("FS02", "assinatura-1", T0.AddSeconds(30)));
        // Passada a janela dupla, a assinatura já seria recusada pelo relógio; a memória pode esquecê-la.
        Assert.True(replay.TryRegister("FS01", "assinatura-1", T0 + BatchSignature.MaxSkew * 2 + TimeSpan.FromSeconds(1)));
    }
}

/// <summary>O que o painel aceita e recusa pela rede, com o painel inteiro em processo.</summary>
public sealed class AgentIdentityHttpTests : IClassFixture<IsolatedPanelFactory>
{
    private readonly IsolatedPanelFactory _factory;
    public AgentIdentityHttpTests(IsolatedPanelFactory factory) => _factory = factory;

    private static AgentBatch Batch(string server) =>
        new(server, DateTime.UtcNow, null, Array.Empty<FileEvent>(), Array.Empty<HostSignal>(), Array.Empty<Core.Incidents.AgentIncident>());

    private static HttpRequestMessage Signed(AgentKey key, string agent, AgentBatch batch, DateTime? at = null, byte[]? overrideBody = null)
    {
        var body = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(batch, System.Text.Json.JsonSerializerOptions.Web);
        var ts = BatchSignature.Timestamp(at ?? DateTime.UtcNow);
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/ingest") { Content = new ByteArrayContent(overrideBody ?? body) };
        request.Content.Headers.ContentType = new("application/json");
        request.Headers.Add(BatchSignature.AgentHeader, agent);
        request.Headers.Add(BatchSignature.TimestampHeader, ts);
        request.Headers.Add(BatchSignature.SignatureHeader, BatchSignature.Sign(key, agent, ts, body));
        return request;
    }

    private async Task<AgentKey> EnrollAsync(string server)
    {
        var key = AgentKey.Generate();
        using var scope = _factory.Services.CreateScope();
        var svc = scope.ServiceProvider.GetRequiredService<AgentEnrollmentService>();
        var token = await svc.CreateTokenAsync(1, TimeSpan.FromHours(1), "teste", DateTime.UtcNow);
        Assert.Equal(EnrollOutcome.Enrolled, await svc.EnrollAsync(token, server, key.PublicKeyBase64, "teste", DateTime.UtcNow));
        return key;
    }

    [Fact]
    public async Task Lote_sem_assinatura_ou_de_agente_desconhecido_e_recusado()
    {
        var client = _factory.CreateClient();

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/ingest", Batch("FS-X1"))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Signed(AgentKey.Generate(), "FS-X1", Batch("FS-X1")))).StatusCode);

        // O segredo compartilhado das versões anteriores não abre mais nada.
        var legacy = new HttpRequestMessage(HttpMethod.Post, "/api/ingest") { Content = JsonContent.Create(Batch("FS-X1")) };
        legacy.Headers.Add("X-RansomGuard-Token", "test-ingest-secret");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(legacy)).StatusCode);
    }

    [Fact]
    public async Task Agente_enrolado_envia_lote_assinado_e_o_mesmo_pedido_repetido_e_recusado()
    {
        var key = await EnrollAsync("FS-A1");
        var client = _factory.CreateClient();
        var at = DateTime.UtcNow;
        var batch = Batch("FS-A1");

        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Signed(key, "FS-A1", batch, at))).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await client.SendAsync(Signed(key, "FS-A1", batch, at))).StatusCode);          // captura reenviada
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Signed(key, "FS-A1", batch, at.AddMilliseconds(5)))).StatusCode);   // envio novo do agente
    }

    /// <summary>
    /// O ponto do achado: com o segredo único, quem o lesse num servidor forjava batimento de um agente morto e
    /// incidente em nome de qualquer outro.
    /// </summary>
    [Fact]
    public async Task Um_agente_nao_fala_em_nome_de_outro_servidor()
    {
        var keyA = await EnrollAsync("FS-B1");
        await EnrollAsync("FS-B2");
        var client = _factory.CreateClient();

        // Assina como FS-B1, mas o lote diz ser do FS-B2.
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(Signed(keyA, "FS-B1", Batch("FS-B2")))).StatusCode);
        // Diz ser o FS-B2 no cabeçalho, com a chave do FS-B1.
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Signed(keyA, "FS-B2", Batch("FS-B2")))).StatusCode);
    }

    [Fact]
    public async Task Corpo_trocado_depois_da_assinatura_relogio_fora_da_janela_e_agente_revogado_sao_recusados()
    {
        var key = await EnrollAsync("FS-C1");
        var client = _factory.CreateClient();
        var other = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(Batch("FS-C1") with { At = DateTime.UtcNow.AddDays(1) }, System.Text.Json.JsonSerializerOptions.Web);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Signed(key, "FS-C1", Batch("FS-C1"), overrideBody: other))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Signed(key, "FS-C1", Batch("FS-C1"), at: DateTime.UtcNow.AddMinutes(-30)))).StatusCode);

        using (var scope = _factory.Services.CreateScope())
            Assert.True(await scope.ServiceProvider.GetRequiredService<AgentEnrollmentService>().RevokeAsync("FS-C1"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Signed(key, "FS-C1", Batch("FS-C1")))).StatusCode);
    }

    [Fact]
    public async Task Enrolamento_pela_rede_exige_token_valido_e_o_token_de_uso_unico_nao_se_repete()
    {
        var client = _factory.CreateClient();
        string token;
        using (var scope = _factory.Services.CreateScope())
            token = await scope.ServiceProvider.GetRequiredService<AgentEnrollmentService>().CreateTokenAsync(1, TimeSpan.FromHours(1), "teste", DateTime.UtcNow);
        var key = AgentKey.Generate();

        var refused = await client.PostAsJsonAsync("/api/enroll", new { token = "errado", server = "FS-D1", publicKey = key.PublicKeyBase64 });
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);

        var accepted = await client.PostAsJsonAsync("/api/enroll", new { token, server = "FS-D1", publicKey = key.PublicKeyBase64 });
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Contains(key.Fingerprint, await accepted.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Signed(key, "FS-D1", Batch("FS-D1")))).StatusCode);

        var reused = await client.PostAsJsonAsync("/api/enroll", new { token, server = "FS-D2", publicKey = AgentKey.Generate().PublicKeyBase64 });
        Assert.Equal(HttpStatusCode.Unauthorized, reused.StatusCode);
        var taken = await client.PostAsJsonAsync("/api/enroll", new { token, server = "FS-D1", publicKey = AgentKey.Generate().PublicKeyBase64 });
        Assert.Equal(HttpStatusCode.Conflict, taken.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/enroll", new { token, server = "a b", publicKey = "x" })).StatusCode);
    }
}

/// <summary>A tela em que o administrador gera o token e vê quem está enrolado.</summary>
public sealed class AgentsPageHttpTests : IClassFixture<IsolatedPanelFactory>
{
    private readonly IsolatedPanelFactory _factory;
    public AgentsPageHttpTests(IsolatedPanelFactory factory) => _factory = factory;

    private static string Antiforgery(string html) => Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;

    private async Task<HttpClient> AdminAsync()
    {
        var c = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var setup = await (await c.GetAsync("/setup")).Content.ReadAsStringAsync();
        await c.PostAsync("/auth/setup", new FormUrlEncodedContent(new Dictionary<string, string>
            { ["__RequestVerificationToken"] = Antiforgery(setup), ["username"] = "admin", ["password"] = "senha-forte-123", ["token"] = _factory.SetupToken }));
        var login = await (await c.GetAsync("/login")).Content.ReadAsStringAsync();
        await c.PostAsync("/auth/login", new FormUrlEncodedContent(new Dictionary<string, string>
            { ["__RequestVerificationToken"] = Antiforgery(login), ["username"] = "admin", ["password"] = "senha-forte-123" }));
        return c;
    }

    [Fact]
    public async Task Anonimo_nao_abre_a_tela_de_agentes()
    {
        var c = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var response = await c.GetAsync("/agentes");

        Assert.True(response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden, response.StatusCode.ToString());
    }

    [Fact]
    public async Task Admin_gera_token_ve_o_comando_uma_vez_e_o_token_enrola_um_agente_que_passa_a_aparecer_na_tela()
    {
        var admin = await AdminAsync();
        var page = await (await admin.GetAsync("/agentes")).Content.ReadAsStringAsync();
        Assert.DoesNotContain("ENROLLTOKEN=", page);

        var posted = await admin.PostAsync("/agentes", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["_handler"] = "novo-token", ["__RequestVerificationToken"] = Antiforgery(page), ["Form.MaxUses"] = "1", ["Form.Hours"] = "2"
        }));
        var html = await posted.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, posted.StatusCode);
        var token = Regex.Match(html, "ENROLLTOKEN=([A-Za-z0-9_\\-]+)").Groups[1].Value;
        Assert.True(token.Length >= 30, "a tela não mostrou o comando com o token");
        Assert.Contains("msiexec", html);
        Assert.DoesNotContain("INGESTSECRET", html);

        var key = AgentKey.Generate();
        var enrolled = await _factory.CreateClient().PostAsJsonAsync("/api/enroll", new { token, server = "FS-UI1", publicKey = key.PublicKeyBase64 });
        Assert.Equal(HttpStatusCode.OK, enrolled.StatusCode);

        var after = await (await admin.GetAsync("/agentes")).Content.ReadAsStringAsync();
        Assert.Contains("FS-UI1", after);
        Assert.Contains(key.Fingerprint, after);
        Assert.DoesNotContain(token, after);                       // o token só aparece na resposta que o criou

        using var scope = _factory.Services.CreateScope();
        var audit = scope.ServiceProvider.GetRequiredService<RansomGuardDb>().OperatorAudit.Select(a => a.Action).ToList();
        Assert.Contains("agent.token", audit);
        Assert.Contains("agent.enroll", audit);
    }

    [Fact]
    public async Task A_tela_inicial_nao_mostra_mais_segredo_e_aponta_para_a_tela_de_agentes()
    {
        var admin = await AdminAsync();

        var home = await (await admin.GetAsync("/")).Content.ReadAsStringAsync();

        Assert.DoesNotContain("INGESTSECRET", home);
        Assert.Contains("/agentes", home);
    }
}

/// <summary>Guarda da blocklist no painel: o que nunca entra, venha de onde vier.</summary>
public sealed class BlocklistGuardTests : IDisposable
{
    private static readonly DateTime T0 = new(2026, 11, 16, 12, 0, 0, DateTimeKind.Utc);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rg-b1-" + Guid.NewGuid().ToString("N"));
    private readonly SqliteConnection _conn;
    private readonly RansomGuardDb _db;
    private readonly AgentPolicyService _svc;

    public BlocklistGuardTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:"); _conn.Open();
        _db = new RansomGuardDb(new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite(_conn).Options);
        _db.Database.EnsureCreated();
        AgentPolicyService.EnsureSchemaAsync(_db).GetAwaiter().GetResult();
        AgentEnrollmentService.EnsureSchemaAsync(_db).GetAwaiter().GetResult();
        _svc = new AgentPolicyService(_db, new FileInstallKeyStore(Path.Combine(_dir, "k.json")),
            ownAddresses: () => new HashSet<string> { "10.0.0.50" });
    }

    public void Dispose() { _db.Dispose(); _conn.Dispose(); if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    [Fact]
    public async Task O_endereco_do_proprio_painel_nunca_entra_na_blocklist()
    {
        Assert.False(await _svc.AddToNetworkBlocklistAsync("10.0.0.50", T0));
        Assert.True(await _svc.AddToNetworkBlocklistAsync("10.0.9.66", T0));
    }

    [Fact]
    public async Task O_endereco_de_onde_um_agente_enrolado_fala_nunca_entra_na_blocklist()
    {
        var agents = new AgentEnrollmentService(_db);
        await agents.EnrollAsync(await agents.CreateTokenAsync(1, TimeSpan.FromHours(1), "admin", T0), "FS01", AgentKey.Generate().PublicKeyBase64, "10.0.0.21", T0);
        await agents.TouchAddressAsync("FS01", "10.0.0.22");

        Assert.False(await _svc.AddToNetworkBlocklistAsync("10.0.0.22", T0));   // um file server condenado derrubaria os demais
        Assert.True(await _svc.AddToNetworkBlocklistAsync("10.0.0.21", T0));    // o endereço antigo já não é dele
    }

    [Fact]
    public async Task Ha_teto_de_enderecos_ativos_na_blocklist()
    {
        for (var i = 0; i < AgentPolicyService.MaxBlocklistEntries; i++)
            Assert.True(await _svc.AddToNetworkBlocklistAsync($"10.1.{i / 250}.{i % 250 + 1}", T0));

        Assert.False(await _svc.AddToNetworkBlocklistAsync("10.2.0.1", T0));
        Assert.True(await _svc.AddToNetworkBlocklistAsync("10.2.0.1", T0 + NetworkBlocklist.Ttl + TimeSpan.FromMinutes(1)));   // os antigos expiraram
    }
}
