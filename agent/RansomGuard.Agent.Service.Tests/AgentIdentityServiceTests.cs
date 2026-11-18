using System.Net;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using RansomGuard.Agent.Service.Windows;
using RansomGuard.Core.Auth;
using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Service.Tests;

/// <summary>Painel de mentira: grava o que o agente manda e responde o que o teste mandar.</summary>
internal sealed class FakePanel : HttpMessageHandler
{
    public List<(string Path, Dictionary<string, string> Headers, byte[] Body)> Requests { get; } = new();
    public Func<string, (HttpStatusCode Status, string Json)> Reply { get; set; } = _ => (HttpStatusCode.OK, "{}");

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? Array.Empty<byte>() : await request.Content.ReadAsByteArrayAsync(ct);
        Requests.Add((request.RequestUri!.AbsolutePath, request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value)), body));
        var (status, json) = Reply(request.RequestUri.AbsolutePath);
        return new HttpResponseMessage(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    }

    public HttpClient Client() => new(this) { BaseAddress = new Uri("https://painel.teste:5001") };
}

/// <summary>B1 — a identidade do agente no servidor monitorado: chave própria, protegida, enrolada uma vez.</summary>
[SupportedOSPlatform("windows")]
public sealed class AgentIdentityServiceTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rg-agent-id-" + Guid.NewGuid().ToString("N")[..10]);
    public AgentIdentityServiceTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    private AgentIdentity Identity(string server = "FS01") => new(_dir, server, NullLogger.Instance);

    private static AgentBatch Batch(string server = "FS01") =>
        new(server, DateTime.UtcNow, null, Array.Empty<FileEvent>(), Array.Empty<HostSignal>(), Array.Empty<Core.Incidents.AgentIncident>());

    [Fact]
    public void A_chave_e_criada_uma_vez_fica_protegida_em_disco_e_e_a_mesma_ao_reabrir()
    {
        var first = Identity();
        var second = Identity();

        Assert.Equal(first.Key.Fingerprint, second.Key.Fingerprint);
        var raw = File.ReadAllText(Path.Combine(_dir, AgentIdentity.KeyFileName));
        Assert.DoesNotContain(Convert.ToBase64String(first.Key.Seed), raw);
        Assert.StartsWith("RGP1:", raw);
    }

    /// <summary>
    /// O agente não pode parar de proteger o servidor porque um arquivo estragou: gera chave nova, guarda o arquivo
    /// antigo para análise e fica sem enrolamento — o painel recusa até o administrador enrolar de novo.
    /// </summary>
    [Fact]
    public void Chave_ilegivel_nao_derruba_o_agente_gera_outra_e_volta_a_exigir_enrolamento()
    {
        var first = Identity();
        first.MarkEnrolled();
        var path = Path.Combine(_dir, AgentIdentity.KeyFileName);
        File.WriteAllText(path, "RGP1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        var second = Identity();

        Assert.NotEqual(first.Key.Fingerprint, second.Key.Fingerprint);
        Assert.False(second.IsEnrolled);
        Assert.Contains(Directory.GetFiles(_dir), f => Path.GetFileName(f).StartsWith(AgentIdentity.KeyFileName + ".ilegivel-"));
    }

    [Fact]
    public void O_enrolamento_vale_para_a_chave_e_o_nome_em_que_foi_feito()
    {
        var identity = Identity();
        Assert.False(identity.IsEnrolled);

        identity.MarkEnrolled();

        Assert.True(Identity().IsEnrolled);
        Assert.False(Identity("FS02").IsEnrolled);            // o servidor mudou de nome: é outra identidade para o painel
        identity.ClearEnrollment();
        Assert.False(Identity().IsEnrolled);
    }

    [Fact]
    public async Task Com_token_o_agente_se_enrola_apresentando_a_chave_publica_e_descarta_o_token()
    {
        var panel = new FakePanel();
        var identity = Identity();
        string? token = "token-de-uso-unico";
        var enroller = new AgentEnroller(panel.Client(), identity, () => token, () => token = null, NullLogger<AgentEnroller>.Instance);

        Assert.True(await enroller.EnsureEnrolledAsync(CancellationToken.None));

        var request = Assert.Single(panel.Requests);
        Assert.Equal("/api/enroll", request.Path);
        using var sent = JsonDocument.Parse(request.Body);
        Assert.Equal("token-de-uso-unico", sent.RootElement.GetProperty("token").GetString());
        Assert.Equal("FS01", sent.RootElement.GetProperty("server").GetString());
        Assert.Equal(identity.Key.PublicKeyBase64, sent.RootElement.GetProperty("publicKey").GetString());
        Assert.DoesNotContain(Convert.ToBase64String(identity.Key.Seed), Encoding.UTF8.GetString(request.Body));
        Assert.True(identity.IsEnrolled);
        Assert.Null(token);                                    // o token saiu do registro

        Assert.True(await enroller.EnsureEnrolledAsync(CancellationToken.None));
        Assert.Single(panel.Requests);                         // enrolado: não pede de novo
    }

    [Fact]
    public async Task Agente_ja_enrolado_descarta_um_token_que_tenha_sobrado_sem_falar_com_o_painel()
    {
        var panel = new FakePanel();
        var identity = Identity();
        identity.MarkEnrolled();
        string? token = "token-informado-de-novo-na-atualizacao";
        var enroller = new AgentEnroller(panel.Client(), identity, () => token, () => token = null, NullLogger<AgentEnroller>.Instance);

        Assert.True(await enroller.EnsureEnrolledAsync(CancellationToken.None));

        Assert.Null(token);
        Assert.Empty(panel.Requests);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)] [InlineData(HttpStatusCode.Conflict)] [InlineData(HttpStatusCode.InternalServerError)]
    public async Task Enrolamento_recusado_deixa_o_agente_sem_identidade_no_painel_e_o_token_onde_estava(HttpStatusCode status)
    {
        var panel = new FakePanel { Reply = _ => (status, "{\"error\":\"recusado\"}") };
        var identity = Identity();
        string? token = "token";
        var enroller = new AgentEnroller(panel.Client(), identity, () => token, () => token = null, NullLogger<AgentEnroller>.Instance);

        Assert.False(await enroller.EnsureEnrolledAsync(CancellationToken.None));

        Assert.False(identity.IsEnrolled);
        Assert.Equal("token", token);
    }

    [Fact]
    public async Task Sem_token_e_sem_enrolamento_o_agente_nao_fala_com_o_painel()
    {
        var panel = new FakePanel();
        var identity = Identity();
        var enroller = new AgentEnroller(panel.Client(), identity, () => null, () => { }, NullLogger<AgentEnroller>.Instance);
        var sink = new HttpBatchSink(panel.Client(), identity, enroller, NullLogger<HttpBatchSink>.Instance);

        Assert.Null(await sink.SendAsync(Batch()));

        Assert.Empty(panel.Requests);                          // nem enrolamento, nem lote sem assinatura reconhecível
    }

    [Fact]
    public async Task Cada_lote_vai_assinado_com_a_chave_do_agente_sobre_o_corpo_exato()
    {
        var panel = new FakePanel();
        var identity = Identity();
        identity.MarkEnrolled();
        var enroller = new AgentEnroller(panel.Client(), identity, () => null, () => { }, NullLogger<AgentEnroller>.Instance);
        var sink = new HttpBatchSink(panel.Client(), identity, enroller, NullLogger<HttpBatchSink>.Instance);

        Assert.NotNull(await sink.SendAsync(Batch()));

        var request = Assert.Single(panel.Requests);
        Assert.Equal("/api/ingest", request.Path);
        Assert.Equal("FS01", request.Headers[BatchSignature.AgentHeader]);
        Assert.False(request.Headers.ContainsKey("X-RansomGuard-Token"));
        Assert.Equal(BatchSignatureResult.Valid, BatchSignature.Verify(identity.Key.PublicKey, "FS01",
            request.Headers[BatchSignature.TimestampHeader], request.Headers[BatchSignature.SignatureHeader], request.Body, DateTime.UtcNow));
        Assert.Equal("FS01", JsonDocument.Parse(request.Body).RootElement.GetProperty("server").GetString());
    }

    [Fact]
    public async Task Painel_que_nao_reconhece_o_agente_faz_ele_voltar_a_precisar_de_enrolamento()
    {
        var panel = new FakePanel { Reply = _ => (HttpStatusCode.Unauthorized, "{\"error\":\"Agente não enrolado neste painel.\",\"code\":\"not-enrolled\"}") };
        var identity = Identity();
        identity.MarkEnrolled();
        var enroller = new AgentEnroller(panel.Client(), identity, () => null, () => { }, NullLogger<AgentEnroller>.Instance);
        var sink = new HttpBatchSink(panel.Client(), identity, enroller, NullLogger<HttpBatchSink>.Instance);

        Assert.Null(await sink.SendAsync(Batch()));

        Assert.False(identity.IsEnrolled);
    }

    [Fact]
    public async Task Recusa_por_relogio_ou_assinatura_nao_apaga_o_enrolamento()
    {
        var panel = new FakePanel { Reply = _ => (HttpStatusCode.Unauthorized, "{\"error\":\"Relógio fora da janela\",\"code\":\"clock\"}") };
        var identity = Identity();
        identity.MarkEnrolled();
        var enroller = new AgentEnroller(panel.Client(), identity, () => null, () => { }, NullLogger<AgentEnroller>.Instance);
        var sink = new HttpBatchSink(panel.Client(), identity, enroller, NullLogger<HttpBatchSink>.Instance);

        Assert.Null(await sink.SendAsync(Batch()));

        Assert.True(identity.IsEnrolled);
    }

    [Fact]
    public void Enderecos_de_infraestrutura_incluem_os_do_proprio_servidor_e_o_painel()
    {
        var addresses = InfrastructureAddresses.Current("https://203.0.113.9:5001", refresh: true);

        Assert.Contains("203.0.113.9", addresses);
        Assert.Contains("127.0.0.1", addresses);
        Assert.DoesNotContain("203.0.113.77", addresses);
    }
}
