using System.Text;
using RansomGuard.Core.Auth;
using RansomGuard.Core.Response;

namespace RansomGuard.Core.Tests;

/// <summary>
/// B1 — cada agente tem a própria chave e assina cada lote. Quem lê o registro de um servidor não ganha mais o poder
/// de falar em nome de todos os outros.
/// </summary>
public class BatchSignatureTests
{
    private static readonly DateTime Now = new(2026, 11, 16, 12, 0, 0, DateTimeKind.Utc);
    private static readonly byte[] Body = Encoding.UTF8.GetBytes("{\"server\":\"FS01\",\"events\":[]}");

    private static (AgentKey Key, string Timestamp, string Signature) Signed(string agent = "FS01", DateTime? at = null, byte[]? body = null)
    {
        var key = AgentKey.Generate();
        var ts = BatchSignature.Timestamp(at ?? Now);
        return (key, ts, BatchSignature.Sign(key, agent, ts, body ?? Body));
    }

    [Fact]
    public void Lote_assinado_pelo_proprio_agente_confere()
    {
        var (key, ts, sig) = Signed();

        Assert.Equal(BatchSignatureResult.Valid, BatchSignature.Verify(key.PublicKey, "FS01", ts, sig, Body, Now.AddSeconds(20)));
        Assert.Equal(BatchSignatureResult.Valid, BatchSignature.Verify(key.PublicKey, "fs01", ts, sig, Body, Now));   // nome sem diferenciar maiúsculas
    }

    [Fact]
    public void Corpo_alterado_outro_nome_ou_outra_chave_nao_conferem()
    {
        var (key, ts, sig) = Signed();
        var tampered = Encoding.UTF8.GetBytes("{\"server\":\"FS01\",\"events\":[1]}");

        Assert.Equal(BatchSignatureResult.BadSignature, BatchSignature.Verify(key.PublicKey, "FS01", ts, sig, tampered, Now));
        Assert.Equal(BatchSignatureResult.BadSignature, BatchSignature.Verify(key.PublicKey, "FS02", ts, sig, Body, Now));
        Assert.Equal(BatchSignatureResult.BadSignature, BatchSignature.Verify(AgentKey.Generate().PublicKey, "FS01", ts, sig, Body, Now));
    }

    [Fact]
    public void Assinatura_velha_ou_do_futuro_e_recusada_mesmo_sendo_autentica()
    {
        var (key, ts, sig) = Signed(at: Now);

        Assert.Equal(BatchSignatureResult.Expired, BatchSignature.Verify(key.PublicKey, "FS01", ts, sig, Body, Now + BatchSignature.MaxSkew + TimeSpan.FromSeconds(1)));
        Assert.Equal(BatchSignatureResult.Expired, BatchSignature.Verify(key.PublicKey, "FS01", ts, sig, Body, Now - BatchSignature.MaxSkew - TimeSpan.FromSeconds(1)));
        Assert.Equal(BatchSignatureResult.Valid, BatchSignature.Verify(key.PublicKey, "FS01", ts, sig, Body, Now + BatchSignature.MaxSkew));
    }

    [Theory]
    [InlineData("", "AAAA")] [InlineData("ontem", "AAAA")] [InlineData("2026-11-16T12:00:00Z", "")] [InlineData("2026-11-16T12:00:00Z", "nao-e-base64!")]
    [InlineData("2026-11-16T12:00:00Z", "AAAA")]
    public void Cabecalho_malformado_nunca_confere(string timestamp, string signature)
    {
        var result = BatchSignature.Verify(AgentKey.Generate().PublicKey, "FS01", timestamp, signature, Body, Now);

        Assert.NotEqual(BatchSignatureResult.Valid, result);
    }

    [Fact]
    public void A_chave_e_reconstruida_da_semente_e_a_impressao_digital_e_estavel()
    {
        var key = AgentKey.Generate();
        var again = AgentKey.FromSeed(key.Seed);

        Assert.Equal(key.PublicKey, again.PublicKey);
        Assert.Equal(key.Fingerprint, again.Fingerprint);
        Assert.Equal(16, key.Fingerprint.Length);
        Assert.NotEqual(key.Fingerprint, AgentKey.Generate().Fingerprint);
        Assert.True(AgentKey.IsValidPublicKey(key.PublicKeyBase64));
        Assert.False(AgentKey.IsValidPublicKey("AAAA"));
        Assert.False(AgentKey.IsValidPublicKey("não é base64"));
    }

    [Theory]
    [InlineData("FS01", true)] [InlineData("srv-arquivos_02.corp", true)] [InlineData("", false)] [InlineData("a b", false)]
    [InlineData("FS01;drop", false)] [InlineData("*", false)] [InlineData("../x", false)]
    public void Nome_de_servidor_aceito_no_enrolamento(string name, bool ok)
        => Assert.Equal(ok, AgentKey.IsValidServerName(name));

    [Fact]
    public void Postura_de_transporte_avisa_quando_o_agente_ainda_nao_tem_identidade_no_painel()
    {
        Assert.True(TransportPosture.Evaluate("https://painel.corp:5001", enrolled: true).Secure);

        var pending = TransportPosture.Evaluate("https://painel.corp:5001", enrolled: false);
        Assert.False(pending.Secure);
        Assert.Contains(pending.Warnings, w => w.Contains("enrol", StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>
/// Guarda da blocklist no agente: nenhum incidente — verdadeiro, forjado ou vindo de outro servidor — faz o agente
/// bloquear o próprio gateway, o servidor de nomes/DC ou o painel.
/// </summary>
public class InfrastructureGuardTests
{
    private static readonly IReadOnlySet<string> Protected = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "10.0.0.1", "10.0.0.10" };

    [Fact]
    public async Task Bloqueio_de_endereco_de_infraestrutura_e_recusado_sem_chegar_ao_executor()
    {
        var inner = new RecordingExecutor();
        var guarded = new InfrastructureGuardExecutor(inner, () => Protected);

        var outcome = await guarded.ExecuteAsync(new ResponseAction(ResponseStep.BlockIp, "FS01", "10.0.0.10", "blocklist de rede"));

        Assert.Equal(ResponseStatus.Skipped, outcome.Status);
        Assert.Contains("infraestrutura", outcome.Detail);
        Assert.Empty(inner.Executed);
    }

    [Fact]
    public async Task Outros_enderecos_e_outros_degraus_passam_e_a_reversao_nunca_e_barrada()
    {
        var inner = new RecordingExecutor();
        var guarded = new InfrastructureGuardExecutor(inner, () => Protected);

        Assert.True((await guarded.ExecuteAsync(new ResponseAction(ResponseStep.BlockIp, "FS01", "10.0.9.66", "x"))).Ok);
        Assert.True((await guarded.ExecuteAsync(new ResponseAction(ResponseStep.KillSmbSession, "FS01", "10.0.0.10", "x"))).Ok);
        Assert.True((await guarded.RevertAsync(new ResponseAction(ResponseStep.BlockIp, "FS01", "10.0.0.10", "x"))).Ok);

        Assert.Equal(2, inner.Executed.Count);
        Assert.Single(inner.Reverted);
    }

    [Fact]
    public async Task Falha_ao_levantar_os_enderecos_nao_derruba_a_contencao()
    {
        var inner = new RecordingExecutor();
        var guarded = new InfrastructureGuardExecutor(inner, () => throw new InvalidOperationException("sem rede"));

        Assert.True((await guarded.ExecuteAsync(new ResponseAction(ResponseStep.BlockIp, "FS01", "10.0.9.66", "x"))).Ok);
    }
}
