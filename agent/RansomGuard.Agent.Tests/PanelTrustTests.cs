using RansomGuard.Agent.Auth;
using RansomGuard.Core.Auth;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Policy;
using RansomGuard.Core.Response;
using RansomGuard.Core.Score;
using RansomGuard.Core.Signing;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// F38 — o agente só obedece ao painel cuja chave fixou. O produto é gratuito: não existe licença nem "tier";
/// o que o painel pode mudar no agente é a política (e mandar reverter), e só com assinatura da chave fixada.
/// Painel falso, resposta em claro, chave trocada: nada disso liga nem desliga a contenção.
/// </summary>
public class PanelTrustTests
{
    private static readonly DateTime T0 = new(2026, 10, 3, 12, 0, 0, DateTimeKind.Utc);
    private static readonly byte[] Seed = Enumerable.Range(10, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] EvilSeed = Enumerable.Range(90, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] KeyId = [9, 9, 9, 9, 9, 9, 9, 9];

    private static string PubContent(byte[] seed) =>
        MinisignPublicKey.FromRaw(KeyId, Minisign.PublicKeyFromSeed(seed)).ToFileContent("test");

    private static SignedAssertion Policy(long version, string mode, byte[]? seed = null, string server = "*") =>
        AgentPolicyDocument.Sign(new AgentPolicyDocument(server, version, mode, "DenyUserOnShare",
            Array.Empty<string>(), Array.Empty<string>(), false, T0), seed ?? Seed, KeyId);

    // ── PanelTrust ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Tofu_pins_the_first_key_and_refuses_a_different_one_later()
    {
        var store = new InMemoryPanelKeyStore();
        var trust = new PanelTrust(store);
        Assert.False(trust.HasKey);

        Assert.True(trust.TryPin(PubContent(Seed)));
        Assert.True(trust.HasKey);
        Assert.NotNull(store.Load());

        Assert.False(trust.TryPin(PubContent(EvilSeed)));      // painel "novo" com outra chave: recusado
        Assert.True(trust.TryPin(PubContent(Seed)));           // a mesma chave: idempotente
        Assert.Equal(PolicyOutcome.Valid, trust.EvaluatePolicy(Policy(1, "Block"), "FS01", T0).Outcome);
    }

    [Fact]
    public void Configured_key_is_pinned_and_wins_over_the_store()
    {
        var store = new InMemoryPanelKeyStore();
        store.Save(PubContent(EvilSeed));
        var trust = new PanelTrust(store, configuredPublicKey: PubContent(Seed));

        Assert.True(trust.Pinned);
        Assert.Equal(PolicyOutcome.Valid, trust.EvaluatePolicy(Policy(1, "Block"), "FS01", T0).Outcome);
        Assert.Equal(PolicyOutcome.InvalidSignature, trust.EvaluatePolicy(Policy(2, "Block", EvilSeed), "FS01", T0).Outcome);
    }

    [Fact]
    public void Store_key_is_reloaded_on_restart()
    {
        var store = new InMemoryPanelKeyStore();
        new PanelTrust(store).TryPin(PubContent(Seed));
        var restarted = new PanelTrust(store);
        Assert.True(restarted.HasKey);
        Assert.False(restarted.Pinned);
    }

    [Fact]
    public void Without_a_pinned_key_no_document_is_accepted()
    {
        var trust = new PanelTrust(new InMemoryPanelKeyStore());

        Assert.Equal(PolicyOutcome.Malformed, trust.EvaluatePolicy(Policy(1, "Block"), "FS01", T0).Outcome);
    }

    // ── AgentCycle: a contenção depende do modo, não de licença ───────────────────────────────

    private sealed class FakePosture : IPostureCollector { public PostureSnapshot Collect(string s) => new() { Server = s }; }
    private sealed class CanaryHit : IFileEventCollector
    {
        public IReadOnlyList<FileEvent> Drain() => new[]
        {
            new FileEvent(T0, @"CORP\vendas1", "10.0.9.66", @"\\FS01\Financeiro", FileOp.Write, "!0__ransomguard_canary.docx", ".docx", IsCanary: true)
        };
    }
    private sealed class NoSignals : IHostSignalCollector { public IReadOnlyList<HostSignal> Drain() => Array.Empty<HostSignal>(); }
    private sealed class Recorder : IResponseExecutor
    {
        public List<ResponseStep> Executed = new();
        public Task<ResponseOutcome> ExecuteAsync(ResponseAction a, CancellationToken ct = default) { Executed.Add(a.Step); return Task.FromResult(ResponseOutcome.Done()); }
        public Task<ResponseOutcome> RevertAsync(ResponseAction a, CancellationToken ct = default) => Task.FromResult(ResponseOutcome.Done());
    }
    private sealed class ReplySink(BatchResponse? reply) : IBatchSink
    {
        public Task<BatchResponse?> SendAsync(AgentBatch batch, CancellationToken ct = default) => Task.FromResult(reply);
    }

    private static (AgentCycle Cycle, Recorder Exec) Cycle(ResponseMode mode, BatchResponse? reply, PanelTrust? trust = null)
    {
        var exec = new Recorder();
        var cycle = new AgentCycle("FS01", new FakePosture(), new CanaryHit(), new NoSignals(), new ReplySink(reply),
            new ResponseLadder(), new ResponsePolicy { Mode = mode }, exec, trust: trust);
        return (cycle, exec);
    }

    private static PanelTrust Trusting() => new(new InMemoryPanelKeyStore(), PubContent(Seed));

    [Fact]
    public async Task Block_mode_contains_a_high_confidence_incident_without_license_or_panel()
    {
        var (cycle, exec) = Cycle(ResponseMode.Block, reply: null);   // painel fora do ar

        var result = await cycle.RunOnceAsync(T0);

        Assert.True(result.LocalContainments > 0);
        Assert.Contains(ResponseStep.BlockIp, exec.Executed);
        Assert.Contains(ResponseStep.DenyUserOnShare, exec.Executed);
    }

    [Fact]
    public async Task Monitor_mode_never_acts_even_on_a_canary_hit()
    {
        var (cycle, exec) = Cycle(ResponseMode.Monitor, new BatchResponse());

        var result = await cycle.RunOnceAsync(T0);

        Assert.Equal(1, result.Detections);
        Assert.Equal(0, result.LocalContainments);
        Assert.Empty(exec.Executed);
    }

    [Fact]
    public async Task Spoofed_panel_cannot_switch_a_monitoring_agent_to_block()
    {
        var (cycle, exec) = Cycle(ResponseMode.Monitor, new BatchResponse(Policy: Policy(1, "Block", EvilSeed)), Trusting());

        await cycle.RunOnceAsync(T0);                    // recebe a política forjada
        await cycle.RunOnceAsync(T0.AddSeconds(5));      // e continua sem agir

        Assert.Equal(PolicyOutcome.InvalidSignature, cycle.LastPolicyOutcome);
        Assert.Equal(ResponseMode.Monitor, cycle.Policy.Mode);
        Assert.Empty(exec.Executed);
    }

    [Fact]
    public async Task Spoofed_panel_cannot_switch_a_blocking_agent_off()
    {
        var (cycle, exec) = Cycle(ResponseMode.Block, new BatchResponse(Policy: Policy(1, "Monitor", EvilSeed)), Trusting());

        await cycle.RunOnceAsync(T0);
        exec.Executed.Clear();
        await cycle.RunOnceAsync(T0.AddSeconds(5));

        Assert.Equal(ResponseMode.Block, cycle.Policy.Mode);
        Assert.Contains(ResponseStep.BlockIp, exec.Executed);
    }

    [Fact]
    public async Task Legitimate_panel_switches_the_mode_through_a_signed_policy()
    {
        var (cycle, exec) = Cycle(ResponseMode.Monitor, new BatchResponse(Policy: Policy(1, "Block")), Trusting());

        await cycle.RunOnceAsync(T0);                    // ainda em Monitor neste ciclo; a política chega na resposta
        Assert.Empty(exec.Executed);
        await cycle.RunOnceAsync(T0.AddSeconds(5));

        Assert.Equal(ResponseMode.Block, cycle.Policy.Mode);
        Assert.Contains(ResponseStep.BlockIp, exec.Executed);
    }

    [Fact]
    public async Task Without_trust_component_a_policy_in_the_reply_is_ignored()
    {
        var (cycle, _) = Cycle(ResponseMode.Monitor, new BatchResponse(Policy: Policy(1, "Block")), trust: null);

        await cycle.RunOnceAsync(T0);

        Assert.Equal(ResponseMode.Monitor, cycle.Policy.Mode);
    }
}

/// <summary>F39 — pin do certificado TLS do painel: configurado > fixado (TOFU) > cadeia válida.</summary>
public class CertificatePinningTests
{
    private const string A = "AA11BB22", B = "CC33DD44";

    [Fact]
    public void Configured_thumbprint_wins_and_rejects_anything_else()
    {
        Assert.Equal(PinDecision.Accept, CertificatePinning.Decide(A, pinnedThumbprint: B, configuredThumbprint: "aa:11:bb:22", chainValid: false));
        Assert.Equal(PinDecision.Reject, CertificatePinning.Decide(B, null, A, chainValid: true));
    }

    [Fact]
    public void Tofu_pins_the_first_self_signed_certificate_and_rejects_a_different_one_later()
    {
        Assert.Equal(PinDecision.PinAndAccept, CertificatePinning.Decide(A, null, null, chainValid: false));
        Assert.Equal(PinDecision.Accept, CertificatePinning.Decide(A, A, null, chainValid: false));
        Assert.Equal(PinDecision.Reject, CertificatePinning.Decide(B, A, null, chainValid: false));
    }

    [Fact]
    public void Publicly_valid_certificate_is_accepted_without_pinning_and_missing_certificate_is_rejected()
    {
        Assert.Equal(PinDecision.Accept, CertificatePinning.Decide(A, null, null, chainValid: true));
        Assert.Equal(PinDecision.Reject, CertificatePinning.Decide("", null, null, chainValid: true));
    }
}
