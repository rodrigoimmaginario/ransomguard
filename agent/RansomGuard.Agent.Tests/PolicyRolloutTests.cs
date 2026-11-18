using RansomGuard.Agent.Auth;
using RansomGuard.Core.Auth;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Policy;
using RansomGuard.Core.Response;
using RansomGuard.Core.Score;
using RansomGuard.Core.Signing;

namespace RansomGuard.Agent.Tests;

/// <summary>F33 — o painel configura o agente (política assinada) e manda reverter (comandos assinados).</summary>
public class PolicyRolloutTests
{
    private static readonly DateTime T0 = new(2026, 10, 4, 9, 0, 0, DateTimeKind.Utc);
    private static readonly byte[] Seed = Enumerable.Range(20, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] Evil = Enumerable.Range(70, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] KeyId = [5, 5, 5, 5, 5, 5, 5, 5];
    private static string Pub(byte[] seed) => MinisignPublicKey.FromRaw(KeyId, Minisign.PublicKeyFromSeed(seed)).ToFileContent("t");
    private static PanelTrust Trusting() => new(new InMemoryPanelKeyStore(), Pub(Seed));

    private static SignedAssertion Policy(long version, string mode, byte[]? seed = null, string server = "*", string[]? users = null) =>
        AgentPolicyDocument.Sign(new AgentPolicyDocument(server, version, mode, "DenyUserOnShare", users ?? Array.Empty<string>(), Array.Empty<string>(), false, T0), seed ?? Seed, KeyId);
    private static SignedAssertion Commands(params AgentCommand[] cmds) =>
        CommandEnvelope.Sign(new CommandEnvelope("FS01", T0, T0 + CommandEnvelope.Validity, cmds), Seed, KeyId);

    private sealed class Posture : IPostureCollector { public PostureSnapshot Collect(string s) => new() { Server = s }; }
    private sealed class NoEvents : IFileEventCollector { public IReadOnlyList<FileEvent> Drain() => Array.Empty<FileEvent>(); }
    private sealed class NoSignals : IHostSignalCollector { public IReadOnlyList<HostSignal> Drain() => Array.Empty<HostSignal>(); }
    private sealed class Sink : IBatchSink
    {
        public BatchResponse? Reply; public List<AgentBatch> Sent = new();
        public Task<BatchResponse?> SendAsync(AgentBatch b, CancellationToken ct = default) { Sent.Add(b); return Task.FromResult(Reply); }
    }
    private sealed class MemoryPolicyStore : IPolicyStore { public SignedAssertion? Stored; public SignedAssertion? Load() => Stored; public void Save(SignedAssertion p) => Stored = p; }

    private static (AgentCycle cycle, Sink sink, RecordingExecutor exec) Make(PanelTrust trust, IPolicyStore? store = null)
    {
        var sink = new Sink(); var exec = new RecordingExecutor();
        var cycle = new AgentCycle("FS01", new Posture(), new NoEvents(), new NoSignals(), sink, new ResponseLadder(),
            new ResponsePolicy { Mode = ResponseMode.Monitor }, exec, trust: trust, policyStore: store);
        return (cycle, sink, exec);
    }

    [Fact]
    public async Task Valid_signed_policy_replaces_the_registry_policy()
    {
        var (cycle, sink, _) = Make(Trusting());
        Assert.Equal(ResponseMode.Monitor, cycle.Policy.Mode);
        sink.Reply = new BatchResponse(Policy: Policy(1, "Block", users: new[] { @"CORP\svc-backup" }));
        await cycle.RunOnceAsync(T0);
        Assert.Equal(PolicyOutcome.Valid, cycle.LastPolicyOutcome);
        Assert.Equal(ResponseMode.Block, cycle.Policy.Mode);
        Assert.Contains(@"CORP\svc-backup", cycle.Policy.AllowlistedUsers);
    }

    [Fact]
    public async Task Forged_policy_and_rollback_are_ignored()
    {
        var (cycle, sink, _) = Make(Trusting());
        sink.Reply = new BatchResponse(Policy: Policy(5, "Alert"));
        await cycle.RunOnceAsync(T0);
        Assert.Equal(ResponseMode.Alert, cycle.Policy.Mode);

        sink.Reply = new BatchResponse(Policy: Policy(6, "Block", seed: Evil));
        await cycle.RunOnceAsync(T0.AddSeconds(5));
        Assert.Equal(PolicyOutcome.InvalidSignature, cycle.LastPolicyOutcome);
        Assert.Equal(ResponseMode.Alert, cycle.Policy.Mode);

        sink.Reply = new BatchResponse(Policy: Policy(4, "Block"));
        await cycle.RunOnceAsync(T0.AddSeconds(10));
        Assert.Equal(PolicyOutcome.Rollback, cycle.LastPolicyOutcome);
        Assert.Equal(ResponseMode.Alert, cycle.Policy.Mode);
    }

    [Fact]
    public async Task Policy_for_another_server_is_ignored()
    {
        var (cycle, sink, _) = Make(Trusting());
        sink.Reply = new BatchResponse(Policy: Policy(1, "Block", server: "FS02"));
        await cycle.RunOnceAsync(T0);
        Assert.Equal(PolicyOutcome.WrongServer, cycle.LastPolicyOutcome);
        Assert.Equal(ResponseMode.Monitor, cycle.Policy.Mode);
    }

    [Fact]
    public async Task Accepted_policy_is_persisted_and_reapplied_after_restart()
    {
        var store = new MemoryPolicyStore();
        var (cycle, sink, _) = Make(Trusting(), store);
        sink.Reply = new BatchResponse(Policy: Policy(3, "Block"));
        await cycle.RunOnceAsync(T0);
        Assert.NotNull(store.Stored);

        var (restarted, sink2, _) = Make(Trusting(), store);   // nova instância, sem resposta do painel
        sink2.Reply = null;
        await restarted.RunOnceAsync(T0.AddMinutes(1));
        Assert.Equal(ResponseMode.Block, restarted.Policy.Mode);
    }

    [Fact]
    public async Task Revert_command_is_executed_once_and_reported_in_the_next_batch()
    {
        var (cycle, sink, exec) = Make(Trusting());
        var cmd = new AgentCommand("revert-7", AgentCommand.Revert, "DenyUserOnShare", @"\\FS01\Fin", @"CORP\ana", "falso positivo");
        sink.Reply = new BatchResponse(Commands: Commands(cmd));

        await cycle.RunOnceAsync(T0);
        Assert.Equal(PolicyOutcome.Valid, cycle.LastCommandsOutcome);
        var reverted = Assert.Single(exec.Reverted);
        Assert.Equal(ResponseStep.DenyUserOnShare, reverted.Step);
        Assert.Equal(@"CORP\ana", reverted.Account);

        await cycle.RunOnceAsync(T0.AddSeconds(5));                 // painel reenvia o mesmo comando
        Assert.Single(exec.Reverted);                               // não repete
        var reported = sink.Sent[1].CommandResults!.Single();
        Assert.Equal("revert-7", reported.CommandId);
        Assert.Equal("Executed", reported.Status);

        sink.Reply = new BatchResponse();
        await cycle.RunOnceAsync(T0.AddSeconds(10));
        Assert.Empty(sink.Sent[2].CommandResults!);                  // entregue uma vez, não repete
    }

    [Fact]
    public async Task Command_with_unsafe_target_is_skipped_and_reported()
    {
        var (cycle, sink, exec) = Make(Trusting());
        sink.Reply = new BatchResponse(Commands: Commands(new AgentCommand("revert-9", AgentCommand.Revert, "BlockIp", "10.0.0.1; rm", null, "x")));
        await cycle.RunOnceAsync(T0);
        await cycle.RunOnceAsync(T0.AddSeconds(5));
        Assert.Empty(exec.Reverted);
        Assert.Equal("Skipped", sink.Sent[1].CommandResults!.Single().Status);
    }

    [Fact]
    public async Task Forged_commands_are_never_executed()
    {
        var (cycle, sink, exec) = Make(Trusting());
        var env = new CommandEnvelope("FS01", T0, T0.AddMinutes(15), new[] { new AgentCommand("r1", AgentCommand.Revert, "BlockIp", "10.0.0.1", null, "x") });
        sink.Reply = new BatchResponse(Commands: CommandEnvelope.Sign(env, Evil, KeyId));
        await cycle.RunOnceAsync(T0);
        Assert.Equal(PolicyOutcome.InvalidSignature, cycle.LastCommandsOutcome);
        Assert.Empty(exec.Reverted);
    }
}

/// <summary>G4b — o agente converge o firewall local para a blocklist assinada da política.</summary>
public class NetworkBlocklistAgentTests
{
    private static readonly DateTime T0 = new(2026, 10, 4, 13, 0, 0, DateTimeKind.Utc);
    private static readonly byte[] Seed = Enumerable.Range(20, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] KeyId = [5, 5, 5, 5, 5, 5, 5, 5];
    private static PanelTrust Trusting() => new(new InMemoryPanelKeyStore(), MinisignPublicKey.FromRaw(KeyId, Minisign.PublicKeyFromSeed(Seed)).ToFileContent("t"));
    private static SignedAssertion Policy(long version, params string[] blocked) =>
        AgentPolicyDocument.Sign(new AgentPolicyDocument("*", version, "Monitor", "DenyUserOnShare", Array.Empty<string>(), Array.Empty<string>(), false, T0, blocked), Seed, KeyId);

    private sealed class Posture : IPostureCollector { public PostureSnapshot Collect(string s) => new() { Server = s }; }
    private sealed class NoEvents : IFileEventCollector { public IReadOnlyList<FileEvent> Drain() => Array.Empty<FileEvent>(); }
    private sealed class NoSignals : IHostSignalCollector { public IReadOnlyList<HostSignal> Drain() => Array.Empty<HostSignal>(); }
    private sealed class Sink : IBatchSink { public BatchResponse? Reply; public Task<BatchResponse?> SendAsync(AgentBatch b, CancellationToken ct = default) => Task.FromResult(Reply); }

    [Fact]
    public async Task Blocklist_is_applied_once_and_reverted_when_an_ip_leaves()
    {
        var sink = new Sink(); var exec = new RecordingExecutor();
        var cycle = new AgentCycle("FS02", new Posture(), new NoEvents(), new NoSignals(), sink, new ResponseLadder(),
            new ResponsePolicy(), exec, trust: Trusting());

        sink.Reply = new BatchResponse(Policy: Policy(1, "10.0.9.66", "10.0.9.77", "not-an-ip; rm"));
        await cycle.RunOnceAsync(T0);
        Assert.Equal(new[] { "10.0.9.66", "10.0.9.77" }, exec.Executed.Where(a => a.Step == ResponseStep.BlockIp).Select(a => a.Target));
        Assert.Equal(2, cycle.AppliedBlocklist.Count);

        await cycle.RunOnceAsync(T0.AddSeconds(5));                                   // mesma política: nada repete
        Assert.Equal(2, exec.Executed.Count);

        sink.Reply = new BatchResponse(Policy: Policy(2, "10.0.9.66"));         // .77 saiu
        await cycle.RunOnceAsync(T0.AddSeconds(10));
        var reverted = Assert.Single(exec.Reverted);
        Assert.Equal("10.0.9.77", reverted.Target);
        Assert.Equal(new[] { "10.0.9.66" }, cycle.AppliedBlocklist);
    }
}
