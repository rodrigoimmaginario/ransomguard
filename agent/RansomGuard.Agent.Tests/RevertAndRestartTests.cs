using RansomGuard.Agent.Auth;
using RansomGuard.Agent.Protection;
using RansomGuard.Core.Auth;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Fsrm;
using RansomGuard.Core.Policy;
using RansomGuard.Core.Response;
using RansomGuard.Core.Score;
using RansomGuard.Core.Signing;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// D4 — o plantio desce às subpastas; a remoção precisa descer também. Antes ela só olhava a raiz: reverter ou
/// desinstalar deixava centenas de arquivos ocultos espalhados pelas pastas do cliente.
/// </summary>
public class CanaryRemovalCoversSubfoldersTests
{
    private sealed class DiskFs : ICanaryFileSystem
    {
        public readonly Dictionary<string, List<string>> Files = new(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string, List<string>> Subdirs = new(StringComparer.OrdinalIgnoreCase);
        public void AddDir(string dir, params string[] subs)
        {
            Files.TryAdd(dir, new List<string>()); Subdirs[dir] = subs.ToList();
            foreach (var s in subs) { Files.TryAdd(s, new List<string>()); Subdirs.TryAdd(s, new List<string>()); }
        }
        public bool DirectoryExists(string path) => Files.ContainsKey(path);
        public IReadOnlyList<string> ListFiles(string path) => Files[path].ToList();
        public IReadOnlyList<string> ListDirectories(string path) => Subdirs.TryGetValue(path, out var l) ? l : Array.Empty<string>();
        public void WriteCanary(string fullPath, string content) => Files[Path.GetDirectoryName(fullPath)!].Add(Path.GetFileName(fullPath));
        public void Delete(string fullPath) => Files[Path.GetDirectoryName(fullPath)!].Remove(Path.GetFileName(fullPath));
        public int Canaries => Files.Values.Sum(f => f.Count(CanaryPlan.IsCanary));
    }

    [Fact]
    public void Remover_apaga_os_canarios_de_todas_as_pastas_em_que_o_plantio_entrou()
    {
        var fs = new DiskFs();
        fs.AddDir(@"D:\Fin", @"D:\Fin\2024", @"D:\Fin\2025");
        fs.AddDir(@"D:\Fin\2024", @"D:\Fin\2024\Q1");
        fs.Files[@"D:\Fin\2024"].Add("contrato.docx");                 // dado do cliente
        var planter = new CanaryPlanter(fs);
        planter.Plant(new[] { @"D:\Fin" });
        Assert.Equal(4 * CanaryPlan.NamesFor("x").Count, fs.Canaries);

        var removed = planter.Remove(new[] { @"D:\Fin" });

        Assert.Equal(0, fs.Canaries);
        Assert.Equal(4 * CanaryPlan.NamesFor("x").Count, removed.Where(r => r.Ok).Sum(r => r.Planted));
        Assert.Contains("contrato.docx", fs.Files[@"D:\Fin\2024"]);    // o que é do cliente não se toca
    }

    /// <summary>O plantio tem teto de subpastas; a remoção não: pastas criadas depois mudam quem cabe no teto.</summary>
    [Fact]
    public void Remover_nao_para_no_teto_de_subpastas_do_plantio()
    {
        var fs = new DiskFs();
        var subs = Enumerable.Range(0, CanaryPlanter.MaxSubdirectoriesPerRoot + 50).Select(i => $@"D:\Big\d{i:0000}").ToArray();
        fs.AddDir(@"D:\Big", subs);
        foreach (var s in subs) fs.Files[s].Add(CanaryPlan.NamesFor("x")[0]);   // canário em TODAS, inclusive além do teto

        new CanaryPlanter(fs).Remove(new[] { @"D:\Big" });

        Assert.Equal(0, fs.Canaries);
    }
}

/// <summary>
/// B5 — a blocklist de rede aplicada sobrevive ao reinício do agente. Sem isso, um IP que saísse da lista enquanto o
/// serviço estava parado ficava bloqueado no firewall para sempre: o agente não lembrava que a regra era dele.
/// </summary>
public class BlocklistSurvivesRestartTests
{
    private static readonly DateTime T0 = new(2026, 11, 16, 13, 0, 0, DateTimeKind.Utc);
    private static readonly byte[] Seed = Enumerable.Range(20, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] KeyId = [5, 5, 5, 5, 5, 5, 5, 5];
    private static PanelTrust Trusting() => new(new InMemoryPanelKeyStore(), MinisignPublicKey.FromRaw(KeyId, Minisign.PublicKeyFromSeed(Seed)).ToFileContent("t"));
    private static SignedAssertion Policy(long version, params string[] blocked) =>
        AgentPolicyDocument.Sign(new AgentPolicyDocument("*", version, "Monitor", "DenyUserOnShare", Array.Empty<string>(), Array.Empty<string>(), false, T0, blocked), Seed, KeyId);

    private sealed class Posture : IPostureCollector { public PostureSnapshot Collect(string s) => new() { Server = s }; }
    private sealed class NoEvents : IFileEventCollector { public IReadOnlyList<FileEvent> Drain() => Array.Empty<FileEvent>(); }
    private sealed class NoSignals : IHostSignalCollector { public IReadOnlyList<HostSignal> Drain() => Array.Empty<HostSignal>(); }
    private sealed class Sink : IBatchSink { public BatchResponse? Reply; public Task<BatchResponse?> SendAsync(AgentBatch b, CancellationToken ct = default) => Task.FromResult(Reply); }
    private sealed class MemoryBlocklistStore : IAppliedBlocklistStore
    {
        public List<string> Saved = new();
        public IReadOnlyCollection<string> Load() => Saved.ToList();
        public void Save(IReadOnlyCollection<string> ips) => Saved = ips.ToList();
    }

    private static AgentCycle Agent(Sink sink, RecordingExecutor exec, IAppliedBlocklistStore store) =>
        new("FS02", new Posture(), new NoEvents(), new NoSignals(), sink, new ResponseLadder(), new ResponsePolicy(), exec,
            trust: Trusting(), blocklistStore: store);

    /// <summary>
    /// Laboratório, sessão 4 — com a regra de firewall removida por fora (administrador, ou um invasor com direito de
    /// administrador), o agente achava que o IP seguia bloqueado e nunca recolocava a regra. A cada 10 minutos ele
    /// reafirma a blocklist inteira (o script é idempotente e confere o efeito).
    /// </summary>
    [Fact]
    public async Task A_blocklist_e_reafirmada_periodicamente()
    {
        var exec = new RecordingExecutor();
        var sink = new Sink { Reply = new BatchResponse(Policy: Policy(1, "10.0.9.66")) };
        var agent = Agent(sink, exec, new MemoryBlocklistStore());

        await agent.RunOnceAsync(T0);
        await agent.RunOnceAsync(T0.AddMinutes(5));
        Assert.Single(exec.Executed, a => a.Target == "10.0.9.66");

        await agent.RunOnceAsync(T0.AddMinutes(11));
        Assert.Equal(2, exec.Executed.Count(a => a.Target == "10.0.9.66"));
    }

    [Fact]
    public async Task Depois_de_reiniciar_o_agente_libera_o_ip_que_saiu_da_lista()
    {
        var store = new MemoryBlocklistStore();
        var sink = new Sink { Reply = new BatchResponse(Policy: Policy(1, "10.0.9.66", "10.0.9.77")) };
        await Agent(sink, new RecordingExecutor(), store).RunOnceAsync(T0);
        Assert.Equal(new[] { "10.0.9.66", "10.0.9.77" }, store.Saved.OrderBy(x => x));

        // Reinício: outro processo, mesma pasta de dados. Enquanto isso o painel tirou o .77 da lista.
        var exec = new RecordingExecutor();
        sink.Reply = new BatchResponse(Policy: Policy(2, "10.0.9.66"));
        var restarted = Agent(sink, exec, store);
        await restarted.RunOnceAsync(T0.AddMinutes(30));

        Assert.Equal("10.0.9.77", Assert.Single(exec.Reverted).Target);
        // Ao subir, o agente reafirma o que ficou (sessão 4 do laboratório): o script é idempotente e confere a regra.
        Assert.Single(exec.Executed, a => a.Target == "10.0.9.66");
        Assert.Equal(new[] { "10.0.9.66" }, restarted.AppliedBlocklist);
        Assert.Equal(new[] { "10.0.9.66" }, store.Saved);
    }

    [Fact]
    public async Task Falha_ao_liberar_mantem_o_ip_lembrado_para_tentar_de_novo()
    {
        var store = new MemoryBlocklistStore { Saved = { "10.0.9.77" } };
        var sink = new Sink { Reply = new BatchResponse(Policy: Policy(1)) };
        var exec = new FailingRevert();
        var cycle = new AgentCycle("FS02", new Posture(), new NoEvents(), new NoSignals(), sink, new ResponseLadder(), new ResponsePolicy(), exec,
            trust: Trusting(), blocklistStore: store);

        await cycle.RunOnceAsync(T0);

        Assert.Equal(new[] { "10.0.9.77" }, store.Saved);
    }

    private sealed class FailingRevert : IResponseExecutor
    {
        public Task<ResponseOutcome> ExecuteAsync(ResponseAction a, CancellationToken ct = default) => Task.FromResult(ResponseOutcome.Done());
        public Task<ResponseOutcome> RevertAsync(ResponseAction a, CancellationToken ct = default) => Task.FromResult(ResponseOutcome.Fail("firewall indisponível"));
    }
}
