using RansomGuard.Agent.Queue;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;
using RansomGuard.Core.Score;

namespace RansomGuard.Agent.Tests;

/// <summary>F34 — painel fora do ar: lotes ficam na fila e são reentregues em ordem; nada se perde, nada duplica.</summary>
public class DurableQueueTests
{
    private static readonly DateTime T0 = new(2026, 10, 4, 15, 0, 0, DateTimeKind.Utc);
    private sealed class Posture : IPostureCollector { public PostureSnapshot Collect(string s) => new() { Server = s }; }
    private sealed class Feed : IFileEventCollector
    {
        private readonly Queue<IReadOnlyList<FileEvent>> _batches = new();
        public void Next(params FileEvent[] e) => _batches.Enqueue(e);
        public IReadOnlyList<FileEvent> Drain() => _batches.Count > 0 ? _batches.Dequeue() : Array.Empty<FileEvent>();
    }
    private sealed class NoSignals : IHostSignalCollector { public IReadOnlyList<HostSignal> Drain() => Array.Empty<HostSignal>(); }
    private sealed class FlakyPanel : IBatchSink
    {
        public bool Down;
        public readonly List<AgentBatch> Received = new();
        public Task<BatchResponse?> SendAsync(AgentBatch b, CancellationToken ct = default)
        {
            if (Down) return Task.FromResult<BatchResponse?>(null);
            Received.Add(b); return Task.FromResult<BatchResponse?>(new BatchResponse());
        }
    }
    private static FileEvent Ev(int i) => new(T0.AddSeconds(i), "u", "10.0.0.1", "s", FileOp.Write, $"f{i}");

    [Fact]
    public async Task Batches_during_an_outage_are_delivered_in_order_when_the_panel_returns()
    {
        var feed = new Feed(); var panel = new FlakyPanel(); var queue = new InMemoryBatchQueue();
        var cycle = new AgentCycle("FS01", new Posture(), feed, new NoSignals(), panel, new ResponseLadder(), new ResponsePolicy(),
            new RecordingExecutor(), queue: queue);

        feed.Next(Ev(1)); await cycle.RunOnceAsync(T0, collectPosture: false);              // entregue
        panel.Down = true;
        feed.Next(Ev(2)); await cycle.RunOnceAsync(T0.AddSeconds(5), collectPosture: false); // fila
        feed.Next(Ev(3)); await cycle.RunOnceAsync(T0.AddSeconds(10), collectPosture: false);
        feed.Next();      await cycle.RunOnceAsync(T0.AddSeconds(15), collectPosture: false); // só batimento: não vale a pena guardar
        Assert.Equal(2, cycle.QueuedBatches);
        Assert.Single(panel.Received);

        panel.Down = false;
        feed.Next(Ev(4)); await cycle.RunOnceAsync(T0.AddSeconds(20), collectPosture: false);

        Assert.Equal(0, cycle.QueuedBatches);
        Assert.Equal(new[] { "f1", "f2", "f3", "f4" }, panel.Received.Select(b => b.Events[0].Path));
        Assert.Equal(new[] { T0, T0.AddSeconds(5), T0.AddSeconds(10), T0.AddSeconds(20) }, panel.Received.Select(b => b.At));
    }

    private sealed class CountingPanel : IBatchSink
    {
        public bool Down = true;
        public int Calls;
        public Task<BatchResponse?> SendAsync(AgentBatch b, CancellationToken ct = default)
        {
            Calls++;
            return Task.FromResult<BatchResponse?>(Down ? null : new BatchResponse());
        }
    }

    /// <summary>
    /// Laboratório, sessão 5 — com o painel parado, cada tentativa de envio ficava ~21 s presa (o firewall do Windows
    /// descarta a conexão à porta fechada) e, nesse tempo, o agente não lia nem detectava: a contenção veio 9–11 s depois
    /// do início do ataque. Depois de uma falha, o agente guarda os lotes na fila sem tentar a rede, com espera crescente.
    /// </summary>
    [Fact]
    public async Task Com_o_painel_fora_o_agente_espera_antes_de_tentar_de_novo_e_guarda_os_lotes()
    {
        var feed = new Feed(); var panel = new CountingPanel(); var queue = new InMemoryBatchQueue();
        var cycle = new AgentCycle("FS01", new Posture(), feed, new NoSignals(), panel, new ResponseLadder(), new ResponsePolicy(),
            new RecordingExecutor(), queue: queue);

        for (var s = 0; s < 10; s++) { feed.Next(Ev(s)); await cycle.RunOnceAsync(T0.AddSeconds(s), collectPosture: false); }
        Assert.Equal(1, panel.Calls);                         // uma tentativa; os outros nove ciclos não tocam a rede
        Assert.Equal(10, cycle.QueuedBatches);                // nada se perde

        feed.Next(Ev(20)); await cycle.RunOnceAsync(T0.AddSeconds(16), collectPosture: false);
        Assert.Equal(2, panel.Calls);                         // passados 15 s, tenta de novo (e falha: espera dobra)
        feed.Next(Ev(21)); await cycle.RunOnceAsync(T0.AddSeconds(40), collectPosture: false);
        Assert.Equal(2, panel.Calls);

        panel.Down = false;
        feed.Next(Ev(22)); await cycle.RunOnceAsync(T0.AddSeconds(47), collectPosture: false);
        Assert.Equal(0, cycle.QueuedBatches);                 // voltou: entrega tudo
        feed.Next(Ev(23)); await cycle.RunOnceAsync(T0.AddSeconds(48), collectPosture: false);
        Assert.True(panel.Calls > 3);                         // e volta a enviar a cada ciclo
    }

    [Fact]
    public async Task A_espera_entre_tentativas_tem_teto()
    {
        var feed = new Feed(); var panel = new CountingPanel(); var queue = new InMemoryBatchQueue();
        var cycle = new AgentCycle("FS01", new Posture(), feed, new NoSignals(), panel, new ResponseLadder(), new ResponsePolicy(),
            new RecordingExecutor(), queue: queue);
        var t = T0;
        for (var i = 0; i < 2000; i++) { feed.Next(Ev(i)); await cycle.RunOnceAsync(t, collectPosture: false); t = t.AddSeconds(1); }
        // Em 2000 s: 15 + 30 + 60 + 120 + 120... — nunca mais de 2 min sem tentar.
        Assert.InRange(panel.Calls, 2000 / 121, 20);
    }

    [Fact]
    public async Task Queue_is_capped_by_count_and_age_dropping_the_oldest()
    {
        var q = new InMemoryBatchQueue();
        for (var i = 0; i < 5; i++) q.Enqueue(new AgentBatch("FS01", T0.AddMinutes(i), null, new[] { Ev(i) }, Array.Empty<HostSignal>()));
        Assert.Equal(2, q.Prune(T0.AddMinutes(10), maxCount: 3, maxAge: TimeSpan.FromDays(1)));
        Assert.Equal("f2", q.Peek(1)[0].Events[0].Path);
        Assert.Equal(3, q.Prune(T0.AddDays(2), maxCount: 100, maxAge: TimeSpan.FromDays(1)));
        Assert.Equal(0, q.Count);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Flush_stops_at_the_first_failure_and_keeps_the_rest()
    {
        var feed = new Feed(); var panel = new FlakyPanel(); var queue = new InMemoryBatchQueue();
        var cycle = new AgentCycle("FS01", new Posture(), feed, new NoSignals(), panel, new ResponseLadder(), new ResponsePolicy(),
            new RecordingExecutor(), queue: queue);
        panel.Down = true;
        for (var i = 1; i <= 3; i++) { feed.Next(Ev(i)); await cycle.RunOnceAsync(T0.AddSeconds(i * 5), collectPosture: false); }
        Assert.Equal(3, cycle.QueuedBatches);
        feed.Next(Ev(9)); await cycle.RunOnceAsync(T0.AddSeconds(30), collectPosture: false);   // ainda fora
        Assert.Equal(4, cycle.QueuedBatches);
        Assert.Empty(panel.Received);
        Assert.Equal(0, cycle.DroppedBatches);
    }
}
