using RansomGuard.Agent;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;
using RansomGuard.Core.Score;

namespace RansomGuard.Agent.Tests;

public class AgentCycleTests
{
    private static readonly DateTime T0 = new(2026, 7, 23, 2, 0, 0, DateTimeKind.Utc);

    private sealed class FakePosture : IPostureCollector
    {
        public PostureSnapshot Collect(string server) => new() { Server = server, AgentInstalled = true };
    }
    private sealed class FakeEvents(IReadOnlyList<FileEvent> e) : IFileEventCollector
    {
        private IReadOnlyList<FileEvent> _e = e;
        public IReadOnlyList<FileEvent> Drain() { var r = _e; _e = Array.Empty<FileEvent>(); return r; }
    }
    private sealed class FakeSignals(IReadOnlyList<HostSignal> s) : IHostSignalCollector
    {
        private IReadOnlyList<HostSignal> _s = s;
        public IReadOnlyList<HostSignal> Drain() { var r = _s; _s = Array.Empty<HostSignal>(); return r; }
    }
    private sealed class CapturingSink : IBatchSink
    {
        public List<AgentBatch> Sent { get; } = new();
        public BatchResponse? Reply { get; set; }
        public Task<BatchResponse?> SendAsync(AgentBatch batch, CancellationToken ct = default)
        {
            Sent.Add(batch);
            return Task.FromResult(Reply);
        }
    }

    private static IReadOnlyList<FileEvent> RemoteAttack() =>
        Enumerable.Range(0, 90).Select(i =>
            new FileEvent(T0.AddSeconds(i), @"CORP\v", "10.0.9.66", @"\\FS01\Fin",
                FileOp.Rename, $"f{i}.xlsx", ".locked")).ToList();

    private static AgentCycle Build(
        IReadOnlyList<FileEvent> events, IReadOnlyList<HostSignal> signals,
        CapturingSink sink, RecordingExecutor exec, ResponseMode mode)
        => new("FS01", new FakePosture(), new FakeEvents(events), new FakeSignals(signals),
            sink, new ResponseLadder(), new ResponsePolicy { Mode = mode }, exec);

    [Fact]
    public async Task Cycle_collects_detects_and_sends_batch()
    {
        var sink = new CapturingSink();
        var exec = new RecordingExecutor();
        var cycle = Build(RemoteAttack(),
            new[] { new HostSignal(T0.AddSeconds(2), HostSignalKind.VssDeleted, "FS01") },
            sink, exec, ResponseMode.Block);

        var result = await cycle.RunOnceAsync(T0);

        Assert.Equal(90, result.Events);
        Assert.Equal(1, result.Detections);
        Assert.True(result.PostureSent);
        Assert.Single(sink.Sent);
        Assert.Equal(90, sink.Sent[0].Events.Count);
    }

    [Fact]
    public async Task High_incident_in_block_mode_triggers_local_containment()
    {
        var exec = new RecordingExecutor();
        var cycle = Build(RemoteAttack(),
            new[] { new HostSignal(T0.AddSeconds(2), HostSignalKind.VssDeleted, "FS01") },
            new CapturingSink(), exec, ResponseMode.Block);

        var result = await cycle.RunOnceAsync(T0);

        Assert.True(result.LocalContainments > 0);
        Assert.NotEmpty(exec.Executed);
    }

    [Fact]
    public async Task Monitor_mode_sends_batch_but_never_contains()
    {
        var exec = new RecordingExecutor();
        var cycle = Build(RemoteAttack(),
            new[] { new HostSignal(T0.AddSeconds(2), HostSignalKind.VssDeleted, "FS01") },
            new CapturingSink(), exec, ResponseMode.Monitor);

        var result = await cycle.RunOnceAsync(T0);

        Assert.Equal(0, result.LocalContainments);
        Assert.Empty(exec.Executed);
    }

    [Fact]
    public async Task Fast_cycle_without_posture_still_sends_events()
    {
        var sink = new CapturingSink();
        var cycle = Build(RemoteAttack(), Array.Empty<HostSignal>(),
            sink, new RecordingExecutor(), ResponseMode.Block);

        var result = await cycle.RunOnceAsync(T0, collectPosture: false);

        Assert.False(result.PostureSent);
        Assert.Null(sink.Sent[0].Posture);
        Assert.Equal(90, sink.Sent[0].Events.Count);
    }

    [Fact]
    public async Task Empty_cycle_sends_heartbeat_like_batch()
    {
        var sink = new CapturingSink();
        var cycle = Build(Array.Empty<FileEvent>(), Array.Empty<HostSignal>(),
            sink, new RecordingExecutor(), ResponseMode.Block);

        var result = await cycle.RunOnceAsync(T0);

        Assert.Equal(0, result.Events);
        Assert.Equal(0, result.Detections);
        Assert.Single(sink.Sent); // ainda envia (mantém heartbeat/postura)
    }
}
