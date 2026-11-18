using RansomGuard.Core.Notifications;

namespace RansomGuard.Core.Tests;

public class NotificationDispatcherTests
{
    private static readonly DateTime T0 = new(2026, 7, 26, 14, 0, 0, DateTimeKind.Utc);

    /// <summary>Canal de mentira controlável: entrega, falha ou explode, e conta as chamadas.</summary>
    private sealed class StubChannel : INotificationChannel
    {
        private readonly SendResult? _result;
        private readonly Exception? _throw;
        private readonly TimeSpan _delay;
        private readonly AsyncLatch? _latch;

        public int Calls { get; private set; }
        public AlertMessage? Last { get; private set; }
        public ChannelKind Kind { get; }
        public string Name { get; }

        public StubChannel(string name, SendResult? result = null, Exception? ex = null,
            TimeSpan delay = default, ChannelKind kind = ChannelKind.Ntfy, AsyncLatch? latch = null)
        {
            _latch = latch;
            Name = name;
            Kind = kind;
            _result = result;
            _throw = ex;
            _delay = delay;
        }

        public async Task<SendResult> SendAsync(AlertMessage message, CancellationToken ct = default)
        {
            Calls++;
            Last = message;
            if (_delay > TimeSpan.Zero) await Task.Delay(_delay, ct);
            // Trava assíncrona: só libera quando TODOS os participantes estão dentro de SendAsync ao mesmo tempo —
            // prova de paralelismo sem relógio e sem bloquear thread (em série, o 1º ficaria preso → timeout).
            if (_latch is not null) await _latch.ArriveAndWaitAsync();
            if (_throw is not null) throw _throw;
            return _result ?? SendResult.Success(Name);
        }
    }

    /// <summary>Latch assíncrono: libera todos quando N chegaram. Não bloqueia thread do pool.</summary>
    private sealed class AsyncLatch(int participants)
    {
        private int _arrived;
        private readonly TaskCompletionSource _open = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task ArriveAndWaitAsync()
        {
            if (Interlocked.Increment(ref _arrived) >= participants) _open.TrySetResult();
            return _open.Task;
        }
    }

    private static AlertMessage Critical(string key = "det:FS01") =>
        new(AlertSeverity.Critical, "t", "s", "r", Array.Empty<string>()) { DedupKey = key };

    [Fact]
    public async Task Fans_out_to_every_enabled_channel()
    {
        var a = new StubChannel("ntfy");
        var b = new StubChannel("Teams");
        var c = new StubChannel("Telegram");

        var report = await new NotificationDispatcher(new[] { a, b, c }).DispatchAsync(Critical(), T0);

        Assert.True(report.Sent);
        Assert.Equal(1, a.Calls);
        Assert.Equal(1, b.Calls);
        Assert.Equal(1, c.Calls);
        Assert.Equal(3, report.Results.Count);
    }

    /// <summary>
    /// O requisito mais importante do despachante: durante um ataque, o Teams fora do ar não pode
    /// impedir o push no celular.
    /// </summary>
    [Fact]
    public async Task One_broken_channel_does_not_silence_the_others()
    {
        var quebrado = new StubChannel("Teams", SendResult.Failure("503"));
        var ok = new StubChannel("ntfy");

        var report = await new NotificationDispatcher(new[] { quebrado, ok }).DispatchAsync(Critical(), T0);

        Assert.True(report.Sent);                       // houve entrega
        Assert.Equal(1, ok.Calls);
        Assert.Single(report.Failures);
        Assert.Contains("Teams: 503", report.Failures);
    }

    [Fact]
    public async Task A_channel_that_throws_is_isolated_too()
    {
        var explode = new StubChannel("Email", ex: new InvalidOperationException("config inválida"));
        var ok = new StubChannel("ntfy");

        var report = await new NotificationDispatcher(new[] { explode, ok }).DispatchAsync(Critical(), T0);

        Assert.True(report.Sent);
        Assert.Equal(1, ok.Calls);
        Assert.Contains(report.Failures, f => f.Contains("config inválida"));
    }

    [Fact]
    public async Task All_channels_failing_reports_not_sent_but_never_throws()
    {
        var report = await new NotificationDispatcher(new[]
        {
            new StubChannel("a", SendResult.Failure("x")),
            new StubChannel("b", ex: new Exception("y"))
        }).DispatchAsync(Critical(), T0);

        Assert.False(report.Sent);
        Assert.Equal(2, report.Failures.Count());
    }

    [Fact]
    public async Task Below_minimum_severity_nothing_is_sent()
    {
        var ch = new StubChannel("ntfy");
        var msg = new AlertMessage(AlertSeverity.Warning, "t", "s", "r", Array.Empty<string>());

        var report = await new NotificationDispatcher(new[] { ch }).DispatchAsync(msg, T0);

        Assert.False(report.Sent);
        Assert.Equal(NotificationPolicy.Decision.BelowSeverity, report.Decision);
        Assert.Equal(0, ch.Calls);   // não gasta chamada de rede à toa
    }

    [Fact]
    public async Task Flood_from_the_same_actor_is_suppressed_at_the_dispatcher()
    {
        var ch = new StubChannel("ntfy");
        var d = new NotificationDispatcher(new[] { ch }, new NotificationPolicy { FloodWindow = TimeSpan.FromMinutes(10) });

        await d.DispatchAsync(Critical(), T0);
        var segundo = await d.DispatchAsync(Critical(), T0.AddMinutes(2));

        Assert.Equal(NotificationPolicy.Decision.Flooded, segundo.Decision);
        Assert.Equal(1, ch.Calls);   // um ataque = um alerta, não cem
    }

    [Fact]
    public async Task Different_servers_are_not_suppressed_by_each_other()
    {
        var ch = new StubChannel("ntfy");
        var d = new NotificationDispatcher(new[] { ch });

        await d.DispatchAsync(Critical("det:FS01"), T0);
        await d.DispatchAsync(Critical("det:FS02"), T0.AddSeconds(5));

        Assert.Equal(2, ch.Calls);
    }

    /// <summary>
    /// Quatro canais atravessam uma barreira que só abre quando os quatro estão dentro de SendAsync ao mesmo
    /// tempo. Em série, o primeiro ficaria preso na barreira e o teste falharia por timeout — determinístico,
    /// sem medir relógio (a versão anterior media < 600 ms e oscilava em runner lento).
    /// </summary>
    [Fact]
    public async Task Channels_run_in_parallel()
    {
        var latch = new AsyncLatch(4);
        var canais = Enumerable.Range(0, 4).Select(i => new StubChannel($"c{i}", latch: latch)).ToArray();

        var dispatch = new NotificationDispatcher(canais).DispatchAsync(Critical(), T0);
        var done = await Task.WhenAny(dispatch, Task.Delay(TimeSpan.FromSeconds(10)));

        Assert.True(ReferenceEquals(done, dispatch), "canais em série: a trava de 4 nunca abriu");
        await dispatch;
        Assert.All(canais, c => Assert.Equal(1, c.Calls));
    }

    [Fact]
    public async Task No_channel_configured_is_not_an_error()
    {
        var report = await new NotificationDispatcher(Array.Empty<INotificationChannel>())
            .DispatchAsync(Critical(), T0);

        Assert.False(report.Sent);
        Assert.Empty(report.Results);
    }

    [Fact]
    public async Task Test_button_bypasses_the_policy()
    {
        var ch = new StubChannel("ntfy");
        // Política padrão só deixa passar Critical; a mensagem de teste é Info e ainda assim sai.
        var r = await NotificationDispatcher.TestAsync(ch);

        Assert.True(r.Ok);
        Assert.Equal(AlertSeverity.Info, ch.Last!.Severity);
        Assert.Contains("ntfy", ch.Last.ShortBody);
    }

    [Fact]
    public async Task Test_button_reports_failure_instead_of_crashing_the_page()
    {
        var ch = new StubChannel("Teams", ex: new HttpRequestException("host desconhecido"));
        var r = await NotificationDispatcher.TestAsync(ch);

        Assert.False(r.Ok);
        Assert.Contains("host desconhecido", r.Detail);
    }
}
