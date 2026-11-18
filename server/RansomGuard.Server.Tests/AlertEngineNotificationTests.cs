using RansomGuard.Core.Detection;
using RansomGuard.Core.Notifications;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Notifications;
using DetectionModel = RansomGuard.Core.Detection.Detection;

namespace RansomGuard.Server.Tests;

/// <summary>
/// O elo que faltava: um incidente detectado precisa virar alerta **nos canais do admin**, não só
/// no log. E o alerta que chega ali é o rico (severidade, dedup) — não a string que a versão
/// anterior mandava.
/// </summary>
public class AlertEngineNotificationTests
{
    private sealed class SpySink : INotificationSink
    {
        public readonly List<AlertMessage> Dispatched = new();
        public Task<DispatchReport> DispatchAsync(AlertMessage m, DateTime now, CancellationToken ct = default)
        {
            Dispatched.Add(m);
            return Task.FromResult(new DispatchReport(true, NotificationPolicy.Decision.Send,
                Array.Empty<(string, SendResult)>()));
        }
        public Task<SendResult> TestAsync(ChannelKind kind, CancellationToken ct = default)
            => Task.FromResult(SendResult.Success(kind.ToString()));
    }

    private static readonly DateTime T0 = new(2026, 7, 26, 14, 0, 0, DateTimeKind.Utc);

    private static DetectionModel HighIncident() =>
        new("FS01", @"CORP\vendas1", "10.0.9.66", @"\\FS01\Financeiro", Confidence.High,
            new HashSet<DetectionReason> { DetectionReason.CanaryTouched }, 120, T0, T0.AddSeconds(30));

    [Fact]
    public async Task Incidente_dispara_alerta_rico_nos_canais()
    {
        var spy = new SpySink();
        var engine = new AlertEngine(new CollectingAlertSink(), spy);

        await engine.RaiseDetectionAsync(HighIncident());

        var m = Assert.Single(spy.Dispatched);
        Assert.Equal(AlertSeverity.Critical, m.Severity);      // High → Critical
        Assert.Contains("FS01", m.Title);
        Assert.NotNull(m.DedupKey);                            // dá para agrupar durante a tempestade
    }

    [Fact]
    public async Task Agente_silencioso_tambem_notifica()
    {
        var spy = new SpySink();
        var engine = new AlertEngine(new CollectingAlertSink(), spy);

        await engine.RaiseTamperAsync("FS02", T0.AddMinutes(-25), default);

        var m = Assert.Single(spy.Dispatched);
        Assert.Equal(AlertSeverity.Critical, m.Severity);
        Assert.Contains("FS02", m.Title);
    }

    [Fact]
    public async Task O_sink_de_log_continua_recebendo()
    {
        var log = new CollectingAlertSink();
        var engine = new AlertEngine(log, new SpySink());

        await engine.RaiseDetectionAsync(HighIncident());

        Assert.Single(log.Sent);   // diagnóstico nunca é substituído pelos canais
    }

    /// <summary>
    /// Sem canais configurados (o INotificationSink é opcional), o comportamento é o anterior: só o
    /// log. O painel de um tester que nunca abriu a aba funciona exatamente como antes.
    /// </summary>
    [Fact]
    public async Task Sem_sink_de_notificacao_so_o_log_e_usado()
    {
        var log = new CollectingAlertSink();
        var engine = new AlertEngine(log);   // sem notificações

        await engine.RaiseDetectionAsync(HighIncident());

        Assert.Single(log.Sent);
    }
}
