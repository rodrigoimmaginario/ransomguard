using RansomGuard.Server.Ingestion;

namespace RansomGuard.Server.Ingestion;

/// <summary>
/// R2 — dá um chamador de produção para <see cref="IngestionService.CheckHeartbeatsAsync"/>.
///
/// A lógica de "agente silencioso além do limite = alerta de tamper" (resposta ao cenário EDR
/// killer) existia e era testada, mas nada a acionava no painel: em produção, um agente morto
/// nunca gerava alerta. Este serviço roda a varredura periodicamente.
///
/// Duas decisões de robustez:
/// <list type="bullet">
///   <item><b>Escopo por volta.</b> O <see cref="IngestionService"/> é scoped (usa o DbContext),
///   então cada varredura resolve o serviço num escopo próprio.</item>
///   <item><b>Nunca derruba o host.</b> Uma exceção na varredura vira log e a próxima volta tenta
///   de novo — um monitor que morre em silêncio seria o mesmo problema que ele existe para evitar.</item>
/// </list>
/// </summary>
public sealed class HeartbeatMonitor : BackgroundService
{
    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<HeartbeatMonitor> _log;
    private readonly TimeSpan _interval;
    private readonly TimeSpan _maxSilence;

    /// <param name="interval">De quanto em quanto tempo varrer. Default: 1 min.</param>
    /// <param name="maxSilence">Silêncio que caracteriza tamper. Default: 10 min (casa com o simulador).</param>
    public HeartbeatMonitor(
        IServiceScopeFactory scopes, ILogger<HeartbeatMonitor> log,
        TimeSpan? interval = null, TimeSpan? maxSilence = null)
    {
        _scopes = scopes;
        _log = log;
        _interval = interval ?? TimeSpan.FromMinutes(1);
        _maxSilence = maxSilence ?? TimeSpan.FromMinutes(10);
    }

    /// <summary>
    /// Uma varredura. Resolve o serviço num escopo e executa a checagem; falha vira log e retorna 0,
    /// nunca propaga. Exposto para teste sem subir o host.
    /// </summary>
    public async Task<int> RunOnceAsync(DateTime now, CancellationToken ct = default)
    {
        try
        {
            using var scope = _scopes.CreateScope();
            var svc = scope.ServiceProvider.GetRequiredService<IngestionService>();
            return await svc.CheckHeartbeatsAsync(now, _maxSilence, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Falha na varredura de heartbeats (será retentada).");
            return 0;
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation("Monitor de heartbeats iniciado (intervalo {Interval}, silêncio {Silence}).",
            _interval, _maxSilence);

        while (!stoppingToken.IsCancellationRequested)
        {
            var raised = await RunOnceAsync(DateTime.UtcNow, stoppingToken);
            if (raised > 0)
                _log.LogWarning("{N} agente(s) silencioso(s) além do limite — alerta de tamper disparado.", raised);

            try { await Task.Delay(_interval, stoppingToken); }
            catch (TaskCanceledException) { break; }
        }
    }
}
