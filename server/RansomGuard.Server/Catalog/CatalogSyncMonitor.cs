namespace RansomGuard.Server.Catalog;

/// <summary>
/// F28 — roda o <see cref="CatalogSyncService"/> na partida e periodicamente, para o cache do relay
/// acompanhar a origem publicada. Nunca derruba o host: falha vira log e a próxima volta tenta de
/// novo (a invariante fail-safe do sync garante que o cache atual é preservado).
///
/// Só é registrado quando há chave pública de catálogo configurada — sem ela, não há o que
/// verificar, e o painel serve 404 (o agente segue na semente). Coerente com o fail-closed do agente.
/// </summary>
public sealed class CatalogSyncMonitor : BackgroundService
{
    private readonly CatalogSyncService _sync;
    private readonly ILogger<CatalogSyncMonitor> _log;
    private static readonly TimeSpan Interval = TimeSpan.FromHours(6);

    public CatalogSyncMonitor(CatalogSyncService sync, ILogger<CatalogSyncMonitor> log)
    {
        _sync = sync;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation("Sync do catálogo iniciado (intervalo {Interval}).", Interval);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (await _sync.SyncAsync(stoppingToken))
                    _log.LogInformation("Catálogo atualizado a partir da origem publicada.");
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Falha no sync do catálogo (será retentado).");
            }

            try { await Task.Delay(Interval, stoppingToken); }
            catch (TaskCanceledException) { break; }
        }
    }
}
