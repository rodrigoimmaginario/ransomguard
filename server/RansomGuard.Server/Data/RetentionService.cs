using Microsoft.EntityFrameworkCore;

namespace RansomGuard.Server.Data;

/// <summary>
/// F35 — retenção. Sem ela o SQLite cresce para sempre e o painel degrada em meses. Lógica pura em
/// <see cref="Retention.PurgeAsync"/> (testável); o serviço hospedado só a agenda (uma vez por dia, com atraso inicial).
/// Padrões: incidentes 90 dias, registros de postura 30 dias (o mais recente de cada servidor nunca é apagado).
/// </summary>
public static class Retention
{
    public static async Task<(int Incidents, int Postures)> PurgeAsync(RansomGuardDb db, DateTime now, int incidentDays, int postureDays, CancellationToken ct = default)
    {
        var incidentCutoff = now.AddDays(-Math.Max(1, incidentDays));
        var postureCutoff = now.AddDays(-Math.Max(1, postureDays));

        var oldIncidents = await db.Detections.Where(d => d.At < incidentCutoff).ToListAsync(ct);
        db.Detections.RemoveRange(oldIncidents);   // ResponseActions caem por cascata

        var latestPerServer = await db.PostureRecords.GroupBy(p => p.ServerId).Select(g => g.Max(p => p.Id)).ToListAsync(ct);
        var oldPostures = await db.PostureRecords.Where(p => p.At < postureCutoff && !latestPerServer.Contains(p.Id)).ToListAsync(ct);
        db.PostureRecords.RemoveRange(oldPostures);

        await db.SaveChangesAsync(ct);
        return (oldIncidents.Count, oldPostures.Count);
    }
}

public sealed class RetentionService(IServiceScopeFactory scopes, IConfiguration cfg, ILogger<RetentionService> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var incidentDays = cfg.GetValue("Retention:IncidentDays", 90);
        var postureDays = cfg.GetValue("Retention:PostureDays", 30);
        await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken);   // deixa o painel subir antes
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopes.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<RansomGuardDb>();
                var (i, p) = await Retention.PurgeAsync(db, DateTime.UtcNow, incidentDays, postureDays, stoppingToken);
                if (i + p > 0) log.LogInformation("Retenção: {I} incidente(s) e {P} registro(s) de postura removidos.", i, p);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                log.LogError(ex, "Retenção falhou; tenta de novo amanhã.");
            }
            await Task.Delay(TimeSpan.FromHours(24), stoppingToken);
        }
    }
}
