using Microsoft.EntityFrameworkCore;
using RansomGuard.Core.Notifications;
using RansomGuard.Server.Data;

namespace RansomGuard.Server.Notifications;

/// <summary>Recebe o alerta já composto e o entrega nos canais do admin.</summary>
public interface INotificationSink
{
    Task<DispatchReport> DispatchAsync(AlertMessage message, DateTime now, CancellationToken ct = default);
    Task<SendResult> TestAsync(ChannelKind kind, CancellationToken ct = default);
}

/// <summary>
/// A ponte entre um incidente e o bolso do admin. Lê os canais e a preferência salvos, monta os
/// canais reais e despacha — aplicando severidade mínima e anti-flood.
///
/// É **singleton** porque o estado de anti-flood (memória de "este ator já foi avisado") precisa
/// sobreviver entre requisições: durante um ataque, um só incidente vira dezenas de eventos, e sem
/// essa memória viraria dezenas de push idênticos. Como o banco é scoped, cada despacho abre seu
/// próprio escopo para ler a configuração fresca — o admin muda um canal e o próximo alerta já usa.
/// </summary>
public sealed class NotificationDispatchService : INotificationSink
{
    private readonly IServiceScopeFactory _scopes;
    private readonly IHttpClientFactory _httpFactory;
    private readonly ISmtpTransport _smtp;
    private readonly ILogger<NotificationDispatchService> _log;

    // Singleton: guarda o estado de supressão entre alertas.
    private readonly NotificationPolicy _policy = new();

    public NotificationDispatchService(
        IServiceScopeFactory scopes, IHttpClientFactory httpFactory,
        ISmtpTransport smtp, ILogger<NotificationDispatchService> log)
    {
        _scopes = scopes;
        _httpFactory = httpFactory;
        _smtp = smtp;
        _log = log;
    }

    public async Task<DispatchReport> DispatchAsync(AlertMessage message, DateTime now, CancellationToken ct = default)
    {
        var (channels, skipped) = await BuildChannelsAsync(applySettings: true, ct);

        foreach (var s in skipped)
            _log.LogWarning("Canal {Kind} habilitado mas incompleto: {Reason}", s.Kind, s.Reason);

        if (channels.Count == 0)
        {
            // Sem canal configurado, o alerta segue só no log/painel — não é erro, é o estado padrão.
            _log.LogInformation("Alerta sem canal de notificação configurado: {Title}", message.Title);
            return new DispatchReport(false, NotificationPolicy.Decision.Send, Array.Empty<(string, SendResult)>());
        }

        var dispatcher = new NotificationDispatcher(channels, _policy);
        var report = await dispatcher.DispatchAsync(message, now, ct);

        if (report.Decision == NotificationPolicy.Decision.Flooded)
            _log.LogDebug("Alerta suprimido (anti-flood): {Key}", message.DedupKey);
        foreach (var f in report.Failures)
            _log.LogWarning("Falha de canal: {Failure}", f);

        return report;
    }

    public async Task<SendResult> TestAsync(ChannelKind kind, CancellationToken ct = default)
    {
        // O teste não aplica a política (o admin clicou agora, precisa da resposta agora) e monta
        // só o canal pedido.
        var (channels, skipped) = await BuildChannelsAsync(applySettings: false, ct, only: kind);

        var canal = channels.FirstOrDefault(c => c.Kind == kind);
        if (canal is null)
        {
            var motivo = skipped.FirstOrDefault(s => s.Kind == kind)?.Reason
                         ?? "Canal não configurado ou desabilitado.";
            return SendResult.Failure(motivo);
        }

        var result = await NotificationDispatcher.TestAsync(canal, ct);
        await RegistrarTentativaAsync(kind, result, ct);
        return result;
    }

    private async Task<(IReadOnlyList<INotificationChannel> Channels, IReadOnlyList<SkippedChannel> Skipped)>
        BuildChannelsAsync(bool applySettings, CancellationToken ct, ChannelKind? only = null)
    {
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RansomGuardDb>();

        var query = db.NotificationChannels.AsQueryable();
        if (only is { } k) query = query.Where(c => c.Kind == k);
        var configs = await query.ToListAsync(ct);

        if (applySettings)
        {
            var settings = await db.NotificationSettings.FirstOrDefaultAsync(ct);
            if (settings is not null)
            {
                _policy.MinimumSeverity = settings.MinimumSeverity;
                _policy.FloodWindow = TimeSpan.FromMinutes(Math.Max(0, settings.FloodWindowMinutes));
            }
        }

        // Um HttpClient nomeado com timeout curto: durante um ataque, um canal lento não pode
        // segurar os outros (o dispatcher já os roda em paralelo, mas o timeout fecha o pior caso).
        var http = _httpFactory.CreateClient("notifications");
        var set = new ChannelFactory(http, _smtp).Build(configs);
        return (set.Channels, set.Skipped);
    }

    private async Task RegistrarTentativaAsync(ChannelKind kind, SendResult result, CancellationToken ct)
    {
        try
        {
            using var scope = _scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<RansomGuardDb>();
            var cfg = await db.NotificationChannels.FirstOrDefaultAsync(c => c.Kind == kind, ct);
            if (cfg is null) return;

            cfg.LastAttemptAt = DateTime.UtcNow;
            cfg.LastAttemptOk = result.Ok;
            cfg.LastAttemptDetail = result.Detail;
            await db.SaveChangesAsync(ct);
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Não foi possível registrar o resultado do teste de {Kind}", kind);
        }
    }
}
