using RansomGuard.Core.Detection;
using RansomGuard.Core.Notifications;
using RansomGuard.Server.Notifications;

namespace RansomGuard.Server.Alerts;

/// <summary>Destino de um alerta (e-mail/SIEM/painel). O envio real é integração; a interface
/// isola a decisão de alertar (testável) do meio de entrega.</summary>
public interface IAlertSink
{
    Task SendAsync(string subject, string body, CancellationToken ct = default);
}

/// <summary>Coleta alertas em memória — usada em testes e no simulador.</summary>
public sealed class CollectingAlertSink : IAlertSink
{
    public List<(string Subject, string Body)> Sent { get; } = new();
    public Task SendAsync(string subject, string body, CancellationToken ct = default)
    {
        Sent.Add((subject, body));
        return Task.CompletedTask;
    }
}

/// <summary>
/// Decide quando alertar e formata o alerta. Regra da fatia 2: detecção de confiança **High**
/// vira alerta imediato; heartbeat perdido vira alerta de tamper. A escada de resposta automática
/// (agir) é da fatia 4 — aqui só avisamos.
/// </summary>
public sealed class AlertEngine
{
    private readonly IAlertSink _sink;
    private readonly INotificationSink? _notifications;

    /// <param name="sink">Saída de diagnóstico (log/painel) — sempre presente.</param>
    /// <param name="notifications">
    /// Canais do admin (F13). Opcional: sem ele, o comportamento é o anterior (só o sink de
    /// diagnóstico), o que mantém os testes existentes e o painel sem canais funcionando igual.
    /// </param>
    public AlertEngine(IAlertSink sink, INotificationSink? notifications = null)
    {
        _sink = sink;
        _notifications = notifications;
    }

    /// <summary>Alerta apenas incidentes de alta confiança (evita ruído no free tier).</summary>
    public bool ShouldAlert(Detection d) => d.Confidence == Confidence.High;

    public async Task RaiseDetectionAsync(Detection d, CancellationToken ct = default)
    {
        // Diagnóstico legível (log/painel), como antes.
        var subject = $"[RansomGuard] Incidente em {d.Server} — {d.Confidence}";
        var body =
            $"Servidor: {d.Server}\n" +
            $"Usuário: {d.User}\n" +
            $"Origem (IP): {d.SourceIp}\n" +
            $"Share: {d.Share}\n" +
            $"Arquivos afetados: {d.AffectedFiles}\n" +
            $"Razões: {string.Join(", ", d.Reasons)}\n" +
            $"Janela: {d.FirstAt:u} → {d.LastAt:u}";
        await _sink.SendAsync(subject, body, ct);

        // E o alerta rico nos canais do admin — com severidade e dedup, que a string jogava fora.
        if (_notifications is not null)
            await _notifications.DispatchAsync(AlertComposer.ForDetection(d), DateTime.UtcNow, ct);
    }

    public async Task RaiseTamperAsync(string server, DateTime lastBeat, CancellationToken ct = default)
    {
        var subject = $"[RansomGuard] Agente silencioso em {server} — possível tamper";
        var body =
            $"O agente de {server} parou de reportar (último batimento {lastBeat:u}).\n" +
            "Agente morto pode indicar EDR killer / adulteração. Verifique o servidor.";
        await _sink.SendAsync(subject, body, ct);

        if (_notifications is not null)
        {
            var now = DateTime.UtcNow;
            await _notifications.DispatchAsync(AlertComposer.ForAgentSilent(server, lastBeat, now), now, ct);
        }
    }
}
