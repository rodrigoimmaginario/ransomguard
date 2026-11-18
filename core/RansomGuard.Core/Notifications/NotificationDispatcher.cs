namespace RansomGuard.Core.Notifications;

/// <summary>O que aconteceu com um alerta ao passar pelo despachante.</summary>
/// <param name="Sent">Houve pelo menos uma entrega?</param>
/// <param name="Decision">Por que foi (ou não foi) despachado.</param>
/// <param name="Results">Resultado por canal, na ordem em que foram configurados.</param>
public sealed record DispatchReport(
    bool Sent,
    NotificationPolicy.Decision Decision,
    IReadOnlyList<(string Channel, SendResult Result)> Results)
{
    public IEnumerable<string> Failures =>
        Results.Where(r => !r.Result.Ok).Select(r => $"{r.Channel}: {r.Result.Detail}");
}

/// <summary>
/// Aplica a política (severidade mínima + anti-flood) e distribui o alerta para todos os canais
/// habilitados.
///
/// Regra de ouro: **um canal quebrado não pode calar os outros**. Se o Teams está fora do ar durante
/// um ataque, o push no celular precisa sair mesmo assim — por isso cada canal é isolado e as falhas
/// viram relatório, não exceção.
/// </summary>
public sealed class NotificationDispatcher
{
    private readonly IReadOnlyList<INotificationChannel> _channels;
    private readonly NotificationPolicy _policy;

    public NotificationDispatcher(IEnumerable<INotificationChannel> channels, NotificationPolicy? policy = null)
    {
        _channels = channels.ToList();
        _policy = policy ?? new NotificationPolicy();
    }

    public async Task<DispatchReport> DispatchAsync(AlertMessage message, DateTime now, CancellationToken ct = default)
    {
        var decision = _policy.Evaluate(message, now);
        if (decision != NotificationPolicy.Decision.Send)
            return new DispatchReport(false, decision, Array.Empty<(string, SendResult)>());

        // Envio em paralelo: durante um ataque, quatro canais em série custam segundos que importam.
        var tasks = _channels.Select(async c =>
        {
            try
            {
                return (c.Name, await c.SendAsync(message, ct));
            }
            catch (Exception ex)
            {
                // Um canal mal configurado pode lançar algo inesperado; ele falha sozinho.
                return (c.Name, SendResult.Failure($"Erro inesperado: {ex.Message}"));
            }
        });

        var results = await Task.WhenAll(tasks);
        return new DispatchReport(results.Any(r => r.Item2.Ok), decision, results);
    }

    /// <summary>
    /// Envia a mensagem de teste do botão "Enviar teste" — ignora a política de propósito: o admin
    /// clicou agora e precisa da resposta agora, mesmo que a severidade mínima seja Critical.
    /// </summary>
    public static async Task<SendResult> TestAsync(INotificationChannel channel, CancellationToken ct = default)
    {
        try
        {
            return await channel.SendAsync(AlertComposer.ForTest(channel.Name), ct);
        }
        catch (Exception ex)
        {
            return SendResult.Failure($"Erro inesperado: {ex.Message}");
        }
    }
}
