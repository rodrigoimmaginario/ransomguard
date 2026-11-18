namespace RansomGuard.Core.Notifications;

/// <summary>Tipos de canal que o admin pode habilitar. Todos gratuitos (requisito do produto).</summary>
public enum ChannelKind
{
    /// <summary>Push no celular; pode ser self-hosted (recomendado) ou ntfy.sh.</summary>
    Ntfy,
    /// <summary>Webhook de chat: Microsoft Teams (Power Automate) ou Slack.</summary>
    Webhook,
    Telegram,
    Email
}

/// <summary>Resultado de uma tentativa de envio — legível para mostrar na tela de configuração.</summary>
/// <param name="Ok">Entregue?</param>
/// <param name="Detail">Mensagem para o admin (sucesso ou motivo da falha, em português).</param>
public sealed record SendResult(bool Ok, string Detail)
{
    public static SendResult Success(string channel) => new(true, $"Entregue via {channel}.");
    public static SendResult Failure(string detail) => new(false, detail);
}

/// <summary>
/// Um canal de notificação configurado. Implementações fazem o envio real (HTTP/SMTP); a interface
/// mantém o resto do sistema agnóstico e permite testar sem rede.
/// </summary>
public interface INotificationChannel
{
    ChannelKind Kind { get; }
    /// <summary>Nome amigável para logs e para a tela ("ntfy", "Teams", …).</summary>
    string Name { get; }
    Task<SendResult> SendAsync(AlertMessage message, CancellationToken ct = default);
}
