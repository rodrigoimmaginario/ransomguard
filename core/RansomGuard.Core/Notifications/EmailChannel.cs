namespace RansomGuard.Core.Notifications;

/// <summary>Dados do servidor de e-mail. Guardados no painel; a senha nunca volta para a tela.</summary>
public sealed record SmtpSettings(
    string Host,
    int Port,
    string From,
    IReadOnlyList<string> To)
{
    public string? User { get; init; }
    public string? Password { get; init; }
    public bool UseSsl { get; init; } = true;
}

/// <summary>
/// Transporte SMTP. Existe como interface para que o canal seja testável sem servidor de e-mail —
/// a implementação real (SmtpClient) fica no painel, onde há o ambiente para isso.
/// </summary>
public interface ISmtpTransport
{
    Task SendAsync(SmtpSettings settings, string subject, string body, CancellationToken ct);
}

/// <summary>
/// Canal de e-mail — o denominador comum: toda empresa já tem servidor de e-mail, então não há
/// custo nem dependência externa nova. É o mais lento dos quatro (pode levar minutos), por isso a
/// UI o apresenta como complemento, não como canal principal de resposta a incidente.
/// </summary>
public sealed class EmailChannel : INotificationChannel
{
    private readonly ISmtpTransport _transport;
    private readonly SmtpSettings _settings;

    public ChannelKind Kind => ChannelKind.Email;
    public string Name => "E-mail";

    public EmailChannel(ISmtpTransport transport, SmtpSettings settings)
    {
        _transport = transport;
        _settings = settings;
    }

    public async Task<SendResult> SendAsync(AlertMessage message, CancellationToken ct = default)
    {
        if (_settings.To.Count == 0)
            return SendResult.Failure("Nenhum destinatário configurado.");

        try
        {
            await _transport.SendAsync(_settings, message.Title, message.RichBody, ct);
            return SendResult.Success(Name);
        }
        catch (OperationCanceledException)
        {
            return SendResult.Failure("O servidor de e-mail não respondeu a tempo.");
        }
        catch (Exception ex)
        {
            return SendResult.Failure($"Falha no envio de e-mail: {ex.Message}");
        }
    }
}
