using RansomGuard.Core.Notifications;

namespace RansomGuard.Server.Notifications;

/// <summary>Um config que não pôde virar canal, e por quê — para a tela avisar o admin.</summary>
public sealed record SkippedChannel(ChannelKind Kind, string Reason);

/// <summary>O resultado de montar os canais a partir do que está salvo.</summary>
public sealed record ChannelSet(
    IReadOnlyList<INotificationChannel> Channels,
    IReadOnlyList<SkippedChannel> Skipped);

/// <summary>
/// Transforma o que o admin salvou (<see cref="NotificationChannelConfig"/>) nos canais reais que o
/// <see cref="NotificationDispatcher"/> usa. É a peça que decide "este config vira canal?" — e a
/// resposta honesta, quando o config está pela metade, é **pular com motivo**, não criar um canal
/// que vai falhar em silêncio no meio de um ataque.
///
/// Lógica pura: entram os configs + um <see cref="HttpClient"/> e um <see cref="ISmtpTransport"/>,
/// saem os canais. Testável sem rede.
/// </summary>
public sealed class ChannelFactory
{
    private readonly HttpClient _http;
    private readonly ISmtpTransport _smtp;

    public ChannelFactory(HttpClient http, ISmtpTransport smtp)
    {
        _http = http;
        _smtp = smtp;
    }

    public ChannelSet Build(IEnumerable<NotificationChannelConfig> configs)
    {
        var canais = new List<INotificationChannel>();
        var pulados = new List<SkippedChannel>();

        foreach (var c in configs)
        {
            // Canal desabilitado não é erro nem aviso — é a escolha do admin. Só ignora.
            if (!c.Enabled) continue;

            var (canal, motivo) = TryBuild(c);
            if (canal is not null) canais.Add(canal);
            else pulados.Add(new SkippedChannel(c.Kind, motivo!));
        }

        return new ChannelSet(canais, pulados);
    }

    /// <returns>(canal, null) quando OK; (null, motivo) quando o config está incompleto.</returns>
    private (INotificationChannel?, string?) TryBuild(NotificationChannelConfig c) => c.Kind switch
    {
        ChannelKind.Ntfy => BuildNtfy(c),
        ChannelKind.Webhook => BuildWebhook(c),
        ChannelKind.Telegram => BuildTelegram(c),
        ChannelKind.Email => BuildEmail(c),
        _ => (null, "Tipo de canal desconhecido.")
    };

    private (INotificationChannel?, string?) BuildNtfy(NotificationChannelConfig c)
    {
        if (string.IsNullOrWhiteSpace(c.NtfyServer))
            return (null, "Falta o endereço do servidor ntfy.");
        if (string.IsNullOrWhiteSpace(c.NtfyTopic))
            return (null, "Falta o tópico ntfy.");
        return (new NtfyChannel(_http, c.NtfyServer, c.NtfyTopic, NullIfBlank(c.NtfyToken)), null);
    }

    private (INotificationChannel?, string?) BuildWebhook(NotificationChannelConfig c)
    {
        if (string.IsNullOrWhiteSpace(c.WebhookUrl))
            return (null, "Falta a URL do webhook (Teams ou Slack).");
        return (new WebhookChannel(_http, c.WebhookUrl, c.WebhookFormat), null);
    }

    private (INotificationChannel?, string?) BuildTelegram(NotificationChannelConfig c)
    {
        if (string.IsNullOrWhiteSpace(c.TelegramBotToken))
            return (null, "Falta o token do bot (peça ao @BotFather).");
        if (string.IsNullOrWhiteSpace(c.TelegramChatId))
            return (null, "Falta o Chat ID.");
        return (new TelegramChannel(_http, c.TelegramBotToken, c.TelegramChatId), null);
    }

    private (INotificationChannel?, string?) BuildEmail(NotificationChannelConfig c)
    {
        if (string.IsNullOrWhiteSpace(c.SmtpHost))
            return (null, "Falta o servidor de e-mail (SMTP).");
        if (string.IsNullOrWhiteSpace(c.SmtpFrom))
            return (null, "Falta o remetente.");

        var destinatarios = (c.SmtpTo ?? "")
            .Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (destinatarios.Length == 0)
            return (null, "Nenhum destinatário de e-mail configurado.");

        var settings = new SmtpSettings(c.SmtpHost, c.SmtpPort, c.SmtpFrom, destinatarios)
        {
            User = NullIfBlank(c.SmtpUser),
            Password = NullIfBlank(c.SmtpPassword),
            UseSsl = c.SmtpSsl
        };
        return (new EmailChannel(_smtp, settings), null);
    }

    private static string? NullIfBlank(string? v) => string.IsNullOrWhiteSpace(v) ? null : v;
}
