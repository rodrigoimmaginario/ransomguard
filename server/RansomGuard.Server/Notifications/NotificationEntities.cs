using RansomGuard.Core.Notifications;

namespace RansomGuard.Server.Notifications;

/// <summary>
/// Um canal configurado pelo admin. Uma linha por tipo (ntfy, webhook, Telegram, e-mail) — a tabela
/// é aditiva ao modelo existente, sem tocar em nada que já está em produção.
///
/// Segredos (token, senha SMTP) ficam aqui em claro no SQLite local: o banco já vive dentro do
/// servidor do cliente e é protegido pelo ACL da máquina, o mesmo lugar onde ficam as credenciais
/// do serviço. A UI nunca devolve o segredo salvo para a tela (só um indicador de "configurado").
/// </summary>
public sealed class NotificationChannelConfig
{
    public int Id { get; set; }
    public ChannelKind Kind { get; set; }
    public bool Enabled { get; set; }

    // ntfy
    public string? NtfyServer { get; set; }
    public string? NtfyTopic { get; set; }
    public string? NtfyToken { get; set; }

    // Webhook (Teams / Slack)
    public string? WebhookUrl { get; set; }
    /// <summary>Null = detectar pela URL.</summary>
    public WebhookFormat? WebhookFormat { get; set; }

    // Telegram
    public string? TelegramBotToken { get; set; }
    public string? TelegramChatId { get; set; }

    // E-mail
    public string? SmtpHost { get; set; }
    public int SmtpPort { get; set; } = 587;
    public bool SmtpSsl { get; set; } = true;
    public string? SmtpUser { get; set; }
    public string? SmtpPassword { get; set; }
    public string? SmtpFrom { get; set; }
    /// <summary>Destinatários separados por vírgula ou ponto-e-vírgula.</summary>
    public string? SmtpTo { get; set; }

    // Diagnóstico do último envio, para a tela mostrar se o canal está de pé.
    public DateTime? LastAttemptAt { get; set; }
    public bool? LastAttemptOk { get; set; }
    public string? LastAttemptDetail { get; set; }
}

/// <summary>Preferências de quando notificar. Linha única (Id = 1).</summary>
public sealed class NotificationSettings
{
    public int Id { get; set; } = 1;

    /// <summary>Severidade mínima. Padrão Critical — o produto prefere silêncio a ruído.</summary>
    public AlertSeverity MinimumSeverity { get; set; } = AlertSeverity.Critical;

    /// <summary>Janela anti-flood, em minutos. Um ataque gera um alerta, não cem.</summary>
    public int FloodWindowMinutes { get; set; } = 10;

    /// <summary>Avisar quando um agente parar de reportar (possível tamper/EDR killer).</summary>
    public bool NotifyAgentSilent { get; set; } = true;
}
