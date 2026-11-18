using RansomGuard.Core.Notifications;
using RansomGuard.Server.Notifications;

namespace RansomGuard.Server.Tests;

/// <summary>
/// A fábrica decide se o que o admin salvou vira um canal de verdade. A regra que importa: config
/// pela metade é **pulado com motivo**, nunca vira um canal que falha em silêncio no meio de um
/// ataque — que é o pior momento para descobrir que o alerta nunca sairia.
/// </summary>
public class ChannelFactoryTests
{
    private sealed class NoopSmtp : ISmtpTransport
    {
        public Task SendAsync(SmtpSettings s, string subject, string body, CancellationToken ct) => Task.CompletedTask;
    }

    private static ChannelFactory Factory() => new(new HttpClient(), new NoopSmtp());

    private static NotificationChannelConfig Enabled(ChannelKind kind) => new() { Kind = kind, Enabled = true };

    [Fact]
    public void Canal_desabilitado_nao_vira_canal_nem_aviso()
    {
        var cfg = new NotificationChannelConfig
        {
            Kind = ChannelKind.Ntfy, Enabled = false,
            NtfyServer = "https://ntfy.corp", NtfyTopic = "rg"
        };

        var set = Factory().Build(new[] { cfg });

        Assert.Empty(set.Channels);
        Assert.Empty(set.Skipped);   // desabilitar é escolha do admin, não erro
    }

    [Fact]
    public void Ntfy_completo_vira_canal()
    {
        var cfg = Enabled(ChannelKind.Ntfy);
        cfg.NtfyServer = "https://ntfy.corp.local";
        cfg.NtfyTopic = "ransomguard";

        var set = Factory().Build(new[] { cfg });

        Assert.Single(set.Channels);
        Assert.Equal(ChannelKind.Ntfy, set.Channels[0].Kind);
    }

    [Fact]
    public void Ntfy_sem_topico_e_pulado_com_motivo()
    {
        var cfg = Enabled(ChannelKind.Ntfy);
        cfg.NtfyServer = "https://ntfy.corp.local";
        // topic faltando

        var set = Factory().Build(new[] { cfg });

        Assert.Empty(set.Channels);
        var pulado = Assert.Single(set.Skipped);
        Assert.Equal(ChannelKind.Ntfy, pulado.Kind);
        Assert.Contains("tópico", pulado.Reason);
    }

    [Fact]
    public void Webhook_completo_vira_canal_e_detecta_o_formato()
    {
        var cfg = Enabled(ChannelKind.Webhook);
        cfg.WebhookUrl = "https://prod.westus.logic.azure.com/workflows/x";

        var set = Factory().Build(new[] { cfg });

        Assert.Single(set.Channels);
        Assert.Equal("Microsoft Teams", set.Channels[0].Name);
    }

    [Fact]
    public void Webhook_sem_url_e_pulado()
    {
        var set = Factory().Build(new[] { Enabled(ChannelKind.Webhook) });
        Assert.Contains("URL", Assert.Single(set.Skipped).Reason);
    }

    [Fact]
    public void Telegram_precisa_de_token_e_chat_id()
    {
        var soToken = Enabled(ChannelKind.Telegram);
        soToken.TelegramBotToken = "123:ABC";

        var set = Factory().Build(new[] { soToken });

        Assert.Empty(set.Channels);
        Assert.Contains("Chat ID", Assert.Single(set.Skipped).Reason);
    }

    [Fact]
    public void Telegram_completo_vira_canal()
    {
        var cfg = Enabled(ChannelKind.Telegram);
        cfg.TelegramBotToken = "123:ABC";
        cfg.TelegramChatId = "-100999";

        Assert.Single(Factory().Build(new[] { cfg }).Channels);
    }

    [Fact]
    public void Email_separa_destinatarios_por_virgula_e_ponto_e_virgula()
    {
        var cfg = Enabled(ChannelKind.Email);
        cfg.SmtpHost = "smtp.corp.local";
        cfg.SmtpFrom = "rg@corp.local";
        cfg.SmtpTo = "a@corp.local, b@corp.local; c@corp.local";

        var set = Factory().Build(new[] { cfg });

        Assert.Single(set.Channels);
        Assert.Equal("E-mail", set.Channels[0].Name);
    }

    [Fact]
    public void Email_sem_destinatario_e_pulado()
    {
        var cfg = Enabled(ChannelKind.Email);
        cfg.SmtpHost = "smtp.corp.local";
        cfg.SmtpFrom = "rg@corp.local";
        cfg.SmtpTo = "   ";

        Assert.Contains("destinatário", Assert.Single(Factory().Build(new[] { cfg }).Skipped).Reason);
    }

    [Fact]
    public void Email_sem_host_e_pulado()
    {
        var cfg = Enabled(ChannelKind.Email);
        cfg.SmtpFrom = "rg@corp.local";
        cfg.SmtpTo = "a@corp.local";

        Assert.Contains("SMTP", Assert.Single(Factory().Build(new[] { cfg }).Skipped).Reason);
    }

    /// <summary>Um config quebrado não pode impedir os outros de virarem canal.</summary>
    [Fact]
    public void Config_quebrado_nao_derruba_os_bons()
    {
        var bom = Enabled(ChannelKind.Ntfy);
        bom.NtfyServer = "https://ntfy.corp"; bom.NtfyTopic = "rg";
        var ruim = Enabled(ChannelKind.Telegram);   // sem token nem chat id

        var set = Factory().Build(new[] { bom, ruim });

        Assert.Single(set.Channels);
        Assert.Single(set.Skipped);
    }

    [Fact]
    public void Varios_canais_habilitados_viram_varios()
    {
        var ntfy = Enabled(ChannelKind.Ntfy);
        ntfy.NtfyServer = "https://n"; ntfy.NtfyTopic = "t";
        var wh = Enabled(ChannelKind.Webhook);
        wh.WebhookUrl = "https://hooks.slack.com/x";

        var set = Factory().Build(new[] { ntfy, wh });

        Assert.Equal(2, set.Channels.Count);
    }
}
