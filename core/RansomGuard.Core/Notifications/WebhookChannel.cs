using System.Text;
using System.Text.Json;

namespace RansomGuard.Core.Notifications;

/// <summary>Formato do payload — Teams e Slack esperam corpos diferentes.</summary>
public enum WebhookFormat
{
    /// <summary>Slack (e compatíveis): {"text": "..."}.</summary>
    Slack,
    /// <summary>
    /// Microsoft Teams via Power Automate: Adaptive Card. O webhook clássico (Office 365 Connector)
    /// foi descontinuado no fim de 2025 — usar o fluxo "When a Teams webhook request is received".
    /// </summary>
    Teams
}

/// <summary>
/// Canal de chat por webhook — leva o alerta para onde a equipe já conversa. Gratuito nos planos que
/// as empresas normalmente já têm. O formato é detectado pela URL, mas pode ser forçado.
/// </summary>
public sealed class WebhookChannel : INotificationChannel
{
    private readonly HttpClient _http;
    private readonly string _url;
    private readonly WebhookFormat _format;

    public ChannelKind Kind => ChannelKind.Webhook;
    public string Name => _format == WebhookFormat.Teams ? "Microsoft Teams" : "Slack";

    public WebhookChannel(HttpClient http, string url, WebhookFormat? format = null)
    {
        _http = http;
        _url = url;
        _format = format ?? Detect(url);
    }

    /// <summary>
    /// Teams (Power Automate) usa domínios do Azure Logic Apps; Slack usa hooks.slack.com.
    /// Na dúvida, assume Slack (payload mais simples e amplamente aceito).
    /// </summary>
    public static WebhookFormat Detect(string url)
    {
        var u = url.ToLowerInvariant();
        if (u.Contains("logic.azure.com") || u.Contains("webhook.office.com") || u.Contains("powerautomate"))
            return WebhookFormat.Teams;
        return WebhookFormat.Slack;
    }

    public async Task<SendResult> SendAsync(AlertMessage message, CancellationToken ct = default)
    {
        try
        {
            var json = _format == WebhookFormat.Teams ? TeamsCard(message) : SlackPayload(message);
            var resp = await _http.PostAsync(_url,
                new StringContent(json, Encoding.UTF8, "application/json"), ct);

            return resp.IsSuccessStatusCode
                ? SendResult.Success(Name)
                : SendResult.Failure($"{Name} respondeu {(int)resp.StatusCode}. Confira se a URL do webhook continua válida.");
        }
        catch (TaskCanceledException)
        {
            return SendResult.Failure($"{Name} não respondeu a tempo.");
        }
        catch (HttpRequestException ex)
        {
            return SendResult.Failure($"Não foi possível falar com o {Name}: {ex.Message}");
        }
    }

    private static string SlackPayload(AlertMessage m)
        => JsonSerializer.Serialize(new { text = $"*{m.Title}*\n{m.RichBody}" });

    /// <summary>Adaptive Card mínimo — o que o Power Automate do Teams espera hoje.</summary>
    private static string TeamsCard(AlertMessage m) => JsonSerializer.Serialize(new
    {
        type = "message",
        attachments = new[]
        {
            new
            {
                contentType = "application/vnd.microsoft.card.adaptive",
                content = new
                {
                    type = "AdaptiveCard",
                    version = "1.4",
                    body = new object[]
                    {
                        new { type = "TextBlock", text = m.Title, weight = "Bolder", size = "Medium", wrap = true },
                        new { type = "TextBlock", text = m.RichBody, wrap = true }
                    }
                }
            }
        }
    });
}
