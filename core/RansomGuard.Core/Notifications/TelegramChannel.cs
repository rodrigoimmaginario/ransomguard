using System.Text;
using System.Text.Json;

namespace RansomGuard.Core.Notifications;

/// <summary>
/// Canal Telegram via Bot API — o caminho mais rápido para quem já tem o app no celular (foi a
/// integração original do autor, à época do artigo sobre FSRM).
///
/// Segue gratuito e sem limite comercial. Ressalva registrada na UI: parte das redes corporativas
/// bloqueia o Telegram, e por isso ele não é o canal recomendado por padrão neste produto.
/// </summary>
public sealed class TelegramChannel : INotificationChannel
{
    private readonly HttpClient _http;
    private readonly string _botToken;
    private readonly string _chatId;
    private readonly string _apiBase;

    public ChannelKind Kind => ChannelKind.Telegram;
    public string Name => "Telegram";

    /// <param name="apiBase">Base da API (injetável para teste; produção usa api.telegram.org).</param>
    public TelegramChannel(HttpClient http, string botToken, string chatId,
        string apiBase = "https://api.telegram.org")
    {
        _http = http;
        _botToken = botToken;
        _chatId = chatId;
        _apiBase = apiBase.TrimEnd('/');
    }

    public async Task<SendResult> SendAsync(AlertMessage message, CancellationToken ct = default)
    {
        try
        {
            var payload = JsonSerializer.Serialize(new
            {
                chat_id = _chatId,
                text = $"{message.Title}\n\n{message.RichBody}",
                disable_web_page_preview = true
            });

            var resp = await _http.PostAsync($"{_apiBase}/bot{_botToken}/sendMessage",
                new StringContent(payload, Encoding.UTF8, "application/json"), ct);

            if (resp.IsSuccessStatusCode) return SendResult.Success(Name);

            // O Telegram devolve motivos úteis; os dois erros mais comuns na configuração inicial.
            var detail = (int)resp.StatusCode switch
            {
                401 => "Token do bot inválido. Confira o token que o @BotFather entregou.",
                400 => "Chat ID inválido, ou você ainda não enviou a primeira mensagem para o bot.",
                _ => $"Telegram respondeu {(int)resp.StatusCode}."
            };
            return SendResult.Failure(detail);
        }
        catch (TaskCanceledException)
        {
            return SendResult.Failure("Telegram não respondeu a tempo. A rede permite acesso a api.telegram.org?");
        }
        catch (HttpRequestException ex)
        {
            return SendResult.Failure($"Não foi possível falar com o Telegram: {ex.Message}. " +
                                      "Muitas redes corporativas bloqueiam o Telegram.");
        }
    }
}
