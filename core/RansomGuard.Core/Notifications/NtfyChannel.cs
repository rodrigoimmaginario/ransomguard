using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace RansomGuard.Core.Notifications;

/// <summary>
/// Canal ntfy — push no celular via POST simples. É o **recomendado** do produto porque pode ser
/// self-hosted: apontando para um ntfy dentro da rede, o alerta nunca sai para a internet, o que
/// mantém o princípio "nada sai da sua rede".
///
/// Protocolo: POST no tópico, com título/prioridade/tags em cabeçalhos. Token opcional (Bearer) —
/// no ntfy.sh público o tópico funciona como senha, por isso a UI recomenda o self-hosted.
/// </summary>
public sealed class NtfyChannel : INotificationChannel
{
    private readonly HttpClient _http;
    private readonly string _serverUrl;
    private readonly string _topic;
    private readonly string? _token;

    public ChannelKind Kind => ChannelKind.Ntfy;
    public string Name => "ntfy";

    public NtfyChannel(HttpClient http, string serverUrl, string topic, string? token = null)
    {
        _http = http;
        _serverUrl = serverUrl.TrimEnd('/');
        _topic = topic.Trim().TrimStart('/');
        _token = token;
    }

    public async Task<SendResult> SendAsync(AlertMessage message, CancellationToken ct = default)
    {
        try
        {
            // Publicação via JSON no root do servidor — NÃO por cabeçalhos. O título do produto tem
            // emoji e acento ("🚨 RansomGuard · FS01"), e o .NET recusa cabeçalho HTTP não-ASCII
            // ("Request headers must contain only ASCII characters"). A API JSON do ntfy trata UTF-8
            // nativamente. Bug pego na validação ao vivo — nenhum teste de header o pegaria.
            var payload = JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["topic"] = _topic,
                ["title"] = message.Title,
                ["message"] = message.ShortBody,
                ["priority"] = int.Parse(Priority(message.Severity)),
                ["tags"] = message.Tags
            });

            var req = new HttpRequestMessage(HttpMethod.Post, _serverUrl)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json")
            };
            if (!string.IsNullOrWhiteSpace(_token))
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);

            var resp = await _http.SendAsync(req, ct);
            return resp.IsSuccessStatusCode
                ? SendResult.Success(Name)
                : SendResult.Failure($"ntfy respondeu {(int)resp.StatusCode}. Confira o servidor e o tópico.");
        }
        catch (TaskCanceledException)
        {
            return SendResult.Failure("ntfy não respondeu a tempo. O servidor está acessível a partir do painel?");
        }
        catch (HttpRequestException ex)
        {
            return SendResult.Failure($"Não foi possível falar com o ntfy: {ex.Message}");
        }
    }

    /// <summary>Prioridade do ntfy (1–5). Critical vira 5 (toca mesmo no modo silencioso).</summary>
    private static string Priority(AlertSeverity s) => s switch
    {
        AlertSeverity.Critical => "5",
        AlertSeverity.Warning => "4",
        _ => "3"
    };
}
