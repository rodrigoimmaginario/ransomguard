using System.Net;
using System.Text.Json;
using RansomGuard.Core.Notifications;

namespace RansomGuard.Core.Tests;

/// <summary>
/// Handler falso: grava a requisição que o canal montou e devolve a resposta que o teste mandar.
/// É o que permite provar payload, cabeçalhos e tratamento de erro sem tocar na rede.
/// </summary>
internal sealed class FakeHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

    public HttpRequestMessage? LastRequest { get; private set; }
    public string? LastBody { get; private set; }
    public int Calls { get; private set; }

    public FakeHandler(HttpStatusCode status = HttpStatusCode.OK)
        : this(_ => new HttpResponseMessage(status)) { }

    public FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) => _responder = responder;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Calls++;
        LastRequest = request;
        LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
        return _responder(request);
    }

    public HttpClient Client() => new(this);

    /// <summary>Handler que nunca responde — simula servidor inacessível/timeout.</summary>
    public static HttpClient TimingOut() =>
        new(new BlockingHandler()) { Timeout = TimeSpan.FromMilliseconds(50) };

    /// <summary>Handler que estoura HttpRequestException — simula DNS/conexão recusada.</summary>
    public static HttpClient Unreachable(string message = "connection refused") =>
        new(new ThrowingHandler(message));

    private sealed class BlockingHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
        {
            await Task.Delay(Timeout.Infinite, ct);
            return new HttpResponseMessage();
        }
    }

    private sealed class ThrowingHandler : HttpMessageHandler
    {
        private readonly string _message;
        public ThrowingHandler(string message) => _message = message;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
            => throw new HttpRequestException(_message);
    }
}

internal static class Alerts
{
    public static AlertMessage Critical(string title = "🚨 RansomGuard · FS01") =>
        new(AlertSeverity.Critical, title, "corpo curto", "corpo rico com mais detalhe",
            new[] { "rotating_light", "lock" }) { DedupKey = "det:FS01" };

    public static AlertMessage Info() =>
        new(AlertSeverity.Info, "titulo", "curto", "rico", Array.Empty<string>());
}

public class NtfyChannelTests
{
    private static JsonElement Payload(FakeHandler h) => JsonDocument.Parse(h.LastBody!).RootElement;

    [Fact]
    public async Task Publica_via_json_no_root_do_servidor()
    {
        var h = new FakeHandler();
        var r = await new NtfyChannel(h.Client(), "https://ntfy.corp.local/", "ransomguard")
            .SendAsync(Alerts.Critical());

        Assert.True(r.Ok);
        Assert.Equal(HttpMethod.Post, h.LastRequest!.Method);
        // JSON no root (não /topico) — o tópico vai no corpo. Assim o UTF-8 do título viaja no corpo,
        // não num cabeçalho ASCII-only.
        Assert.Equal("https://ntfy.corp.local/", h.LastRequest.RequestUri!.ToString());
        Assert.Equal("application/json", h.LastRequest.Content!.Headers.ContentType!.MediaType);

        var p = Payload(h);
        Assert.Equal("ransomguard", p.GetProperty("topic").GetString());
        Assert.Equal("corpo curto", p.GetProperty("message").GetString());
    }

    /// <summary>
    /// **Regressão do bug pego na validação ao vivo.** O título tem emoji e "·"; enviá-lo num
    /// cabeçalho HTTP faz o .NET lançar "Request headers must contain only ASCII characters". No
    /// corpo JSON, o UTF-8 passa liso.
    /// </summary>
    [Fact]
    public async Task Titulo_com_emoji_e_acento_vai_no_corpo_e_nao_quebra()
    {
        var h = new FakeHandler();
        var r = await new NtfyChannel(h.Client(), "https://ntfy.corp.local", "rg").SendAsync(Alerts.Critical());

        Assert.True(r.Ok);
        Assert.Equal("🚨 RansomGuard · FS01", Payload(h).GetProperty("title").GetString());
    }

    [Fact]
    public async Task Envia_titulo_prioridade_e_tags_no_json()
    {
        var h = new FakeHandler();
        await new NtfyChannel(h.Client(), "https://ntfy.corp.local", "rg").SendAsync(Alerts.Critical());

        var p = Payload(h);
        Assert.Equal("🚨 RansomGuard · FS01", p.GetProperty("title").GetString());
        Assert.Equal(5, p.GetProperty("priority").GetInt32());
        Assert.Equal(new[] { "rotating_light", "lock" },
            p.GetProperty("tags").EnumerateArray().Select(t => t.GetString()).ToArray());
    }

    [Theory]
    [InlineData(AlertSeverity.Critical, 5)]
    [InlineData(AlertSeverity.Warning, 4)]
    [InlineData(AlertSeverity.Info, 3)]
    public async Task Severity_maps_to_ntfy_priority(AlertSeverity sev, int expected)
    {
        var h = new FakeHandler();
        var msg = new AlertMessage(sev, "t", "s", "r", Array.Empty<string>());
        await new NtfyChannel(h.Client(), "https://n", "rg").SendAsync(msg);

        Assert.Equal(expected, Payload(h).GetProperty("priority").GetInt32());
    }

    /// <summary>
    /// Todo usuário Windows é <c>DOMÍNIO\usuário</c>. A barra tem que sobreviver à serialização JSON
    /// como caractere literal — não pode virar escape (\v = tab vertical, \n, etc.). Regressão do
    /// susto na validação ao vivo, onde uma barra virou tab vertical (e era artefato do shell de
    /// teste, não do produto — mas vale travar).
    /// </summary>
    [Fact]
    public async Task Usuario_de_dominio_com_barra_sobrevive_ao_json()
    {
        var h = new FakeHandler();
        var msg = new AlertMessage(AlertSeverity.Critical, "t", @"CORP\vendas1 tocou o canário", "r",
            Array.Empty<string>());
        await new NtfyChannel(h.Client(), "https://n", "rg").SendAsync(msg);

        var recebido = Payload(h).GetProperty("message").GetString()!;
        Assert.Equal(@"CORP\vendas1 tocou o canário", recebido);
        Assert.DoesNotContain('\v', recebido);   // a barra não virou tab vertical
    }

    [Fact]
    public async Task Token_becomes_bearer_authorization()
    {
        var h = new FakeHandler();
        await new NtfyChannel(h.Client(), "https://n", "rg", "tk_segredo").SendAsync(Alerts.Critical());

        Assert.Equal("Bearer", h.LastRequest!.Headers.Authorization!.Scheme);
        Assert.Equal("tk_segredo", h.LastRequest.Headers.Authorization.Parameter);
    }

    [Fact]
    public async Task Without_token_there_is_no_authorization_header()
    {
        var h = new FakeHandler();
        await new NtfyChannel(h.Client(), "https://n", "rg").SendAsync(Alerts.Critical());
        Assert.Null(h.LastRequest!.Headers.Authorization);
    }

    [Fact]
    public async Task Topico_com_barra_inicial_e_normalizado_no_payload()
    {
        var h = new FakeHandler();
        await new NtfyChannel(h.Client(), "https://n///", "/rg").SendAsync(Alerts.Critical());
        Assert.Equal("rg", Payload(h).GetProperty("topic").GetString());
    }

    [Fact]
    public async Task Http_error_is_reported_with_the_status_code()
    {
        var r = await new NtfyChannel(new FakeHandler(HttpStatusCode.Forbidden).Client(), "https://n", "rg")
            .SendAsync(Alerts.Critical());

        Assert.False(r.Ok);
        Assert.Contains("403", r.Detail);
    }

    [Fact]
    public async Task Timeout_produces_an_actionable_message_not_an_exception()
    {
        var r = await new NtfyChannel(FakeHandler.TimingOut(), "https://n", "rg").SendAsync(Alerts.Critical());

        Assert.False(r.Ok);
        Assert.Contains("tempo", r.Detail);
    }

    [Fact]
    public async Task Unreachable_server_does_not_throw()
    {
        var r = await new NtfyChannel(FakeHandler.Unreachable(), "https://n", "rg").SendAsync(Alerts.Critical());
        Assert.False(r.Ok);
    }
}

public class WebhookChannelTests
{
    [Theory]
    [InlineData("https://prod-12.westus.logic.azure.com/workflows/abc/triggers/manual", WebhookFormat.Teams)]
    [InlineData("https://corp.webhook.office.com/webhookb2/xyz", WebhookFormat.Teams)]
    [InlineData("https://hooks.slack.com/services/T00/B00/xxx", WebhookFormat.Slack)]
    [InlineData("https://chat.interno.corp/hook/1", WebhookFormat.Slack)]
    public void Format_is_detected_from_the_url(string url, WebhookFormat expected)
        => Assert.Equal(expected, WebhookChannel.Detect(url));

    [Fact]
    public async Task Slack_payload_is_a_json_text_field()
    {
        var h = new FakeHandler();
        var r = await new WebhookChannel(h.Client(), "https://hooks.slack.com/x").SendAsync(Alerts.Critical());

        Assert.True(r.Ok);
        var text = JsonDocument.Parse(h.LastBody!).RootElement.GetProperty("text").GetString()!;
        Assert.Contains("RansomGuard", text);
        Assert.Contains("corpo rico", text);   // no chat cabe o corpo completo
    }

    [Fact]
    public async Task Teams_payload_is_an_adaptive_card_with_title_and_body()
    {
        var h = new FakeHandler();
        await new WebhookChannel(h.Client(), "https://x.logic.azure.com/y").SendAsync(Alerts.Critical());

        var root = JsonDocument.Parse(h.LastBody!).RootElement;
        var content = root.GetProperty("attachments")[0].GetProperty("content");
        Assert.Equal("AdaptiveCard", content.GetProperty("type").GetString());

        var body = content.GetProperty("body");
        Assert.Equal("🚨 RansomGuard · FS01", body[0].GetProperty("text").GetString());
        Assert.Equal("corpo rico com mais detalhe", body[1].GetProperty("text").GetString());
        // Sem wrap, o Teams corta a mensagem — o admin perderia justamente o detalhe do incidente.
        Assert.True(body[1].GetProperty("wrap").GetBoolean());
    }

    [Fact]
    public async Task Content_type_is_json()
    {
        var h = new FakeHandler();
        await new WebhookChannel(h.Client(), "https://hooks.slack.com/x").SendAsync(Alerts.Critical());
        Assert.Equal("application/json", h.LastRequest!.Content!.Headers.ContentType!.MediaType);
    }

    [Fact]
    public void Explicit_format_overrides_url_detection()
    {
        var c = new WebhookChannel(new FakeHandler().Client(), "https://hooks.slack.com/x", WebhookFormat.Teams);
        Assert.Equal("Microsoft Teams", c.Name);
    }

    [Fact]
    public async Task Expired_webhook_url_is_reported_clearly()
    {
        var r = await new WebhookChannel(new FakeHandler(HttpStatusCode.NotFound).Client(), "https://hooks.slack.com/x")
            .SendAsync(Alerts.Critical());

        Assert.False(r.Ok);
        Assert.Contains("404", r.Detail);
        Assert.Contains("URL do webhook", r.Detail);
    }

    [Fact]
    public async Task Timeout_is_handled()
    {
        var r = await new WebhookChannel(FakeHandler.TimingOut(), "https://hooks.slack.com/x")
            .SendAsync(Alerts.Critical());
        Assert.False(r.Ok);
        Assert.Contains("tempo", r.Detail);
    }
}

public class TelegramChannelTests
{
    [Fact]
    public async Task Posts_send_message_with_token_in_the_path()
    {
        var h = new FakeHandler();
        var r = await new TelegramChannel(h.Client(), "123:ABC", "-100999", "https://tg.test")
            .SendAsync(Alerts.Critical());

        Assert.True(r.Ok);
        Assert.Equal("https://tg.test/bot123:ABC/sendMessage", h.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task Payload_carries_chat_id_and_full_text()
    {
        var h = new FakeHandler();
        await new TelegramChannel(h.Client(), "t", "-100999", "https://tg.test").SendAsync(Alerts.Critical());

        var root = JsonDocument.Parse(h.LastBody!).RootElement;
        Assert.Equal("-100999", root.GetProperty("chat_id").GetString());
        var text = root.GetProperty("text").GetString()!;
        Assert.Contains("RansomGuard", text);
        Assert.Contains("corpo rico", text);
    }

    [Fact]
    public async Task Bad_token_explains_where_to_get_a_valid_one()
    {
        var r = await new TelegramChannel(new FakeHandler(HttpStatusCode.Unauthorized).Client(), "t", "c", "https://tg.test")
            .SendAsync(Alerts.Critical());

        Assert.False(r.Ok);
        Assert.Contains("BotFather", r.Detail);
    }

    [Fact]
    public async Task Bad_chat_id_explains_the_first_message_requirement()
    {
        var r = await new TelegramChannel(new FakeHandler(HttpStatusCode.BadRequest).Client(), "t", "c", "https://tg.test")
            .SendAsync(Alerts.Critical());

        Assert.False(r.Ok);
        Assert.Contains("Chat ID", r.Detail);
    }

    /// <summary>Rede corporativa que bloqueia o Telegram é o caso mais comum de falha aqui.</summary>
    [Fact]
    public async Task Blocked_network_mentions_corporate_blocking()
    {
        var r = await new TelegramChannel(FakeHandler.Unreachable(), "t", "c", "https://tg.test")
            .SendAsync(Alerts.Critical());

        Assert.False(r.Ok);
        Assert.Contains("bloqueiam o Telegram", r.Detail);
    }

    [Fact]
    public async Task Timeout_is_handled()
    {
        var r = await new TelegramChannel(FakeHandler.TimingOut(), "t", "c", "https://tg.test")
            .SendAsync(Alerts.Critical());
        Assert.False(r.Ok);
        Assert.Contains("tempo", r.Detail);
    }
}

public class EmailChannelTests
{
    private sealed class FakeSmtp : ISmtpTransport
    {
        private readonly Exception? _throw;
        public SmtpSettings? Settings { get; private set; }
        public string? Subject { get; private set; }
        public string? Body { get; private set; }
        public int Calls { get; private set; }

        public FakeSmtp(Exception? ex = null) => _throw = ex;

        public Task SendAsync(SmtpSettings s, string subject, string body, CancellationToken ct)
        {
            Calls++;
            if (_throw is not null) throw _throw;
            (Settings, Subject, Body) = (s, subject, body);
            return Task.CompletedTask;
        }
    }

    private static SmtpSettings Settings(params string[] to) =>
        new("smtp.corp.local", 587, "ransomguard@corp.local", to.Length > 0 ? to : new[] { "adm@corp.local" });

    [Fact]
    public async Task Sends_title_as_subject_and_rich_body_as_content()
    {
        var smtp = new FakeSmtp();
        var r = await new EmailChannel(smtp, Settings()).SendAsync(Alerts.Critical());

        Assert.True(r.Ok);
        Assert.Equal("🚨 RansomGuard · FS01", smtp.Subject);
        Assert.Equal("corpo rico com mais detalhe", smtp.Body);
    }

    [Fact]
    public async Task Delivers_to_every_configured_recipient()
    {
        var smtp = new FakeSmtp();
        await new EmailChannel(smtp, Settings("a@corp.local", "b@corp.local")).SendAsync(Alerts.Critical());

        Assert.Equal(new[] { "a@corp.local", "b@corp.local" }, smtp.Settings!.To);
    }

    [Fact]
    public async Task Empty_recipient_list_fails_before_touching_the_server()
    {
        var smtp = new FakeSmtp();
        var r = await new EmailChannel(smtp, new SmtpSettings("h", 25, "f", Array.Empty<string>()))
            .SendAsync(Alerts.Critical());

        Assert.False(r.Ok);
        Assert.Contains("destinatário", r.Detail);
        Assert.Equal(0, smtp.Calls);
    }

    [Fact]
    public async Task Smtp_failure_becomes_a_readable_result_not_an_exception()
    {
        var smtp = new FakeSmtp(new InvalidOperationException("5.7.0 Authentication required"));
        var r = await new EmailChannel(smtp, Settings()).SendAsync(Alerts.Critical());

        Assert.False(r.Ok);
        Assert.Contains("Authentication required", r.Detail);
    }

    [Fact]
    public async Task Timeout_is_handled()
    {
        var smtp = new FakeSmtp(new OperationCanceledException());
        var r = await new EmailChannel(smtp, Settings()).SendAsync(Alerts.Critical());

        Assert.False(r.Ok);
        Assert.Contains("tempo", r.Detail);
    }
}
