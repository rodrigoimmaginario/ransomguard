using System.Net;
using System.Text;
using System.Text.Json;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Notifications;
using DetectionModel = RansomGuard.Core.Detection.Detection;

// NotificationSimulator — portão de regressão da VOZ do produto (F13). Exercita o laço:
// incidente → AlertComposer → NotificationDispatcher → canais reais (com HTTP falso), provando que
// o alerta certo sai nos canais certos, que canal quebrado não cala os outros, e que a política de
// ruído (anti-flood, severidade) protege o admin da fadiga.
//
// exit 0 = verde.

Console.OutputEncoding = Encoding.UTF8;

var falhas = new List<string>();
void Check(string nome, bool ok, string detalhe)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {nome} — {detalhe}");
    if (!ok) falhas.Add(nome);
}

var t0 = new DateTime(2026, 7, 26, 14, 0, 0, DateTimeKind.Utc);

DetectionModel Incidente(Confidence c = Confidence.High) =>
    new("FS01", @"CORP\vendas1", "10.0.9.66", @"\\FS01\Financeiro", c,
        new HashSet<DetectionReason> { DetectionReason.CanaryTouched }, 120, t0, t0.AddSeconds(30));

Console.WriteLine("RansomGuard · NotificationSimulator");
Console.WriteLine(new string('─', 66));

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 1 · Incidente vira alerta acionável nos canais");
{
    var ntfy = new CapturingChannel(ChannelKind.Ntfy);
    var teams = new CapturingChannel(ChannelKind.Webhook);
    var d = new NotificationDispatcher(new INotificationChannel[] { ntfy, teams });

    var msg = AlertComposer.ForDetection(Incidente(), containment: "sessão + IP");
    var report = await d.DispatchAsync(msg, t0);

    Check("todos-os-canais-recebem", ntfy.Received.Count == 1 && teams.Received.Count == 1,
        $"ntfy {ntfy.Received.Count}, teams {teams.Received.Count}");
    Check("alerta-e-critico", msg.Severity == AlertSeverity.Critical, $"severidade {msg.Severity}");
    Check("responde-as-cinco-perguntas",
        msg.ShortBody.Contains(@"CORP\vendas1") && msg.ShortBody.Contains("10.0.9.66") &&
        msg.ShortBody.Contains("Financeiro") && msg.ShortBody.Contains("120 arquivos"),
        "quem, de onde, onde, quanto");
    Check("usuario-de-dominio-intacto", ntfy.Received[0].ShortBody.Contains(@"CORP\vendas1"),
        "a barra de DOMÍNIO\\usuário sobrevive");
    Check("houve-entrega", report.Sent, "report.Sent");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 2 · Canal quebrado NÃO cala os outros");
{
    var quebrado = new FailingChannel(ChannelKind.Webhook, "503 Service Unavailable");
    var ok = new CapturingChannel(ChannelKind.Ntfy);
    var d = new NotificationDispatcher(new INotificationChannel[] { quebrado, ok });

    var report = await d.DispatchAsync(AlertComposer.ForDetection(Incidente()), t0);

    Check("push-saiu-apesar-do-teams-fora", ok.Received.Count == 1, "o canal bom entregou");
    Check("houve-entrega-parcial", report.Sent, "report.Sent com um canal fora");
    Check("falha-vira-relatorio", report.Failures.Any(f => f.Contains("503")),
        string.Join(" | ", report.Failures));
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 3 · Canal que LANÇA exceção é isolado");
{
    var explode = new ThrowingChannel(ChannelKind.Telegram);
    var ok = new CapturingChannel(ChannelKind.Ntfy);
    var d = new NotificationDispatcher(new INotificationChannel[] { explode, ok });

    var report = await d.DispatchAsync(AlertComposer.ForDetection(Incidente()), t0);

    Check("excecao-nao-derruba-o-despacho", ok.Received.Count == 1, "o outro canal seguiu");
    Check("excecao-vira-relatorio", report.Failures.Any(), string.Join(" | ", report.Failures));
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 4 · Anti-flood — um ataque é um alerta, não cem");
{
    var ntfy = new CapturingChannel(ChannelKind.Ntfy);
    var d = new NotificationDispatcher(new INotificationChannel[] { ntfy },
        new NotificationPolicy { FloodWindow = TimeSpan.FromMinutes(10) });

    // O mesmo incidente gera muitos eventos em segundos.
    await d.DispatchAsync(AlertComposer.ForDetection(Incidente()), t0);
    var segundo = await d.DispatchAsync(AlertComposer.ForDetection(Incidente()), t0.AddMinutes(2));

    Check("repeticao-suprimida", ntfy.Received.Count == 1 &&
        segundo.Decision == NotificationPolicy.Decision.Flooded,
        $"{ntfy.Received.Count} push para o mesmo ator em 2 min");

    // Depois da janela, volta a alertar (o ataque pode ter recomeçado).
    var depois = await d.DispatchAsync(AlertComposer.ForDetection(Incidente()), t0.AddMinutes(11));
    Check("apos-a-janela-alerta-de-novo", ntfy.Received.Count == 2 &&
        depois.Decision == NotificationPolicy.Decision.Send, "passada a janela, avisa de novo");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 5 · Severidade mínima protege da fadiga");
{
    var ntfy = new CapturingChannel(ChannelKind.Ntfy);
    var d = new NotificationDispatcher(new INotificationChannel[] { ntfy },
        new NotificationPolicy { MinimumSeverity = AlertSeverity.Critical });

    var aviso = AlertComposer.ForDetection(Incidente(Confidence.Medium));   // vira Warning
    var report = await d.DispatchAsync(aviso, t0);

    Check("abaixo-do-minimo-nao-sai", ntfy.Received.Count == 0 &&
        report.Decision == NotificationPolicy.Decision.BelowSeverity,
        $"Warning com mínimo Critical → {report.Decision}");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 6 · Botão 'Enviar teste' ignora a política e responde na hora");
{
    var ntfy = new CapturingChannel(ChannelKind.Ntfy);
    var r = await NotificationDispatcher.TestAsync(ntfy);

    Check("teste-entrega", r.Ok && ntfy.Received.Count == 1, r.Detail);
    Check("teste-e-info", ntfy.Received[0].Severity == AlertSeverity.Info, "mensagem de teste é Info");
    Check("teste-nomeia-o-canal",
        ntfy.Received[0].ShortBody.Contains(ntfy.Name, StringComparison.OrdinalIgnoreCase),
        "diz qual canal testou");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 7 · ntfy real (HTTP falso) — título com emoji/acento no corpo JSON");
{
    // O bug pego na validação ao vivo: título com emoji num cabeçalho HTTP quebra o .NET.
    var captura = new JsonCapturingHandler();
    var canal = new NtfyChannel(new HttpClient(captura), "https://ntfy.corp.local", "ransomguard");

    var r = await canal.SendAsync(AlertComposer.ForDetection(Incidente()));

    Check("ntfy-entrega", r.Ok, r.Detail);
    Check("publica-json-no-root", captura.LastUrl == "https://ntfy.corp.local/",
        $"POST para {captura.LastUrl}");
    var payload = JsonDocument.Parse(captura.LastBody!).RootElement;
    Check("titulo-utf8-no-corpo",
        payload.GetProperty("title").GetString()!.Contains("🚨") &&
        payload.GetProperty("topic").GetString() == "ransomguard",
        "emoji e acento passam no corpo, não no cabeçalho");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\n" + new string('─', 66));
if (falhas.Count == 0)
{
    Console.WriteLine("VERDE — a voz do produto está provada: alerta certo, canal isolado, anti-flood.");
    return 0;
}
Console.WriteLine($"VERMELHO — {falhas.Count} falha(s):");
foreach (var f in falhas) Console.WriteLine($"  ✗ {f}");
return 1;

// ── Dublês ──────────────────────────────────────────────────────────────────────────────────

sealed class CapturingChannel(ChannelKind kind) : INotificationChannel
{
    public ChannelKind Kind { get; } = kind;
    public string Name => Kind.ToString();
    public List<AlertMessage> Received { get; } = new();
    public Task<SendResult> SendAsync(AlertMessage m, CancellationToken ct = default)
    {
        Received.Add(m);
        return Task.FromResult(SendResult.Success(Name));
    }
}

sealed class FailingChannel(ChannelKind kind, string motivo) : INotificationChannel
{
    public ChannelKind Kind { get; } = kind;
    public string Name => Kind.ToString();
    public Task<SendResult> SendAsync(AlertMessage m, CancellationToken ct = default)
        => Task.FromResult(SendResult.Failure(motivo));
}

sealed class ThrowingChannel(ChannelKind kind) : INotificationChannel
{
    public ChannelKind Kind { get; } = kind;
    public string Name => Kind.ToString();
    public Task<SendResult> SendAsync(AlertMessage m, CancellationToken ct = default)
        => throw new HttpRequestException("host desconhecido");
}

/// <summary>Handler falso que captura o POST do NtfyChannel — prova o payload sem rede.</summary>
sealed class JsonCapturingHandler : HttpMessageHandler
{
    public string? LastUrl { get; private set; }
    public string? LastBody { get; private set; }
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        LastUrl = request.RequestUri!.ToString();
        LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
        return new HttpResponseMessage(HttpStatusCode.OK);
    }
}
