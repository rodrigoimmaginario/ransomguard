using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using RansomGuard.Core.Notifications;
using RansomGuard.Core.Signing;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Auth;
using RansomGuard.Server.Components;
using RansomGuard.Server.Data;
using RansomGuard.Server.Ingestion;
using RansomGuard.Server.Notifications;
using RansomGuard.Server.Seed;
using RansomGuard.Server.Security;

// A4 — o painel roda como serviço do Windows (sobrevive a logoff e reinício; antes era um executável aberto por
// atalho). Como serviço o diretório corrente é System32: a raiz de conteúdo passa a ser a pasta do executável.
var asService = Microsoft.Extensions.Hosting.WindowsServices.WindowsServiceHelpers.IsWindowsService();
var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = asService ? AppContext.BaseDirectory : null
});
builder.Host.UseWindowsService(o => o.ServiceName = "RansomGuardPanel");
// Log de Eventos do Windows só como serviço: a fonte "RansomGuardPanel" é criada pelo instalador. Fora do serviço
// (testes, execução interativa) escrever numa fonte inexistente falhava de vez em quando com "Access is denied".
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();
if (asService && OperatingSystem.IsWindows())
    AddPanelEventLog(builder.Logging);

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
static void AddPanelEventLog(ILoggingBuilder logging) =>
    logging.AddEventLog(new Microsoft.Extensions.Logging.EventLog.EventLogSettings { SourceName = "RansomGuardPanel" });

// A4/D9 — dados fora da pasta do executável, em pasta que só SYSTEM, administradores e a conta do serviço alcançam.
var paths = PanelPaths.Resolve(builder.Configuration, builder.Environment.ContentRootPath, builder.Environment.IsDevelopment());
builder.Services.AddSingleton(paths);
string? dataDirWarning = null;
if (paths.Managed && OperatingSystem.IsWindows())
{
    try { RansomGuard.Core.Security.SecureDirectory.Ensure(paths.DataDirectory); }
    catch (Exception ex) { dataDirWarning = ex.Message; }
}

// Chaves do ASP.NET (cookie de login, antiforgery) na pasta de dados: a conta do serviço não tem um perfil de usuário
// em que confiar, e sem isto cada reinício do serviço deslogaria todo mundo.
if (paths.Managed)
{
    var dataProtection = Microsoft.AspNetCore.DataProtection.DataProtectionBuilderExtensions.PersistKeysToFileSystem(
        builder.Services.AddDataProtection(), new DirectoryInfo(Path.Combine(paths.DataDirectory, "keys")));
    if (OperatingSystem.IsWindows())
        Microsoft.AspNetCore.DataProtection.DataProtectionBuilderExtensions.ProtectKeysWithDpapi(dataProtection, protectToLocalMachine: true);
}

// F39/F40 — segredos da instalação (segredo de ingestão, token de setup, certificado TLS), criados no 1º boot.
var secretsStore = new RansomGuard.Server.Security.InstallSecretsStore(paths.InstallSecrets);
var secrets = secretsStore.GetOrCreate(Environment.MachineName, DateTime.UtcNow);
builder.Services.AddSingleton(secrets);
builder.Services.AddSingleton(secretsStore);

// F39 — HTTPS por padrão com o certificado autoassinado da instalação (porta 5001). O HTTP (5000) fica só na própria
// máquina (D10): serve o redirecionamento para quem abre o painel localmente, e um agente configurado por engano com
// http:// para outro servidor falha na conexão em vez de mandar o segredo de ingestão em claro pela rede.
// Panel:Https=false desliga (ex.: atrás de um proxy TLS). Em testes (TestServer) o Kestrel não é usado.
var httpsEnabled = !bool.TryParse(builder.Configuration["Panel:Https"], out var httpsFlag) || httpsFlag;
var httpsPort = int.TryParse(builder.Configuration["Panel:HttpsPort"], out var hp) ? hp : 5001;
var httpPort = int.TryParse(builder.Configuration["Panel:HttpPort"], out var p0) ? p0 : 5000;
if (httpsEnabled && string.IsNullOrEmpty(builder.Configuration["ASPNETCORE_URLS"]) && string.IsNullOrEmpty(builder.Configuration["urls"]))
{
    var cert = secretsStore.LoadCertificate(secrets);
    builder.WebHost.ConfigureKestrel(k =>
    {
        k.ListenLocalhost(httpPort);
        k.ListenAnyIP(httpsPort, l => l.UseHttps(cert));
        k.Limits.MaxRequestBodySize = RansomGuard.Server.Security.IngestLimits.MaxBodyBytes;
    });
}

// F40 — limite de taxa na ingestão: por token de agente (ou IP), janela fixa. Rajada legítima de 5 s nunca passa de poucos
// pedidos por minuto; centenas por minuto é agente quebrado ou abuso.
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("ingest", ctx => System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(
        ctx.Request.Headers[RansomGuard.Core.Auth.BatchSignature.AgentHeader].ToString() is { Length: > 0 and <= 64 } t ? "a:" + t.ToUpperInvariant() : "ip:" + (ctx.Connection.RemoteIpAddress?.ToString() ?? "?"),
        _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions { PermitLimit = 120, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});

builder.Services.AddHttpContextAccessor();
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Banco self-hosted (SQLite local).
// Caminho do banco: configurável (Database:Path) para testes de integração isolarem cada instância do painel.
builder.Services.AddDbContext<RansomGuardDb>(o => o.UseSqlite($"Data Source={paths.Database}"));

// Alertas: o sink de log é a saída de diagnóstico (sempre presente); os canais do admin (F13) são
// a saída real, montada a partir do que está salvo no painel.
builder.Services.AddSingleton<IAlertSink, LogAlertSink>();

// Notificações (F13): HttpClient nomeado com timeout curto — durante um ataque, um canal lento não
// pode segurar os outros. SMTP real via System.Net.Mail. O serviço de despacho é singleton para o
// estado de anti-flood sobreviver entre requisições.
builder.Services.AddHttpClient("notifications", c => c.Timeout = TimeSpan.FromSeconds(10));
builder.Services.AddSingleton<ISmtpTransport, SystemNetSmtpTransport>();
builder.Services.AddSingleton<INotificationSink, NotificationDispatchService>();
builder.Services.AddScoped<AlertEngine>(sp => new AlertEngine(
    sp.GetRequiredService<IAlertSink>(), sp.GetRequiredService<INotificationSink>()));
builder.Services.AddScoped<IngestionService>();
// F35: retenção (incidentes 90 d, postura 30 d por padrão) — diária, configurável em Retention:*.
builder.Services.AddHostedService<RansomGuard.Server.Data.RetentionService>();
// F38: chave Ed25519 da instalação (arquivo protegido na pasta de dados, criada no 1º boot). Assina a política, os
// comandos e os relatórios de incidente.
builder.Services.AddSingleton<RansomGuard.Server.Auth.IInstallKeyStore>(_ => new RansomGuard.Server.Auth.FileInstallKeyStore(paths.InstallKey));
builder.Services.AddScoped<RansomGuard.Server.Policy.AgentPolicyService>();
// B1: identidade por agente (enrolamento com token de uso limitado; lotes assinados pela chave de cada agente).
builder.Services.AddScoped<RansomGuard.Server.Agents.AgentEnrollmentService>();
builder.Services.AddSingleton<RansomGuard.Server.Agents.BatchReplayGuard>();
// R2: monitor que varre heartbeats e alerta sobre agente silencioso (possível EDR killer).
builder.Services.AddHostedService<HeartbeatMonitor>();

// F28 — relay do catálogo: o painel busca da origem pública, verifica e faz cache; o agente pega
// do painel. Trust anchor de catálogo EMBUTIDO (config em Dev; chave real vem da cerimônia do
// owner). Fail-closed: sem chave, o sync não roda e o relay serve 404 (agente segue na semente).
var catalogKeyB64 = builder.Configuration["Catalog:PublicKeyBase64"];
var catalogOriginUrl = builder.Configuration["Catalog:OriginUrl"]
    ?? RansomGuard.Server.Catalog.HttpCatalogOrigin.DefaultOriginUrl;
var catalogCacheRoot = paths.CatalogCache;
RansomGuard.Core.Signing.MinisignPublicKey? catalogKey = null;
if (!string.IsNullOrWhiteSpace(catalogKeyB64))
{
    try
    {
        var blob = Convert.FromBase64String(catalogKeyB64);
        catalogKey = RansomGuard.Core.Signing.MinisignPublicKey.FromRaw(blob.AsSpan(0, 8), blob.AsSpan(8, 32));
    }
    catch { catalogKey = null; }   // chave malformada = fail-closed
}
if (catalogKey is { } ck)
{
    builder.Services.AddHttpClient("catalog-origin", c => c.Timeout = TimeSpan.FromSeconds(15));
    builder.Services.AddSingleton(sp => new RansomGuard.Server.Catalog.CatalogSyncService(
        new RansomGuard.Server.Catalog.HttpCatalogOrigin(
            sp.GetRequiredService<IHttpClientFactory>().CreateClient("catalog-origin"), catalogOriginUrl),
        new RansomGuard.Server.Catalog.FileCatalogCache(catalogCacheRoot),
        ck));
    builder.Services.AddHostedService<RansomGuard.Server.Catalog.CatalogSyncMonitor>();
}

// Identidade da instalação (GUID publicado em /api/identity). O produto é gratuito: não há licença nem pagamento.
builder.Services.AddScoped<InstallIdentity>(sp => new InstallIdentity(sp.GetRequiredService<RansomGuardDb>()));

// Autenticação do painel (F14): cookie. O painel é self-hosted de um único adm — sem OAuth, sem
// multiusuário. Cookie HttpOnly; expira em 8h. O agente NÃO usa cookie (é máquina-para-máquina).
builder.Services.AddScoped<RansomGuard.Server.Auth.OwnerAccountService>();
builder.Services.AddAuthentication(Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.LoginPath = "/login";
        o.AccessDeniedPath = "/login";
        o.ExpireTimeSpan = TimeSpan.FromHours(8);
        o.Cookie.HttpOnly = true;
        o.Cookie.Name = "ransomguard.auth";
        o.SlidingExpiration = true;
        // F40: cookie só por HTTPS quando a requisição é HTTPS (SameAsRequest mantém o acesso HTTP em lab); SameSite estrito.
        o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        o.Cookie.SameSite = SameSiteMode.Strict;
    });
builder.Services.AddAuthorization(o => o.AddPolicy("admin", p => p.RequireRole(RansomGuard.Server.Auth.Roles.Admin)));
builder.Services.AddCascadingAuthenticationState();

var app = builder.Build();

// Cria/migra o banco e, em Development, semeia dados de demonstração para o painel ter conteúdo.
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<RansomGuardDb>();
    // C2: banco novo nasce pelas migrações; banco de antes delas (RC, desenvolvimento) passa pela ponte e segue por elas.
    await RansomGuard.Server.Data.SchemaUpgrade.ApplyAsync(db);
    if (app.Environment.IsDevelopment())
        await DemoSeed.EnsureAsync(scope.ServiceProvider);

    // O token de primeira execução fica em arquivo, na pasta de dados, só enquanto não existe conta de dono.
    var hasAccount = await scope.ServiceProvider.GetRequiredService<RansomGuard.Server.Auth.OwnerAccountService>().AccountExistsAsync();
    SetupTokenFile.Sync(paths.SetupToken, secrets.SetupToken, hasAccount);
    if (!hasAccount)
        app.Logger.LogWarning("Painel sem conta de administrador: o token de primeira execução está em {Path}.", paths.SetupToken);
}
app.Logger.LogInformation("Dados do painel em {Dir}.", paths.DataDirectory);
if (dataDirWarning is not null)
    app.Logger.LogWarning("Não foi possível restringir a pasta de dados {Dir}: {Erro}", paths.DataDirectory, dataDirWarning);

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseRansomGuardSecurityHeaders();   // F40
if (httpsEnabled && !app.Environment.IsDevelopment()) app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

// Primeira execução: sem conta de adm, força o setup antes de qualquer tela. Deixa passar o próprio
// /setup, os endpoints de auth, a API do agente e os estáticos.
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path.Value ?? "";
    var isento = path.StartsWith("/setup") || path.StartsWith("/auth/") || path.StartsWith("/api/")
                 || path.StartsWith("/_") || path.Contains('.');   // estáticos e framework
    if (!isento)
    {
        var accounts = ctx.RequestServices.GetRequiredService<RansomGuard.Server.Auth.OwnerAccountService>();
        if (!await accounts.AccountExistsAsync(ctx.RequestAborted))
        {
            ctx.Response.Redirect("/setup");
            return;
        }
    }
    await next();
});

// ── Autenticação (F14): setup na 1ª vez, login e logout via endpoints (form POST) ─────────────
// Setup: cria a conta do adm quando ainda não existe. Recusa se já houver conta (evita takeover).
// F40: exige o token de primeira execução (arquivo token-de-setup.txt na pasta de dados) — quem alcança a porta antes
// do admin não cria a conta de dono. O token não vai para o log: como serviço, o log de Aplicativo é legível por
// qualquer usuário do servidor.
// F40: estes endpoints leem o formulário à mão (sem binding), então a validação antiforgery tem de ser explícita —
// com DisableAntiforgery (antes) um site externo conseguia logar/deslogar/criar conta no painel por CSRF.
static async Task<bool> AntiforgeryOk(HttpContext ctx)
{
    try { await ctx.RequestServices.GetRequiredService<Microsoft.AspNetCore.Antiforgery.IAntiforgery>().ValidateRequestAsync(ctx); return true; }
    catch (Microsoft.AspNetCore.Antiforgery.AntiforgeryValidationException) { return false; }
}

app.MapPost("/auth/setup", async (HttpContext ctx, OwnerAccountService accounts, RansomGuard.Server.Security.InstallSecrets s, CancellationToken ct) =>
{
    if (!await AntiforgeryOk(ctx)) return Results.BadRequest("antiforgery");
    var form = await ctx.Request.ReadFormAsync(ct);
    var user = form["username"].ToString();
    var pass = form["password"].ToString();
    var token = form["token"].ToString();

    if (!RansomGuard.Core.Auth.SharedSecret.IsAuthorized(s.SetupToken, token))
        return Results.Redirect("/setup?erro=2");   // token errado

    var ok = await accounts.CreateAsync(user, pass, DateTime.UtcNow, ct);
    if (!ok) return Results.Redirect("/setup?erro=1");   // já existe, ou senha < 8

    var created = string.IsNullOrWhiteSpace(user) ? "admin" : user.Trim();
    await RansomGuard.Server.Auth.OperatorAudit.RecordAsync(ctx.RequestServices.GetRequiredService<RansomGuardDb>(), created, "account.setup", "conta de dono criada", ctx.Connection.RemoteIpAddress?.ToString() ?? "", ct);
    SetupTokenFile.Sync(paths.SetupToken, s.SetupToken, accountExists: true);   // a conta existe: o token não serve mais
    await SignInAsync(ctx, created, RansomGuard.Server.Auth.Roles.Admin);
    return Results.Redirect("/");
});

app.MapPost("/auth/login", async (HttpContext ctx, OwnerAccountService accounts, CancellationToken ct) =>
{
    if (!await AntiforgeryOk(ctx)) return Results.BadRequest("antiforgery");
    var form = await ctx.Request.ReadFormAsync(ct);
    var user = form["username"].ToString();
    var pass = form["password"].ToString();
    var origem = ctx.Connection.RemoteIpAddress?.ToString() ?? "?";

    var (outcome, name, role) = await accounts.TryLoginWithRoleAsync(user, pass, origem, DateTime.UtcNow, ct);
    var db = ctx.RequestServices.GetRequiredService<RansomGuardDb>();
    if (outcome != LoginOutcome.Success)
    {
        await RansomGuard.Server.Auth.OperatorAudit.RecordAsync(db, user, "login.fail", outcome.ToString(), origem, ct);
        return Results.Redirect($"/login?erro={(int)outcome}");
    }

    await RansomGuard.Server.Auth.OperatorAudit.RecordAsync(db, name, "login.ok", role, origem, ct);
    await SignInAsync(ctx, name!, role);
    return Results.Redirect("/");
});

app.MapPost("/auth/logout", async (HttpContext ctx) =>
{
    if (!await AntiforgeryOk(ctx)) return Results.BadRequest("antiforgery");
    await RansomGuard.Server.Auth.OperatorAudit.RecordAsync(ctx.RequestServices.GetRequiredService<RansomGuardDb>(), ctx.User.Identity?.Name, "logout", "", ctx.Connection.RemoteIpAddress?.ToString() ?? "");
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login");
});

static async Task SignInAsync(HttpContext ctx, string username, string role = "admin")
{
    var claims = new List<Claim> { new(ClaimTypes.Name, username), new(ClaimTypes.Role, string.IsNullOrWhiteSpace(role) ? "admin" : role) };
    var id = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(id));
}

// B1 — enrolamento: o agente apresenta a própria chave pública com um token gerado pelo administrador na tela Agentes.
// O token tem prazo e número de usos; o nome do servidor fica vinculado à chave (outra chave não toma o nome).
app.MapPost("/api/enroll", async (HttpContext ctx, EnrollRequest request, RansomGuard.Server.Agents.AgentEnrollmentService agents, RansomGuardDb db, CancellationToken ct) =>
{
    var origin = ctx.Connection.RemoteIpAddress?.ToString() ?? "";
    var outcome = await agents.EnrollAsync(request.Token, request.Server, request.PublicKey, origin, DateTime.UtcNow, ct);
    if (outcome is RansomGuard.Server.Agents.EnrollOutcome.Enrolled)
        await RansomGuard.Server.Auth.OperatorAudit.RecordAsync(db, "-", "agent.enroll", request.Server ?? "", origin, ct);
    return outcome switch
    {
        RansomGuard.Server.Agents.EnrollOutcome.Enrolled or RansomGuard.Server.Agents.EnrollOutcome.AlreadyEnrolled =>
            Results.Ok(new { server = request.Server, fingerprint = RansomGuard.Core.Auth.AgentKey.FingerprintOf(Convert.FromBase64String(request.PublicKey!)) }),
        RansomGuard.Server.Agents.EnrollOutcome.NameTaken =>
            Results.Json(new { error = "Já existe um agente enrolado com este nome e outra chave. Revogue-o na tela Agentes antes de enrolar de novo." }, statusCode: StatusCodes.Status409Conflict),
        RansomGuard.Server.Agents.EnrollOutcome.InvalidToken =>
            Results.Json(new { error = "Token de enrolamento inválido, expirado ou já usado." }, statusCode: StatusCodes.Status401Unauthorized),
        _ => Results.BadRequest(new { error = "Pedido de enrolamento malformado." })
    };
}).AllowAnonymous().RequireRateLimiting("ingest");

// Endpoint de ingestão do agente (o agente Windows POSTa o AgentBatch aqui). SEM cookie: é máquina-para-máquina.
// B1: cada lote é assinado pela chave do PRÓPRIO agente (cabeçalhos X-RansomGuard-Agent/-Timestamp/-Signature). Não
// existe mais segredo compartilhado: quem lê a configuração de um servidor não fala em nome dos outros, e um lote só
// é aceito para o servidor a que a chave está vinculada.
app.MapPost("/api/ingest", async (HttpContext ctx, IngestionService svc, RansomGuard.Server.Agents.AgentEnrollmentService agents,
    RansomGuard.Server.Agents.BatchReplayGuard replay, Microsoft.Extensions.Options.IOptions<Microsoft.AspNetCore.Http.Json.JsonOptions> json, CancellationToken ct) =>
{
    static IResult Refuse(int status, string error, string code = "") => Results.Json(new { error, code }, statusCode: status);

    var agent = ctx.Request.Headers[RansomGuard.Core.Auth.BatchSignature.AgentHeader].ToString();
    var record = RansomGuard.Core.Auth.AgentKey.IsValidServerName(agent) ? await agents.FindAsync(agent, ct) : null;
    if (record is null) return Refuse(StatusCodes.Status401Unauthorized, "Agente não enrolado neste painel.", "not-enrolled");

    if (ctx.Request.ContentLength > RansomGuard.Server.Security.IngestLimits.MaxBodyBytes)
        return Refuse(StatusCodes.Status413PayloadTooLarge, "lote grande demais");
    using var buffer = new MemoryStream();
    await ctx.Request.Body.CopyToAsync(buffer, ct);
    var body = buffer.ToArray();

    var now = DateTime.UtcNow;
    var signature = ctx.Request.Headers[RansomGuard.Core.Auth.BatchSignature.SignatureHeader].ToString();
    var verdict = RansomGuard.Core.Auth.BatchSignature.Verify(Convert.FromBase64String(record.PublicKey), agent,
        ctx.Request.Headers[RansomGuard.Core.Auth.BatchSignature.TimestampHeader].ToString(), signature, body, now);
    if (verdict == RansomGuard.Core.Auth.BatchSignatureResult.Expired)
        return Refuse(StatusCodes.Status401Unauthorized, "Relógio do agente fora da janela aceita pelo painel (5 minutos). Acerte a hora do servidor.", "clock");
    if (verdict != RansomGuard.Core.Auth.BatchSignatureResult.Valid)
        return Refuse(StatusCodes.Status401Unauthorized, "Assinatura do lote inválida.", "bad-signature");
    if (!replay.TryRegister(agent, signature, now))
        return Refuse(StatusCodes.Status409Conflict, "Lote já recebido.", "replay");

    AgentBatch? batch;
    try { batch = System.Text.Json.JsonSerializer.Deserialize<AgentBatch>(body, json.Value.SerializerOptions); }
    catch (System.Text.Json.JsonException) { batch = null; }
    if (batch is null) return Refuse(StatusCodes.Status400BadRequest, "lote ilegível");
    // A chave autentica UM servidor: um agente não manda batimento nem incidente em nome de outro.
    if (!string.Equals(batch.Server, record.Server, StringComparison.OrdinalIgnoreCase))
        return Refuse(StatusCodes.Status403Forbidden, "O lote é de outro servidor.");
    // F40: limites antes de tocar o banco.
    if (RansomGuard.Server.Security.IngestLimits.Validate(batch.Events.Count, batch.Incidents?.Count ?? 0) is { } tooBig)
        return Refuse(StatusCodes.Status413PayloadTooLarge, tooBig);

    await agents.TouchAddressAsync(record.Server, ctx.Connection.RemoteIpAddress?.ToString() ?? "", ct);
    var result = await svc.IngestAsync(batch, ct);
    return Results.Ok(result);
}).AllowAnonymous().RequireRateLimiting("ingest");

// F18 — relay do catálogo assinado. O painel serve ao agente os bytes exatos do último catálogo
// que ele obteve da origem pública (`catalog/` no repositório de distribuição) e guardou em
// `catalog-cache/`. O agente verifica a assinatura por conta própria (defesa em profundidade), então
// o relay não precisa de autenticação forte: mesma superfície máquina-para-máquina do /api/ingest.
// Enquanto o owner não publicar e o painel não sincronizar, responde 404 — o agente segue na semente.
var catalogCacheDir = paths.CatalogCache;
IResult ServeCatalog(string file)
{
    var path = Path.Combine(catalogCacheDir, file);
    return File.Exists(path)
        ? Results.Text(File.ReadAllText(path), "application/octet-stream")
        : Results.NotFound();
}
// F38 — identidade pública da instalação: o agente fixa esta chave (TOFU no primeiro contato ou valor explícito
// em Agent:PanelPublicKey) e passa a exigir asserções assinadas por ela. Público por desenho (só a chave pública).
app.MapGet("/api/identity", async (RansomGuard.Server.Auth.IInstallKeyStore keys, InstallIdentity identity, CancellationToken ct) =>
{
    var key = await keys.GetOrCreateAsync(ct);
    var id = await identity.GetOrCreateAsync(DateTime.UtcNow, ct);
    return Results.Ok(new { installId = id, keyId = key.PublicKey.KeyIdHex, publicKey = key.PublicKeyFileContent });
}).AllowAnonymous();

app.MapGet("/api/catalog/catalog.json", () => ServeCatalog("catalog.json")).AllowAnonymous();
app.MapGet("/api/catalog/catalog.json.minisig", () => ServeCatalog("catalog.json.minisig")).AllowAnonymous();

// F28c — importação manual para ambiente sem egress: o admin sobe o par assinado, verificado com as
// mesmas regras (assinatura + anti-rollback + policy) antes de entrar no cache. Protegido por login.
app.MapPost("/api/catalog/import", async (HttpContext ctx, CancellationToken ct) =>
{
    if (catalogKey is not { } importKey)
        return Results.BadRequest(new { error = "Sem chave pública de catálogo configurada." });
    var form = await ctx.Request.ReadFormAsync(ct);
    var json = form["catalog"].ToString();
    var sig = form["signature"].ToString();
    if (string.IsNullOrWhiteSpace(json) || string.IsNullOrWhiteSpace(sig))
        return Results.BadRequest(new { error = "Envie 'catalog' e 'signature'." });

    var cache = new RansomGuard.Server.Catalog.FileCatalogCache(catalogCacheDir);
    var origin = new RansomGuard.Server.Catalog.StaticCatalogOrigin(json, sig);
    var svc = new RansomGuard.Server.Catalog.CatalogSyncService(origin, cache, importKey);
    var ok = await svc.SyncAsync(ct);
    await RansomGuard.Server.Auth.OperatorAudit.RecordAsync(ctx.RequestServices.GetRequiredService<RansomGuardDb>(), ctx.User.Identity?.Name, "catalog.import", ok ? "aceito" : "recusado", ctx.Connection.RemoteIpAddress?.ToString() ?? "", ct);
    return ok
        ? Results.Ok(new { imported = true })
        : Results.BadRequest(new { error = "Catálogo recusado (assinatura, versão ou política)." });
}).RequireAuthorization("admin");

// G8 — backup do painel: banco (cópia consistente via VACUUM INTO), chave da instalação e segredos, num zip. Só admin.
// Chave e segredos saem em forma PORTÁTIL (em claro): o arquivo protegido só abre na máquina de origem, e backup que
// não restaura em outro servidor não é backup. O zip é, portanto, tão sensível quanto a chave — guarde como tal.
// Restaurar = parar o serviço, colocar os três arquivos na pasta de dados, subir; o painel protege de novo ao ler.
app.MapGet("/backup/ransomguard-backup.zip", async (HttpContext ctx, RansomGuardDb db, CancellationToken ct) =>
{
    var tmp = Path.Combine(Path.GetTempPath(), "rg-backup-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(tmp);
    try
    {
        var dbCopy = Path.Combine(tmp, "ransomguard.db");
        await db.Database.ExecuteSqlRawAsync($"VACUUM INTO '{dbCopy.Replace("'", "''")}'", ct);
        foreach (var (name, src) in new[] { ("install-key.json", paths.InstallKey), ("install-secrets.json", paths.InstallSecrets) })
            if (ProtectedFile.Read(src) is { } portable) await File.WriteAllTextAsync(Path.Combine(tmp, name), portable, ct);
        var zip = Path.Combine(Path.GetTempPath(), "rg-backup-" + Guid.NewGuid().ToString("N") + ".zip");
        System.IO.Compression.ZipFile.CreateFromDirectory(tmp, zip);
        var bytes = await File.ReadAllBytesAsync(zip, ct);
        File.Delete(zip);
        await RansomGuard.Server.Auth.OperatorAudit.RecordAsync(db, ctx.User.Identity?.Name, "backup", $"{bytes.Length} bytes", ctx.Connection.RemoteIpAddress?.ToString() ?? "", ct);
        return Results.File(bytes, "application/zip", $"ransomguard-backup-{DateTime.UtcNow:yyyyMMdd-HHmm}.zip");
    }
    finally { try { Directory.Delete(tmp, true); } catch (IOException) { } }
}).RequireAuthorization("admin");

// Passo 12 — relatório de incidente ASSINADO (promessa do site): JSON canônico + assinatura minisign com a chave da
// instalação. Verificável com a ferramenta minisign padrão e a chave pública de /api/identity. Protegido por login.
app.MapGet("/incidente/{id:int}/relatorio.{ext}", async (int id, string ext, RansomGuardDb db, RansomGuard.Server.Auth.IInstallKeyStore keys, CancellationToken ct) =>
{
    if (ext is not ("json" or "minisig")) return Results.NotFound();
    var d = await db.Detections.Include(x => x.Server).Include(x => x.Actions).FirstOrDefaultAsync(x => x.Id == id, ct);
    if (d is null) return Results.NotFound();
    var reasons = d.Reasons.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(r => Enum.TryParse<RansomGuard.Core.Detection.DetectionReason>(r, out var dr) ? dr : (RansomGuard.Core.Detection.DetectionReason?)null)
        .Where(r => r is not null).Select(r => r!.Value).ToHashSet();
    var model = new RansomGuard.Core.Detection.Detection(d.Server?.Name ?? "", d.User, d.SourceIp, d.Share, d.Confidence, reasons, d.AffectedFiles, d.At, d.At,
        AffectedPaths: d.AffectedPathsJson is null ? null : System.Text.Json.JsonSerializer.Deserialize<string[]>(d.AffectedPathsJson));
    var audit = d.Actions.OrderBy(x => x.Id).Select(x => new RansomGuard.Core.Response.AuditEntry(x.At, x.Actor, x.Operation,
        new RansomGuard.Core.Response.ResponseAction(Enum.TryParse<RansomGuard.Core.Response.ResponseStep>(x.Step, out var st) ? st : RansomGuard.Core.Response.ResponseStep.PreemptiveSnapshot,
            d.Server?.Name ?? "", x.Target, x.Justification, x.Account), x.Justification));
    var report = RansomGuard.Core.Audit.IncidentReport.From(model, audit);
    var key = await keys.GetOrCreateAsync(ct);
    var (json, sig) = report.Sign(key.Seed, key.KeyId);
    return ext == "json"
        ? Results.Text(json, "application/json; charset=utf-8")
        : Results.Text(sig, "text/plain; charset=utf-8");
}).RequireAuthorization();

// G5 — lista de arquivos afetados por incidente, texto puro, para o restore (protegido por login).
app.MapGet("/incidente/{id:int}/arquivos.txt", async (int id, RansomGuardDb db, CancellationToken ct) =>
{
    var d = await db.Detections.Include(x => x.Server).FirstOrDefaultAsync(x => x.Id == id, ct);
    if (d is null) return Results.NotFound();
    var paths = d.AffectedPathsJson is null ? Array.Empty<string>() : System.Text.Json.JsonSerializer.Deserialize<string[]>(d.AffectedPathsJson) ?? Array.Empty<string>();
    var header = $"# RansomGuard — incidente {d.IncidentId ?? d.Id.ToString()} em {d.Server?.Name} ({d.At:u})\n# {d.User} de {d.SourceIp} em {d.Share} — {paths.Length} caminho(s) ({d.AffectedFiles} eventos)\n";
    return Results.Text(header + string.Join("\n", paths) + "\n", "text/plain; charset=utf-8");
}).RequireAuthorization();

// Export SIEM (F17c): os incidentes persistidos em CEF, uma linha por incidente, para o SOC do
// cliente puxar via syslog/coletor. Protegido por login (é uma tela do painel). Metadado apenas.
app.MapGet("/siem/incidentes", async (RansomGuardDb db, CancellationToken ct) =>
{
    var incidentes = await db.Detections
        .Include(d => d.Server)
        .OrderByDescending(d => d.At)
        .Take(1000)   // teto: o SIEM pagina/coleta por tempo; aqui é o export recente
        .ToListAsync(ct);

    var sb = new System.Text.StringBuilder();
    foreach (var d in incidentes)
    {
        // Reconstrói o modelo do Core a partir do registro persistido para reusar o CefExporter.
        var reasons = d.Reasons.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(r => Enum.TryParse<RansomGuard.Core.Detection.DetectionReason>(r, out var v) ? v : (RansomGuard.Core.Detection.DetectionReason?)null)
            .Where(v => v is not null).Select(v => v!.Value).ToHashSet();

        var model = new RansomGuard.Core.Detection.Detection(
            d.Server?.Name ?? "?", d.User, d.SourceIp, d.Share, d.Confidence,
            reasons, d.AffectedFiles, d.At, d.At);

        sb.AppendLine(RansomGuard.Core.Siem.CefExporter.Incident(model));
    }
    return Results.Text(sb.ToString(), "text/plain");
}).RequireAuthorization();

// Relatório executivo do Score, em HTML imprimível (print-to-PDF pelo navegador).
app.MapGet("/relatorio", async (RansomGuardDb db, CancellationToken ct) =>
{
    var servers = await db.Servers.Include(s => s.PostureRecords).ToListAsync(ct);
    var engine = new RansomGuard.Core.Score.RiskScoreEngine();

    // Reconstrói o NetworkScore a partir da última postura de cada servidor.
    var postures = new List<RansomGuard.Core.Score.PostureSnapshot>();
    foreach (var s in servers)
    {
        var last = s.PostureRecords.OrderByDescending(p => p.At).FirstOrDefault();
        if (last is not null)
            postures.Add(PostureFromFindings(s.Name, last.FindingsJson));
    }
    var net = engine.ScoreNetwork(postures);
    var html = RansomGuard.Server.Reporting.HtmlReport.BuildExecutive(net, DateTime.UtcNow);
    return Results.Content(html, "text/html");
}).RequireAuthorization();   // R1: relório expõe servidores/notas/achados — exige login, como /siem/incidentes

// Recompõe uma postura mínima a partir dos achados persistidos, para o relatório refletir o
// último score sem re-coletar. (Simplificação da fatia 2; a fatia 2+ persiste a postura crua.)
static RansomGuard.Core.Score.PostureSnapshot PostureFromFindings(string server, string findingsJson)
{
    var ids = new HashSet<string>();
    foreach (var el in System.Text.Json.JsonDocument.Parse(findingsJson).RootElement.EnumerateArray())
        if (el.TryGetProperty("Id", out var id)) ids.Add(id.GetString() ?? "");

    bool ok(string ruleId) => !ids.Contains(ruleId);
    return new RansomGuard.Core.Score.PostureSnapshot
    {
        Server = server,
        SmbV1Enabled = ids.Contains("smb-v1"),
        SmbSigningRequired = ok("smb-signing"),
        NtlmUnrestricted = ids.Contains("ntlm"),
        SmbAuthRateLimiter = ok("smb-ratelimit"),
        Smb445ExposedBroadly = ids.Contains("smb-445"),
        SharesWritableByEveryone = ids.Contains("share-everyone"),
        BroadNtfsPermissions = ids.Contains("ntfs-broad"),
        VssEnabled = ok("vss"),
        BackupServiceRunning = ok("backup-running"),
        BackupsProtected = ok("backup-protected"),
        FsrmActive = ok("fsrm"),
        ShareAuditingEnabled = ok("share-audit"),
        CanariesPlanted = ok("canaries"),
        AgentInstalled = ok("agent"),
        OverprivilegedServiceAccounts = ids.Contains("svc-priv"),
        ExcessLocalAdmins = ids.Contains("local-admins"),
        OsEndOfLifeOrUnpatched = ids.Contains("os-eol"),
        RdpExposed = ids.Contains("rdp")
    };
}

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

/// <summary>Exposto para os testes de integração (WebApplicationFactory) inspecionarem endpoints.</summary>
public partial class Program { }

/// <summary>Sink de alerta que grava no log — placeholder até o SMTP real (config do owner).</summary>
sealed class LogAlertSink(ILogger<LogAlertSink> log) : IAlertSink
{
    public Task SendAsync(string subject, string body, CancellationToken ct = default)
    {
        log.LogWarning("ALERTA: {Subject}\n{Body}", subject, body);
        return Task.CompletedTask;
    }
}

/// <summary>B1 — pedido de enrolamento de um agente.</summary>
public sealed record EnrollRequest(string? Token, string? Server, string? PublicKey);
