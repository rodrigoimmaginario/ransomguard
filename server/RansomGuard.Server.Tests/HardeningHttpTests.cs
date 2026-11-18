using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using RansomGuard.Core.Detection;
using RansomGuard.Server.Security;

namespace RansomGuard.Server.Tests;

/// <summary>F39/F40 — superfície do painel fechada: setup com token, antiforgery real, cabeçalhos, segredo obrigatório, limites.</summary>
public sealed class HardeningHttpTests : IClassFixture<IsolatedPanelFactory>
{
    private readonly IsolatedPanelFactory _factory;
    public HardeningHttpTests(IsolatedPanelFactory factory) => _factory = factory;

    private HttpClient Client() => _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    private static async Task<string> AntiforgeryTokenOf(HttpClient c, string page)
    {
        var html = await (await c.GetAsync(page)).Content.ReadAsStringAsync();
        var m = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        Assert.True(m.Success, "formulário sem token antiforgery");
        return m.Groups[1].Value;
    }

    [Fact]
    public async Task Setup_without_the_first_run_token_is_refused_and_with_it_creates_the_account()
    {
        var c = Client();
        var af = await AntiforgeryTokenOf(c, "/setup");

        var wrong = await c.PostAsync("/auth/setup", new FormUrlEncodedContent(new Dictionary<string, string>
            { ["__RequestVerificationToken"] = af, ["username"] = "admin", ["password"] = "senha-forte-123", ["token"] = "errado" }));
        Assert.Equal(HttpStatusCode.Redirect, wrong.StatusCode);
        Assert.Contains("erro=2", wrong.Headers.Location!.ToString());

        var right = await c.PostAsync("/auth/setup", new FormUrlEncodedContent(new Dictionary<string, string>
            { ["__RequestVerificationToken"] = af, ["username"] = "admin", ["password"] = "senha-forte-123", ["token"] = _factory.SetupToken }));
        Assert.Equal(HttpStatusCode.Redirect, right.StatusCode);
        Assert.Equal("/", right.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Login_post_without_antiforgery_token_is_rejected()
    {
        var c = Client();
        await c.GetAsync("/login");
        var resp = await c.PostAsync("/auth/login", new FormUrlEncodedContent(new Dictionary<string, string> { ["username"] = "admin", ["password"] = "x" }));
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);   // antiforgery (CSRF de login)
    }

    [Fact]
    public async Task Security_headers_are_present_on_every_response()
    {
        var resp = await Client().GetAsync("/login");
        Assert.Equal("nosniff", resp.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", resp.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("frame-ancestors 'none'", resp.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("no-referrer", resp.Headers.GetValues("Referrer-Policy").Single());
    }

    private static RansomGuard.Agent.AgentBatch Batch(int events) => new("FS-H", DateTime.UtcNow, null,
        Enumerable.Range(0, events).Select(i => new FileEvent(DateTime.UtcNow, "u", "10.0.0.1", "s", FileOp.Read, $"f{i}")).ToList(),
        Array.Empty<HostSignal>(), Array.Empty<Core.Incidents.AgentIncident>());

    [Fact]
    public async Task Ingest_requires_an_enrolled_agent_signature()
    {
        var c = Client();
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.PostAsJsonAsync("/api/ingest", Batch(0))).StatusCode);
        c.DefaultRequestHeaders.Add("X-RansomGuard-Token", "errado");
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.PostAsJsonAsync("/api/ingest", Batch(0))).StatusCode);
    }

    [Fact]
    public async Task Oversized_batches_are_rejected_before_touching_the_database()
    {
        var c = _factory.CreateAgentClient("FS-H");
        var resp = await c.PostAsJsonAsync("/api/ingest", Batch(IngestLimits.MaxEventsPerBatch + 1));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await c.PostAsJsonAsync("/api/ingest", Batch(10))).StatusCode);
    }

    [Fact]
    public void Install_secrets_are_created_once_with_a_usable_certificate()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rg-secrets-" + Guid.NewGuid().ToString("N"));
        try
        {
            var path = Path.Combine(dir, "install-secrets.json");
            var a = new InstallSecretsStore(path).GetOrCreate("FS01", DateTime.UtcNow);
            var b = new InstallSecretsStore(path).GetOrCreate("FS01", DateTime.UtcNow.AddDays(1));   // reload
            Assert.Equal(a.SetupToken, b.SetupToken);
            Assert.True(a.SetupToken.Length >= 20);
            Assert.Equal("", a.IngestSecret);   // B1: não existe mais segredo compartilhado de ingestão
            using var cert = new InstallSecretsStore(path).LoadCertificate(b);
            Assert.True(cert.HasPrivateKey);
            Assert.Equal(a.CertificateThumbprint, SelfSignedCertificate.Thumbprint(cert));
            Assert.Contains("FS01", cert.Subject);
            Assert.True(cert.NotAfter > DateTime.UtcNow.AddYears(4));
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(10, 0, null)]
    [InlineData(5001, 0, "eventos")]
    [InlineData(0, 201, "incidentes")]
    public void Ingest_limits_are_explicit(int events, int incidents, string? expectedFragment)
    {
        var msg = IngestLimits.Validate(events, incidents);
        if (expectedFragment is null) Assert.Null(msg); else Assert.Contains(expectedFragment, msg);
    }
}

/// <summary>G5 — a lista de arquivos afetados chega do agente, fica no painel e sai como texto para o restore.</summary>
public sealed class ForensicsHttpTests : IClassFixture<IsolatedPanelFactory>
{
    private readonly IsolatedPanelFactory _factory;
    public ForensicsHttpTests(IsolatedPanelFactory factory) => _factory = factory;

    [Fact]
    public async Task Affected_paths_are_persisted_and_exportable_after_login()
    {
        var c = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var det = new Detection("FS-F", "u", "10.0.0.9", @"\\FS-F\S", Confidence.High, new HashSet<DetectionReason> { DetectionReason.CanaryTouched }, 3, DateTime.UtcNow, DateTime.UtcNow,
            AffectedPaths: new[] { @"2024\a.xlsx", @"2024\b.xlsx", @"RH\c.docx" });
        var inc = Core.Incidents.AgentIncident.From(det, Core.Response.ResponseDecision.None("x"), Array.Empty<Core.Response.AuditEntry>(), Core.Response.ResponseMode.Monitor);
        var resp = await _factory.CreateAgentClient("FS-F").PostAsJsonAsync("/api/ingest", new RansomGuard.Agent.AgentBatch("FS-F", DateTime.UtcNow, null, Array.Empty<FileEvent>(), Array.Empty<HostSignal>(), new[] { inc }));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RansomGuard.Server.Data.RansomGuardDb>();
        var rec = System.Linq.Enumerable.First(db.Detections.Where(d => d.IncidentId == inc.Id).ToList());
        Assert.Contains("RH", rec.AffectedPathsJson);

        Assert.Equal(HttpStatusCode.Redirect, (await c.GetAsync($"/incidente/{rec.Id}/arquivos.txt")).StatusCode);   // exige login
    }
}

/// <summary>G8 — papéis, auditoria do operador e backup: leitor não altera; admin faz backup; tudo fica na trilha.</summary>
public sealed class OperationHttpTests : IClassFixture<IsolatedPanelFactory>
{
    private readonly IsolatedPanelFactory _factory;
    public OperationHttpTests(IsolatedPanelFactory factory) => _factory = factory;

    private HttpClient Client() => _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
    private static async Task<string> Af(HttpClient c, string page)
    {
        var html = await (await c.GetAsync(page)).Content.ReadAsStringAsync();
        return Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
    }
    private async Task<HttpClient> LoginAsync(string user, string pass)
    {
        var c = Client();
        var af = await Af(c, "/login");
        var r = await c.PostAsync("/auth/login", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = af, ["username"] = user, ["password"] = pass }));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        return c;
    }

    [Fact]
    public async Task Admin_can_create_a_viewer_who_can_read_but_not_backup_and_everything_is_audited()
    {
        // setup do admin (idempotente entre testes da mesma fábrica)
        var setup = Client();
        await setup.PostAsync("/auth/setup", new FormUrlEncodedContent(new Dictionary<string, string>
            { ["__RequestVerificationToken"] = await Af(setup, "/setup"), ["username"] = "admin", ["password"] = "senha-forte-123", ["token"] = _factory.SetupToken }));

        var admin = await LoginAsync("admin", "senha-forte-123");
        var backup = await admin.GetAsync("/backup/ransomguard-backup.zip");
        Assert.Equal(HttpStatusCode.OK, backup.StatusCode);
        Assert.Equal("application/zip", backup.Content.Headers.ContentType!.MediaType);
        using (var zip = new System.IO.Compression.ZipArchive(await backup.Content.ReadAsStreamAsync()))
            Assert.Contains(zip.Entries, e => e.Name == "ransomguard.db");

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RansomGuard.Server.Data.RansomGuardDb>();
            var svc = new RansomGuard.Server.Auth.OwnerAccountService(db);
            Assert.True(await svc.AddViewerAsync("soc", "senha-leitura-1", DateTime.UtcNow));
            Assert.False(await svc.AddViewerAsync("soc", "senha-leitura-1", DateTime.UtcNow));   // repetido
            Assert.False(await svc.RemoveAsync(1));                                                 // admin nunca sai
            var (outcome, _, role) = await svc.TryLoginWithRoleAsync("soc", "senha-leitura-1", "t", DateTime.UtcNow);
            Assert.Equal(RansomGuard.Server.Auth.LoginOutcome.Success, outcome);
            Assert.Equal("viewer", role);
        }

        var viewer = await LoginAsync("soc", "senha-leitura-1");
        Assert.Equal(HttpStatusCode.OK, (await viewer.GetAsync("/auditoria")).StatusCode);
        var denied = await viewer.GetAsync("/backup/ransomguard-backup.zip");
        Assert.True(denied.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Redirect, denied.StatusCode.ToString());
        var pages = await viewer.GetAsync("/contas");
        Assert.True(pages.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Redirect or HttpStatusCode.NotFound, pages.StatusCode.ToString());

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RansomGuard.Server.Data.RansomGuardDb>();
            var actions = db.OperatorAudit.Select(a => a.Action).ToList();
            Assert.Contains("login.ok", actions);
            Assert.Contains("backup", actions);
        }
    }
}

/// <summary>Passo 12 — o relatório de incidente assinado (promessa do site) sai do painel e verifica com a chave pública da instalação.</summary>
public sealed class SignedIncidentReportTests : IClassFixture<IsolatedPanelFactory>
{
    private readonly IsolatedPanelFactory _factory;
    public SignedIncidentReportTests(IsolatedPanelFactory factory) => _factory = factory;

    [Fact]
    public async Task Report_and_signature_verify_against_the_install_public_key()
    {
        var c = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        // ingere um incidente do agente
        var det = new Detection("FS-R", "u", "10.0.0.9", @"\\FS-R\S", Confidence.High, new HashSet<DetectionReason> { DetectionReason.CanaryTouched }, 3, DateTime.UtcNow, DateTime.UtcNow, AffectedPaths: new[] { "a.docx" });
        var decision = new Core.Response.ResponseLadder().Decide(det, new Core.Response.ResponsePolicy { Mode = Core.Response.ResponseMode.Block });
        var runner = new Core.Response.ResponseRunner(new Core.Response.RecordingExecutor()); await runner.RunAsync(decision, DateTime.UtcNow);
        var inc = Core.Incidents.AgentIncident.From(det, decision, runner.Audit, Core.Response.ResponseMode.Block);
        Assert.Equal(HttpStatusCode.OK, (await _factory.CreateAgentClient("FS-R").PostAsJsonAsync("/api/ingest", new RansomGuard.Agent.AgentBatch("FS-R", DateTime.UtcNow, null, Array.Empty<FileEvent>(), Array.Empty<HostSignal>(), new[] { inc }))).StatusCode);

        int id;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RansomGuard.Server.Data.RansomGuardDb>();
            id = db.Detections.Where(d => d.IncidentId == inc.Id).Select(d => d.Id).ToList().Single();
        }
        Assert.Equal(HttpStatusCode.Redirect, (await c.GetAsync($"/incidente/{id}/relatorio.json")).StatusCode);   // exige login

        // logado (setup idempotente + login)
        string Af(string html) => Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        await c.PostAsync("/auth/setup", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = Af(await (await c.GetAsync("/setup")).Content.ReadAsStringAsync()), ["username"] = "admin", ["password"] = "senha-forte-123", ["token"] = _factory.SetupToken }));
        await c.PostAsync("/auth/login", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = Af(await (await c.GetAsync("/login")).Content.ReadAsStringAsync()), ["username"] = "admin", ["password"] = "senha-forte-123" }));

        var json = await c.GetStringAsync($"/incidente/{id}/relatorio.json");
        var sig = await c.GetStringAsync($"/incidente/{id}/relatorio.minisig");
        var identity = await c.GetFromJsonAsync<System.Text.Json.JsonElement>("/api/identity");
        var pub = RansomGuard.Core.Signing.MinisignPublicKey.Parse(identity.GetProperty("publicKey").GetString()!);

        Assert.Equal(RansomGuard.Core.Signing.MinisignVerificationResult.Valid, Core.Audit.IncidentReport.Verify(json, sig, pub));
        Assert.Contains("\"actions\"", json);
        Assert.Contains("a.docx", json);
        Assert.NotEqual(RansomGuard.Core.Signing.MinisignVerificationResult.Valid, Core.Audit.IncidentReport.Verify(json.Replace("a.docx", "b.docx"), sig, pub));
    }
}
