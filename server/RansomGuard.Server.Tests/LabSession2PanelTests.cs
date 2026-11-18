using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Incidents;
using RansomGuard.Core.Response;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Auth;
using RansomGuard.Server.Data;
using RansomGuard.Server.Ingestion;
using RansomGuard.Server.Policy;

namespace RansomGuard.Server.Tests;

/// <summary>Correções do que a sessão 2 do laboratório mostrou, no painel — pelo mesmo caminho que o administrador usa.</summary>
public sealed class LabSession2PanelTests : IClassFixture<IsolatedPanelFactory>
{
    private readonly IsolatedPanelFactory _factory;
    public LabSession2PanelTests(IsolatedPanelFactory factory) => _factory = factory;

    private static string Antiforgery(string html) => Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;

    private async Task<HttpClient> AdminAsync()
    {
        var c = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var setup = await (await c.GetAsync("/setup")).Content.ReadAsStringAsync();
        await c.PostAsync("/auth/setup", new FormUrlEncodedContent(new Dictionary<string, string>
            { ["__RequestVerificationToken"] = Antiforgery(setup), ["username"] = "admin", ["password"] = "senha-forte-123", ["token"] = _factory.SetupToken }));
        var login = await (await c.GetAsync("/login")).Content.ReadAsStringAsync();
        await c.PostAsync("/auth/login", new FormUrlEncodedContent(new Dictionary<string, string>
            { ["__RequestVerificationToken"] = Antiforgery(login), ["username"] = "admin", ["password"] = "senha-forte-123" }));
        return c;
    }

    private async Task<HttpResponseMessage> PostFormAsync(HttpClient c, string page, string handler)
    {
        var html = await (await c.GetAsync(page)).Content.ReadAsStringAsync();
        return await c.PostAsync(page, new FormUrlEncodedContent(new Dictionary<string, string> { ["_handler"] = handler, ["__RequestVerificationToken"] = Antiforgery(html) }));
    }

    private async Task<IReadOnlyList<string>> BlocklistAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var star = await scope.ServiceProvider.GetRequiredService<AgentPolicyService>().GetAsync("*");
        return NetworkBlocklist.Active(star?.BlockedIps, DateTime.UtcNow);
    }

    /// <summary>
    /// L9 — no laboratório, "Liberar na rede" respondia 500: o formulário principal da tela chegava nulo quando outro
    /// formulário dela era enviado. O administrador não conseguia tirar um IP da blocklist pelo painel.
    /// </summary>
    [Fact]
    public async Task Liberar_um_ip_na_tela_de_politica_funciona()
    {
        var admin = await AdminAsync();
        using (var scope = _factory.Services.CreateScope())
            Assert.True(await scope.ServiceProvider.GetRequiredService<AgentPolicyService>().AddToNetworkBlocklistAsync("10.0.9.66", DateTime.UtcNow));

        var response = await PostFormAsync(admin, "/politica", "unblock-10-0-9-66");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.DoesNotContain("10.0.9.66", await BlocklistAsync());
    }

    [Fact]
    public async Task Remover_conta_de_leitura_e_revogar_agente_tambem_funcionam()
    {
        var admin = await AdminAsync();
        using (var scope = _factory.Services.CreateScope())
        {
            Assert.True(await new OwnerAccountService(scope.ServiceProvider.GetRequiredService<RansomGuardDb>()).AddViewerAsync("soc-l9", "senha-leitura-1", DateTime.UtcNow));
            var agents = scope.ServiceProvider.GetRequiredService<RansomGuard.Server.Agents.AgentEnrollmentService>();
            await agents.EnrollAsync(await agents.CreateTokenAsync(1, TimeSpan.FromHours(1), "t", DateTime.UtcNow), "FS-L9", RansomGuard.Core.Auth.AgentKey.Generate().PublicKeyBase64, "", DateTime.UtcNow);
        }
        int viewerId;
        using (var scope = _factory.Services.CreateScope())
            viewerId = (await scope.ServiceProvider.GetRequiredService<RansomGuardDb>().OwnerAccounts.SingleAsync(a => a.Username == "soc-l9")).Id;

        Assert.Equal(HttpStatusCode.OK, (await PostFormAsync(admin, "/contas", $"remove-{viewerId}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await PostFormAsync(admin, "/agentes", "revogar-FS-L9")).StatusCode);

        using var check = _factory.Services.CreateScope();
        Assert.False(await check.ServiceProvider.GetRequiredService<RansomGuardDb>().OwnerAccounts.AnyAsync(a => a.Username == "soc-l9"));
        Assert.Null(await check.ServiceProvider.GetRequiredService<RansomGuard.Server.Agents.AgentEnrollmentService>().FindAsync("FS-L9"));
    }

    /// <summary>
    /// L14 — depois do "Desfazer" de um bloqueio de IP, a blocklist de rede do painel continuava listando o IP: os
    /// outros servidores seguiam bloqueando quem o administrador acabou de liberar.
    /// </summary>
    [Fact]
    public async Task Desfazer_o_bloqueio_de_ip_tira_o_ip_da_blocklist_de_rede()
    {
        var admin = await AdminAsync();
        const string ip = "10.0.9.77";
        int incidentId, actionId;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RansomGuardDb>();
            var policies = scope.ServiceProvider.GetRequiredService<AgentPolicyService>();
            var detection = new Detection("FS-L14", @"CORP\x", ip, @"\\FS-L14\Dados", Confidence.High, new HashSet<DetectionReason> { DetectionReason.CanaryTouched }, 10, DateTime.UtcNow, DateTime.UtcNow);
            var decision = new ResponseLadder().Decide(detection, new ResponsePolicy { Mode = ResponseMode.Block });
            var runner = new ResponseRunner(new RecordingExecutor());
            await runner.RunAsync(decision, DateTime.UtcNow);
            var incident = AgentIncident.From(detection, decision, runner.Audit, ResponseMode.Block);
            await new IngestionService(db, new AlertEngine(new CollectingAlertSink()), policies: policies)
                .IngestAsync(new AgentBatch("FS-L14", DateTime.UtcNow, null, Array.Empty<FileEvent>(), Array.Empty<HostSignal>(), new[] { incident }));
            var record = await db.Detections.Include(d => d.Actions).SingleAsync(d => d.IncidentId == incident.Id);
            incidentId = record.Id;
            actionId = record.Actions.Single(a => a.Step == "BlockIp").Id;
        }
        Assert.Contains(ip, await BlocklistAsync());

        var response = await PostFormAsync(admin, $"/incidente/{incidentId}", $"revert-{actionId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.DoesNotContain(ip, await BlocklistAsync());
    }
}

/// <summary>L12 — o incidente que junta ciclos conta arquivos distintos, não a soma de cada ciclo.</summary>
public class MergedFileCountTests : DbTestBase
{
    private static readonly DateTime T0 = new(2026, 11, 17, 2, 9, 9, DateTimeKind.Utc);

    private static AgentIncident Cycle(int second, params string[] paths)
    {
        var detection = new Detection("rg-fs1", @"RGLAB\bruno", "10.88.1.40", @"\\rg-fs1\Dados", Confidence.High,
            new HashSet<DetectionReason> { DetectionReason.MassRewrite }, paths.Length, T0, T0.AddSeconds(second), AffectedPaths: paths);
        return AgentIncident.From(detection, ResponseDecision.None("monitor"), Array.Empty<AuditEntry>(), ResponseMode.Monitor, incidentId: "episodio-m4");
    }

    [Fact]
    public async Task Arquivo_que_aparece_em_dois_ciclos_conta_uma_vez()
    {
        var svc = new IngestionService(Db, new AlertEngine(new CollectingAlertSink()));
        var first = Enumerable.Range(0, 200).Select(i => $@"m4\doc{i}.docx").ToArray();
        var second = Enumerable.Range(150, 150).Select(i => $@"m4\doc{i}.docx").ToArray();   // 50 deles já estavam no primeiro

        await svc.IngestAsync(new AgentBatch("rg-fs1", T0.AddSeconds(5), null, Array.Empty<FileEvent>(), Array.Empty<HostSignal>(), new[] { Cycle(4, first) }));
        await svc.IngestAsync(new AgentBatch("rg-fs1", T0.AddSeconds(10), null, Array.Empty<FileEvent>(), Array.Empty<HostSignal>(), new[] { Cycle(9, second) }));

        Assert.Equal(300, (await Db.Detections.SingleAsync()).AffectedFiles);
    }
}
