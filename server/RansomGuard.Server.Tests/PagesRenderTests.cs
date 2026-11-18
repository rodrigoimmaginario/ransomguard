using Bunit;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using RansomGuard.Core.Detection;
using RansomGuard.Server.Auth;
using RansomGuard.Server.Components.Pages;
using RansomGuard.Server.Data;
using RansomGuard.Server.Policy;
using RansomGuard.Server.Security;

namespace RansomGuard.Server.Tests;

/// <summary>
/// F36 — as páginas do painel renderizam com dados reais (SQLite em memória): estado vazio com onboarding, lista de
/// incidentes com a coluna de contenção, detalhe com linha do tempo e arquivos, política com formulário.
/// </summary>
public sealed class PagesRenderTests : IDisposable
{
    private static readonly DateTime T0 = new(2026, 10, 4, 16, 0, 0, DateTimeKind.Utc);
    private readonly SqliteConnection _conn;
    private readonly Bunit.BunitContext _ctx = new();
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rg-pages-" + Guid.NewGuid().ToString("N"));

    public PagesRenderTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:"); _conn.Open();
        _ctx.Services.AddDbContext<RansomGuardDb>(o => o.UseSqlite(_conn));
        _ctx.Services.AddSingleton(new InstallSecrets { IngestSecret = "segredo-de-teste-123", CertificateThumbprint = "ABCDEF" });
        _ctx.Services.AddSingleton<IHttpContextAccessor>(new HttpContextAccessor { HttpContext = new DefaultHttpContext { Request = { Scheme = "https", Host = new HostString("painel", 5001) } } });
        _ctx.Services.AddSingleton<IInstallKeyStore>(new FileInstallKeyStore(Path.Combine(_dir, "k.json")));
        _ctx.Services.AddScoped<AgentPolicyService>();
        // As telas só mostram os controles de administração a quem é administrador (D10): estes testes são do admin.
        var auth = _ctx.AddAuthorization();
        auth.SetAuthorized("admin");
        auth.SetRoles(Roles.Admin);
        using var db = Db(); db.Database.EnsureCreated(); AgentPolicyService.EnsureSchemaAsync(db).GetAwaiter().GetResult();
    }

    private RansomGuardDb Db() => new(new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite(_conn).Options);
    public void Dispose() { _ctx.Dispose(); _conn.Dispose(); if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    private DetectionRecord SeedIncident()
    {
        using var db = Db();
        var srv = new ServerEntity { Name = "FS01", FirstSeen = T0, LastSeen = T0, LastScore = 61 };
        var det = new DetectionRecord
        {
            Server = srv, At = T0, User = @"CORP\ana", SourceIp = "10.0.9.66", Share = @"\\FS01\Fin", Confidence = Confidence.High,
            Reasons = "CanaryTouched", AffectedFiles = 42, IncidentId = "abc123", Source = "agent", Mode = "Block", Rationale = "Bloqueio: alta confiança", Contained = true,
            AffectedPathsJson = "[\"2024\\\\a.xlsx\",\"2024\\\\b.xlsx\"]",
            Actions =
            {
                new ResponseActionRecord { At = T0, Actor = "RansomGuard", Operation = "execute", Step = "PreemptiveSnapshot", Target = @"\\FS01\Fin" },
                new ResponseActionRecord { At = T0, Actor = "RansomGuard", Operation = "fail", Step = "BlockIp", Target = "10.0.9.66", Justification = "firewall indisponível" },
                new ResponseActionRecord { At = T0, Actor = "RansomGuard", Operation = "execute", Step = "DenyUserOnShare", Target = @"\\FS01\Fin", Account = @"CORP\ana" },
            }
        };
        db.Detections.Add(det); db.SaveChanges();
        return det;
    }

    [Fact]
    public void Home_without_agents_points_to_the_enrollment_page_and_shows_no_secret()
    {
        var cut = _ctx.Render<Home>();
        Assert.Contains("Nenhum agente ainda", cut.Markup);
        Assert.NotNull(cut.Find("a[href='/agentes']"));
        Assert.DoesNotContain("INGESTSECRET", cut.Markup);       // B1: não existe mais segredo compartilhado para mostrar
        Assert.DoesNotContain("segredo-de-teste-123", cut.Markup);
    }

    [Fact]
    public void Home_with_servers_lists_them_worst_first_and_hides_onboarding()
    {
        SeedIncident();
        using (var db = Db()) { db.Servers.Add(new ServerEntity { Name = "FS02", FirstSeen = T0, LastSeen = T0, LastScore = 20 }); db.SaveChanges(); }
        var cut = _ctx.Render<Home>();
        Assert.DoesNotContain("Nenhum agente ainda", cut.Markup);
        var rows = cut.FindAll("table.rg tbody tr").Select(r => r.TextContent).ToList();
        Assert.Equal(2, rows.Count);
        Assert.Contains("FS02", rows[0]);   // pior primeiro
        Assert.Contains("1", cut.Find(".rg-cards").TextContent);   // 1 incidente
    }

    [Fact]
    public void Incidents_list_shows_containment_summary_and_detail_link()
    {
        var det = SeedIncident();
        var cut = _ctx.Render<Incidentes>();
        var row = cut.Find("table.rg tbody tr").TextContent;
        Assert.Contains("CORP\\ana", row);
        Assert.Contains("1 ok · 1 falha(s)", row);
        Assert.NotNull(cut.Find($"a[href='/incidente/{det.Id}']"));
    }

    [Fact]
    public void Incidents_list_empty_state()
    {
        var cut = _ctx.Render<Incidentes>();
        Assert.Contains("Nenhum incidente registrado", cut.Markup);
    }

    [Fact]
    public void Incident_detail_shows_timeline_files_and_revert_only_for_executed_actions()
    {
        var det = SeedIncident();
        var cut = _ctx.Render<Incidente>(p => p.Add(x => x.Id, det.Id));
        Assert.Contains("verdade do agente", cut.Markup);
        Assert.Contains("Bloqueio: alta confiança", cut.Markup);
        var rows = cut.FindAll("table.rg").Last(t => t.TextContent.Contains("Degrau")).QuerySelectorAll("tbody tr").Select(r => r.TextContent).ToList();
        Assert.Equal(3, rows.Count);
        Assert.Contains("falhou", rows[1]);
        Assert.Contains("firewall indisponível", rows[1]);
        Assert.Equal(2, cut.FindAll("button").Count(b => b.TextContent.Contains("Desfazer")));   // só as executadas
        Assert.Contains("Arquivos afetados (2)", cut.Markup);
        Assert.Contains("2024", cut.Markup);
        Assert.NotNull(cut.Find($"a[href='/incidente/{det.Id}/arquivos.txt']"));
    }

    [Fact]
    public void Incident_detail_not_found()
    {
        var cut = _ctx.Render<Incidente>(p => p.Add(x => x.Id, 999));
        Assert.Contains("Incidente não encontrado", cut.Markup);
    }

    [Fact]
    public void Policy_page_renders_form_blocklist_and_overrides()
    {
        using (var db = Db())
        {
            var svc = new AgentPolicyService(db, new FileInstallKeyStore(Path.Combine(_dir, "k.json")));
            svc.SaveAsync(new AgentPolicyEntity { Server = "*", Mode = "Alert", BlockedIps = NetworkBlocklist.Add("", "10.0.9.66", DateTime.UtcNow) }, DateTime.UtcNow).GetAwaiter().GetResult();
            svc.SaveAsync(new AgentPolicyEntity { Server = "FS02", Mode = "Block" }, DateTime.UtcNow).GetAwaiter().GetResult();
        }
        var cut = _ctx.Render<Politica>();
        Assert.Contains("padrão da rede", cut.Markup);
        Assert.NotNull(cut.Find("select"));
        Assert.Contains("Blocklist de rede (1)", cut.Markup);
        Assert.Contains("10.0.9.66", cut.Markup);
        Assert.Contains("Servidores com política própria", cut.Markup);
        Assert.NotNull(cut.Find("a[href='/politica/FS02']"));
    }
}
