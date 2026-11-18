using RansomGuard.Core.Score;
using RansomGuard.Server.Reporting;

namespace RansomGuard.Server.Tests;

public class HtmlReportTests
{
    private static PostureSnapshot Bad(string name) => new()
    {
        Server = name,
        SharesWritableByEveryone = true,
        VssEnabled = false,
        BackupServiceRunning = false,
        AgentInstalled = true,
        SmbSigningRequired = true,
        SmbAuthRateLimiter = true,
        BackupsProtected = true,
        FsrmActive = true,
        ShareAuditingEnabled = true,
        CanariesPlanted = true
    };

    [Fact]
    public void Report_contains_score_band_and_top_fix()
    {
        var net = new RiskScoreEngine().ScoreNetwork(new[] { Bad("FS01") }, discoveredWithoutAgent: 2);
        var html = HtmlReport.BuildExecutive(net, new DateTime(2026, 7, 23, 10, 0, 0, DateTimeKind.Utc));

        Assert.Contains("/100", html);
        Assert.Contains("FS01", html);
        Assert.Contains("least privilege", html);      // correção do share Everyone
        Assert.Contains("sem agente", html);           // alerta de cobertura
        Assert.Contains("window.print()", html);       // botão imprimir/salvar PDF
    }

    [Fact]
    public void Report_html_encodes_server_names()
    {
        var net = new RiskScoreEngine().ScoreNetwork(new[] { Bad("FS<script>") });
        var html = HtmlReport.BuildExecutive(net, DateTime.UtcNow);
        Assert.DoesNotContain("<script>", html.Replace("window.print()", ""));
        Assert.Contains("FS&lt;script&gt;", html);
    }
}
