using RansomGuard.Core.Score;

namespace RansomGuard.Core.Tests;

public class RiskScoreEngineTests
{
    /// <summary>Servidor exemplar: não viola nenhuma regra (deve dar 100).</summary>
    private static PostureSnapshot Hardened(string name = "FS-GOOD") => new()
    {
        Server = name,
        SmbV1Enabled = false,
        SmbSigningRequired = true,
        NtlmUnrestricted = false,
        SmbAuthRateLimiter = true,
        Smb445ExposedBroadly = false,
        SharesWritableByEveryone = false,
        BroadNtfsPermissions = false,
        VssEnabled = true,
        BackupServiceRunning = true,
        BackupsProtected = true,
        FsrmActive = true,
        ShareAuditingEnabled = true,
        CanariesPlanted = true,
        AgentInstalled = true,
        OverprivilegedServiceAccounts = false,
        ExcessLocalAdmins = false,
        OsEndOfLifeOrUnpatched = false,
        RdpExposed = false
    };

    /// <summary>Servidor péssimo: viola tudo (deve dar 0).</summary>
    private static PostureSnapshot Terrible(string name = "FS-BAD") => new()
    {
        Server = name,
        SmbV1Enabled = true,
        SmbSigningRequired = false,
        NtlmUnrestricted = true,
        SmbAuthRateLimiter = false,
        Smb445ExposedBroadly = true,
        SharesWritableByEveryone = true,
        BroadNtfsPermissions = true,
        VssEnabled = false,
        BackupServiceRunning = false,
        BackupsProtected = false,
        FsrmActive = false,
        ShareAuditingEnabled = false,
        SecurityLogMaxBytes = 20L * 1024 * 1024,   // G2: 20 MB padrão do Windows = pequeno demais
        CanariesPlanted = false,
        AgentInstalled = false,
        OverprivilegedServiceAccounts = true,
        ExcessLocalAdmins = true,
        OsEndOfLifeOrUnpatched = true,
        RdpExposed = true
    };

    [Fact]
    public void Rule_weights_sum_to_100()
        => Assert.Equal(100, ScoreRules.MaxScore(ScoreRules.Default));

    [Fact]
    public void Hardened_server_scores_100_with_no_findings()
    {
        var r = new RiskScoreEngine().ScoreServer(Hardened());
        Assert.Equal(100, r.Score);
        Assert.Empty(r.Findings);
        Assert.Equal(RiskBand.Good, r.Band);
    }

    [Fact]
    public void Terrible_server_scores_0_and_finds_every_rule()
    {
        var r = new RiskScoreEngine().ScoreServer(Terrible());
        Assert.Equal(0, r.Score);
        Assert.Equal(ScoreRules.Default.Count, r.Findings.Count);
        Assert.Equal(RiskBand.Critical, r.Band);
    }

    [Fact]
    public void Findings_are_ordered_by_priority_desc()
    {
        var r = new RiskScoreEngine().ScoreServer(Terrible());
        var priorities = r.Findings.Select(f => f.Priority).ToList();
        Assert.Equal(priorities.OrderByDescending(p => p).ToList(), priorities);
    }

    [Fact]
    public void Every_rule_has_attack_premise_and_fix()
    {
        Assert.All(ScoreRules.Default, rule =>
        {
            Assert.False(string.IsNullOrWhiteSpace(rule.AttackPremise));
            Assert.False(string.IsNullOrWhiteSpace(rule.Fix));
        });
    }

    [Fact]
    public void Fixing_a_finding_raises_the_score()
    {
        var engine = new RiskScoreEngine();
        var before = engine.ScoreServer(Terrible()).Score;

        // Corrige o achado de maior peso empatado (share-everyone, peso 11).
        var improved = Terrible() with { SharesWritableByEveryone = false };
        var after = engine.ScoreServer(improved).Score;

        Assert.True(after > before, $"esperado subir: {before} → {after}");
        Assert.Equal(11, after - before);
    }

    [Fact]
    public void Missing_agent_produces_a_detection_finding()
    {
        var noAgent = Hardened() with { AgentInstalled = false };
        var r = new RiskScoreEngine().ScoreServer(noAgent);
        Assert.Contains(r.Findings, f => f.Rule.Id == "agent");
        Assert.Equal(95, r.Score); // perdeu só os 5 pts do agente (G2 rebalanceou a categoria Detecção)
    }

    [Fact]
    public void Network_score_averages_servers()
    {
        var net = new RiskScoreEngine().ScoreNetwork(new[] { Hardened("A"), Terrible("B") });
        Assert.Equal(50, net.Score); // média de 100 e 0
        Assert.Equal("B", net.Servers[0].Server); // pior primeiro
    }

    [Fact]
    public void Coverage_gap_penalizes_network_score()
    {
        var engine = new RiskScoreEngine();
        // 1 servidor perfeito (100), mas 1 outro descoberto sem agente → cobertura 50% → nota 50.
        var net = engine.ScoreNetwork(new[] { Hardened("A") }, discoveredWithoutAgent: 1);
        Assert.Equal(50, net.Score);
        Assert.Equal(1, net.ServersWithoutAgent);
    }
}

public class ScoreReportTests
{
    private static PostureSnapshot Bad(string name) => new()
    {
        Server = name,
        SharesWritableByEveryone = true,
        VssEnabled = false,
        BackupServiceRunning = false,
        FsrmActive = false,
        AgentInstalled = true,
        SmbSigningRequired = true,
        SmbAuthRateLimiter = true,
        BackupsProtected = true,
        ShareAuditingEnabled = true,
        CanariesPlanted = true
    };

    [Fact]
    public void Executive_report_shows_score_and_top_fixes()
    {
        var net = new RiskScoreEngine().ScoreNetwork(new[] { Bad("FS01") });
        var text = ScoreReport.BuildExecutive(net);

        Assert.Contains("Nota consolidada", text);
        Assert.Contains("FS01", text);
        Assert.Contains("Prioridades", text);
        // A correção do share Everyone (maior prioridade) deve aparecer no topo.
        Assert.Contains("least privilege", text);
    }

    [Fact]
    public void Executive_report_flags_servers_without_agent()
    {
        var net = new RiskScoreEngine().ScoreNetwork(new[] { Bad("FS01") }, discoveredWithoutAgent: 3);
        var text = ScoreReport.BuildExecutive(net);
        Assert.Contains("sem agente", text);
        Assert.Contains("3", text);
    }

    [Fact]
    public void Server_detail_lists_premise_and_fix_for_each_finding()
    {
        var s = new RiskScoreEngine().ScoreServer(Bad("FS01"));
        var text = ScoreReport.BuildServerDetail(s);
        Assert.Contains("Porquê:", text);
        Assert.Contains("Correção:", text);
    }
}
