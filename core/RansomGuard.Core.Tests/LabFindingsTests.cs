using RansomGuard.Core.Detection;
using RansomGuard.Core.Incidents;
using RansomGuard.Core.Response;

namespace RansomGuard.Core.Tests;

/// <summary>
/// Correções do que a sessão 1 do laboratório mostrou (relatorio-2026-11-16-m3-sessao-1.md), numa rede de verdade.
/// </summary>
public class LabFindingsTests
{
    private static readonly DateTime T0 = new(2026, 11, 16, 23, 28, 31, DateTimeKind.Utc);

    private static Detection.Detection High(string ip = "10.88.1.40", DateTime? first = null, DateTime? last = null) =>
        new("rg-fs1", @"RGLAB\bruno", ip, @"\\rg-fs1\Dados", Confidence.High,
            new HashSet<DetectionReason> { DetectionReason.CanaryTouched, DetectionReason.MassRewrite }, 42, first ?? T0, last ?? T0.AddSeconds(1));

    /// <summary>
    /// L4 — no laboratório a decisão saiu em 0,95 s, mas o primeiro degrau era o snapshot, que leva segundos: dos 169
    /// arquivos tocados, cerca de 150 foram DEPOIS da decisão. Primeiro se fecha a porta; o ponto de restauração vem
    /// em seguida.
    /// </summary>
    [Fact]
    public void Em_Block_o_bloqueio_vem_antes_do_snapshot()
    {
        var decision = new ResponseLadder().Decide(High(), new ResponsePolicy { Mode = ResponseMode.Block });

        var steps = decision.Actions.Select(a => a.Step).ToList();
        Assert.Equal(ResponseStep.BlockIp, steps[0]);
        Assert.Equal(ResponseStep.PreemptiveSnapshot, steps[^1]);
        Assert.Equal(new[] { ResponseStep.BlockIp, ResponseStep.DenyUserOnShare, ResponseStep.KillSmbSession, ResponseStep.PreemptiveSnapshot }, steps);
    }

    /// <summary>
    /// L5 (laboratório, sessão 5) — 2 s depois da contenção a MESMA sessão SMB do atacante estava aberta e ele seguiu
    /// gravando por até 63 s. A regra de firewall não derruba conexão TCP já aberta; derrubada a sessão, o cliente
    /// reconecta por essas conexões antes de a negação no share existir. Negar primeiro faz a reconexão falhar.
    /// </summary>
    [Fact]
    public void A_negacao_no_share_vem_antes_de_derrubar_a_sessao()
    {
        var steps = new ResponseLadder().Decide(High(), new ResponsePolicy { Mode = ResponseMode.Block })
            .Actions.Select(a => a.Step).ToList();

        Assert.True(steps.IndexOf(ResponseStep.DenyUserOnShare) < steps.IndexOf(ResponseStep.KillSmbSession));
    }

    [Fact]
    public void Com_teto_na_sessao_a_sessao_e_derrubada_mesmo_sem_a_negacao()
    {
        var steps = new ResponseLadder().Decide(High(), new ResponsePolicy { Mode = ResponseMode.Block, MaxStep = ResponseStep.KillSmbSession })
            .Actions.Select(a => a.Step).ToList();

        Assert.Equal(new[] { ResponseStep.BlockIp, ResponseStep.KillSmbSession, ResponseStep.PreemptiveSnapshot }, steps);
    }

    [Fact]
    public void Sem_contencao_o_snapshot_continua_sendo_a_unica_acao()
    {
        var alert = new ResponseLadder().Decide(High(), new ResponsePolicy { Mode = ResponseMode.Alert });

        Assert.Equal(ResponseStep.PreemptiveSnapshot, Assert.Single(alert.Actions).Step);
    }

    /// <summary>
    /// L3 — um ataque de 8 segundos virou cinco incidentes no painel, um por ciclo do agente. O mesmo ator, no mesmo
    /// share, em ciclos seguidos, é o MESMO incidente.
    /// </summary>
    [Fact]
    public void Deteccoes_seguidas_do_mesmo_ator_recebem_o_mesmo_identificador()
    {
        var episodes = new IncidentEpisodes();

        var first = episodes.IdFor(High(first: T0, last: T0.AddSeconds(1)));
        var second = episodes.IdFor(High(first: T0.AddSeconds(5), last: T0.AddSeconds(9)));
        var later = episodes.IdFor(High(first: T0.AddMinutes(3), last: T0.AddMinutes(3).AddSeconds(2)));

        Assert.Equal(first, second);
        Assert.Equal(first, later);                               // ainda dentro do intervalo que une um episódio
    }

    [Fact]
    public void Outro_ator_ou_o_mesmo_ator_muito_depois_e_outro_incidente()
    {
        var episodes = new IncidentEpisodes();
        var first = episodes.IdFor(High());

        Assert.NotEqual(first, episodes.IdFor(High(ip: "10.88.1.41")));
        Assert.NotEqual(first, episodes.IdFor(High(first: T0 + IncidentEpisodes.Gap + TimeSpan.FromMinutes(1), last: T0 + IncidentEpisodes.Gap + TimeSpan.FromMinutes(2))));
    }

    [Fact]
    public void O_incidente_do_agente_carrega_o_identificador_do_episodio()
    {
        var detection = High(first: T0.AddSeconds(5), last: T0.AddSeconds(9));

        var incident = AgentIncident.From(detection, ResponseDecision.None("x"), Array.Empty<AuditEntry>(), ResponseMode.Monitor, incidentId: "episodio-1");

        Assert.Equal("episodio-1", incident.Id);
        Assert.NotEqual("episodio-1", AgentIncident.From(detection, ResponseDecision.None("x"), Array.Empty<AuditEntry>(), ResponseMode.Monitor).Id);
    }
}
