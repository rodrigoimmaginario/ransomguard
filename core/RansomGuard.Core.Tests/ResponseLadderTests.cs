using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;
using DetectionModel = RansomGuard.Core.Detection.Detection;

namespace RansomGuard.Core.Tests;

public class ResponseLadderTests
{
    private static readonly DateTime T0 = new(2026, 7, 23, 2, 0, 0, DateTimeKind.Utc);

    private static DetectionModel HighIncident(
        string user = @"CORP\vendas1", string ip = "10.0.9.66",
        params DetectionReason[] reasons) =>
        new("FS01", user, ip, @"\\FS01\Financeiro", Confidence.High,
            new HashSet<DetectionReason>(reasons.Length > 0 ? reasons : new[] { DetectionReason.CanaryTouched }),
            120, T0, T0.AddSeconds(30));

    private static DetectionModel MediumIncident() =>
        new("FS01", @"CORP\bob", "10.0.5.20", @"\\FS01\Sh", Confidence.Medium,
            new HashSet<DetectionReason> { DetectionReason.MassRewrite }, 60, T0, T0.AddSeconds(20));

    [Fact]
    public void Block_high_confidence_executes_ladder_in_order()
    {
        var ladder = new ResponseLadder();
        var policy = new ResponsePolicy { Mode = ResponseMode.Block, MaxStep = ResponseStep.IsolateShare };

        var decision = ladder.Decide(HighIncident(), policy);

        Assert.True(decision.Contains);
        // L4: bloqueio primeiro, snapshot por último. L5: negar no share ANTES de derrubar a sessão (a reconexão
        // passa pelas conexões TCP já abertas, que a regra de firewall não derruba). Negar no share antes do AD.
        Assert.Equal(
            new[] { ResponseStep.BlockIp, ResponseStep.DenyUserOnShare, ResponseStep.KillSmbSession,
                    ResponseStep.DisableAdAccount, ResponseStep.IsolateShare, ResponseStep.PreemptiveSnapshot },
            decision.Actions.Select(a => a.Step));
        // IP/sessão miram o IP de origem; conta mira o usuário — a atribuição vem da detecção.
        Assert.Equal("10.0.9.66", decision.Actions[0].Target);
        Assert.Equal(@"CORP\vendas1", decision.Actions[3].Target);
    }

    [Fact]
    public void Max_step_limits_the_ladder()
    {
        var ladder = new ResponseLadder();
        var policy = new ResponsePolicy { Mode = ResponseMode.Block, MaxStep = ResponseStep.BlockIp };

        var decision = ladder.Decide(HighIncident(), policy);

        Assert.Equal(new[] { ResponseStep.BlockIp, ResponseStep.PreemptiveSnapshot },
            decision.Actions.Select(a => a.Step));
        Assert.DoesNotContain(decision.Actions, a => a.Step == ResponseStep.DisableAdAccount);
    }

    [Fact]
    public void Monitor_mode_never_acts_or_alerts()
    {
        var ladder = new ResponseLadder();
        var decision = ladder.Decide(HighIncident(), new ResponsePolicy { Mode = ResponseMode.Monitor });

        Assert.False(decision.Contains);
        Assert.False(decision.Alert);
    }

    [Fact]
    public void Alert_mode_alerts_but_does_not_contain()
    {
        var ladder = new ResponseLadder();
        var decision = ladder.Decide(HighIncident(), new ResponsePolicy { Mode = ResponseMode.Alert });

        Assert.True(decision.Alert);
        Assert.False(decision.Contains);
    }

    [Fact]
    public void Medium_confidence_only_alerts_even_in_block_mode()
    {
        var ladder = new ResponseLadder();
        var decision = ladder.Decide(MediumIncident(), new ResponsePolicy { Mode = ResponseMode.Block });

        Assert.True(decision.Alert);
        Assert.False(decision.Contains);
    }

    [Fact]
    public void Learning_mode_suppresses_containment()
    {
        var ladder = new ResponseLadder();
        var policy = new ResponsePolicy { Mode = ResponseMode.Block, LearningMode = true };

        var decision = ladder.Decide(HighIncident(), policy);
        Assert.True(decision.Alert);
        Assert.False(decision.Contains);
    }

    [Fact]
    public void Allowlisted_actor_without_canary_is_not_contained()
    {
        var ladder = new ResponseLadder();
        var policy = new ResponsePolicy
        {
            Mode = ResponseMode.Block,
            AllowlistedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"CORP\svc-backup" }
        };
        // Incidente High por VSS (não por canário), atribuído ao backup allowlisted.
        var d = HighIncident(user: @"CORP\svc-backup", reasons: DetectionReason.VssDeletion);

        var decision = ladder.Decide(d, policy);
        Assert.False(decision.Contains); // guard-rail salva o backup
        Assert.True(decision.Alert);
    }

    [Fact]
    public void Allowlisted_actor_touching_canary_is_still_contained()
    {
        var ladder = new ResponseLadder();
        var policy = new ResponsePolicy
        {
            Mode = ResponseMode.Block,
            AllowlistedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"CORP\svc-backup" }
        };
        var d = HighIncident(user: @"CORP\svc-backup", reasons: DetectionReason.CanaryTouched);

        var decision = ladder.Decide(d, policy);
        Assert.True(decision.Contains); // canário fura a allowlist
    }

    [Fact]
    public void Containment_in_block_mode_needs_no_license()
    {
        // O produto é gratuito: quem liga a contenção é o administrador, pelo modo. Não há porta de licença.
        var decision = new ResponseLadder().Decide(HighIncident(), new ResponsePolicy { Mode = ResponseMode.Block });

        Assert.True(decision.Contains);
        Assert.True(decision.Alert);
        Assert.DoesNotContain("licença", decision.Rationale, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Monitor_mode_never_acts_whatever_the_confidence()
    {
        var decision = new ResponseLadder().Decide(HighIncident(), new ResponsePolicy { Mode = ResponseMode.Monitor });

        Assert.False(decision.Contains);
        Assert.False(decision.Alert);
        Assert.Empty(decision.Actions);
    }

    [Fact]
    public async Task Runner_executes_and_audits_each_action_and_can_revert()
    {
        var ladder = new ResponseLadder();
        var policy = new ResponsePolicy { Mode = ResponseMode.Block, MaxStep = ResponseStep.DisableAdAccount };
        var decision = ladder.Decide(HighIncident(), policy);

        var exec = new RecordingExecutor();
        var runner = new ResponseRunner(exec);
        await runner.RunAsync(decision, T0);

        Assert.Equal(5, exec.Executed.Count);                               // snapshot + 4 degraus
        Assert.Equal(5, runner.Audit.Count(a => a.Operation == "execute"));
        Assert.Equal(4, runner.ExecutedCount);                              // snapshot não é contenção

        // Remediação: admin reabilita a conta, auditado.
        await runner.RevertAsync(decision.Actions.Last(), T0.AddHours(1), @"CORP\admin", "falso positivo confirmado");
        Assert.Single(exec.Reverted);
        Assert.Contains(runner.Audit, a => a.Operation == "revert" && a.Actor == @"CORP\admin");
    }

    // R4 — executor que sempre falha: a auditoria registra 'fail', nunca 'execute', e nada conta.
    private sealed class FailingExecutor : IResponseExecutor
    {
        public Task<ResponseOutcome> ExecuteAsync(ResponseAction a, CancellationToken ct = default)
            => Task.FromResult(ResponseOutcome.Fail("powershell falhou"));
        public Task<ResponseOutcome> RevertAsync(ResponseAction a, CancellationToken ct = default)
            => Task.FromResult(ResponseOutcome.Fail("powershell falhou"));
    }

    [Fact]
    public async Task Failed_execution_is_audited_as_fail_and_not_counted()
    {
        var ladder = new ResponseLadder();
        var policy = new ResponsePolicy { Mode = ResponseMode.Block, MaxStep = ResponseStep.DisableAdAccount };
        var decision = ladder.Decide(HighIncident(), policy);

        var runner = new ResponseRunner(new FailingExecutor());
        var executed = await runner.RunAsync(decision, T0);

        Assert.Equal(0, executed);                                       // nada contou como contenção
        Assert.Equal(0, runner.Audit.Count(a => a.Operation == "execute"));
        Assert.Equal(5, runner.Audit.Count(a => a.Operation == "fail")); // falha registrada como falha (snapshot + 4)
    }

    [Fact]
    public async Task Unsafe_target_is_skipped_before_reaching_the_executor()
    {
        // Incidente cujo usuário carrega uma tentativa de injeção — metadado de evento manipulado.
        var incident = HighIncident(user: "x'; Remove-Item C:\\ -Recurse; #", ip: "10.0.9.66");
        var policy = new ResponsePolicy { Mode = ResponseMode.Block, MaxStep = ResponseStep.DisableAdAccount };
        var decision = new ResponseLadder().Decide(incident, policy);

        var exec = new RecordingExecutor();
        var runner = new ResponseRunner(exec);
        await runner.RunAsync(decision, T0);

        // O passo DisableAdAccount mira o usuário inseguro → pulado, nunca executado.
        Assert.DoesNotContain(exec.Executed, a => a.Step == ResponseStep.DisableAdAccount);
        Assert.Contains(runner.Audit, a => a.Operation == "skip" && a.Action.Step == ResponseStep.DisableAdAccount);
        // Os passos de IP (alvo legítimo) seguem executando normalmente.
        Assert.Contains(exec.Executed, a => a.Step == ResponseStep.BlockIp);
    }
}
