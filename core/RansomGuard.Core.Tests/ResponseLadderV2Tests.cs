using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;

namespace RansomGuard.Core.Tests;

/// <summary>
/// G4a — escada de resposta v2: bloquear ANTES de derrubar (o cliente SMB reconecta sozinho), degrau
/// "negar este usuário neste share" (funciona sem AD, não derruba os outros), conta no AD só por opt-in,
/// e snapshot VSS preventivo no primeiro sinal (restore garantido antes de qualquer contenção).
/// </summary>
public class ResponseLadderV2Tests
{
    private static readonly DateTime T0 = new(2026, 10, 3, 12, 0, 0, DateTimeKind.Utc);
    private static Detection.Detection High() => new("FS01", @"CORP\ana", "10.0.9.66", @"\\FS01\Fin", Confidence.High,
        new HashSet<DetectionReason> { DetectionReason.CanaryTouched }, 120, T0, T0.AddSeconds(30));
    private static Detection.Detection Medium() => High() with { Confidence = Confidence.Medium, Reasons = new HashSet<DetectionReason> { DetectionReason.MassRewrite } };
    private static ResponseLadder Licensed() => new();   // nome histórico: não há mais licença, a escada é uma só

    [Fact]
    public void Step_order_blocks_ip_before_killing_the_session_and_denies_user_before_touching_ad()
    {
        Assert.True(ResponseStep.PreemptiveSnapshot < ResponseStep.BlockIp);
        Assert.True(ResponseStep.BlockIp < ResponseStep.KillSmbSession);
        Assert.True(ResponseStep.KillSmbSession < ResponseStep.DenyUserOnShare);
        Assert.True(ResponseStep.DenyUserOnShare < ResponseStep.DisableAdAccount);
        Assert.True(ResponseStep.DisableAdAccount < ResponseStep.IsolateShare);
    }

    [Fact]
    public void Default_max_step_stops_before_the_ad_account()
    {
        Assert.Equal(ResponseStep.DenyUserOnShare, new ResponsePolicy().MaxStep);
    }

    [Fact]
    public void Block_high_runs_block_deny_kill_snapshot_in_that_order_by_default()
    {
        var d = Licensed().Decide(High(), new ResponsePolicy { Mode = ResponseMode.Block });
        Assert.True(d.Contains);
        Assert.Equal(new[] { ResponseStep.BlockIp, ResponseStep.DenyUserOnShare, ResponseStep.KillSmbSession, ResponseStep.PreemptiveSnapshot },
            d.Actions.Select(a => a.Step));
        var deny = d.Actions.Single(a => a.Step == ResponseStep.DenyUserOnShare);
        Assert.Equal(@"\\FS01\Fin", deny.Target);
        Assert.Equal(@"CORP\ana", deny.Account);
        Assert.Equal(@"\\FS01\Fin", d.Actions[^1].Target);  // snapshot do volume do share, depois do bloqueio (L4)
    }

    [Fact]
    public void Ad_account_and_share_isolation_require_explicit_opt_in()
    {
        var d = Licensed().Decide(High(), new ResponsePolicy { Mode = ResponseMode.Block, MaxStep = ResponseStep.IsolateShare });
        Assert.Equal(6, d.Actions.Count);
        Assert.Equal(ResponseStep.DisableAdAccount, d.Actions[3].Step);
        Assert.Equal(ResponseStep.IsolateShare, d.Actions[4].Step);
    }

    [Fact]
    public void Block_medium_takes_a_preemptive_snapshot_and_alerts_but_does_not_contain()
    {
        var d = Licensed().Decide(Medium(), new ResponsePolicy { Mode = ResponseMode.Block });
        Assert.True(d.Alert);
        Assert.False(d.Contains);
        var only = Assert.Single(d.Actions);
        Assert.Equal(ResponseStep.PreemptiveSnapshot, only.Step);
    }

    [Fact]
    public void Alert_mode_takes_a_preemptive_snapshot_and_nothing_else()
    {
        var d = Licensed().Decide(High(), new ResponsePolicy { Mode = ResponseMode.Alert });
        Assert.True(d.Alert);
        Assert.False(d.Contains);
        Assert.Equal(ResponseStep.PreemptiveSnapshot, Assert.Single(d.Actions).Step);
    }

    [Fact]
    public void Learning_mode_also_snapshots_but_never_contains()
    {
        var d = Licensed().Decide(High(), new ResponsePolicy { Mode = ResponseMode.Block, LearningMode = true });
        Assert.False(d.Contains);
        Assert.Equal(ResponseStep.PreemptiveSnapshot, Assert.Single(d.Actions).Step);
    }

    [Fact]
    public void Allowlisted_actor_without_canary_gets_no_snapshot_and_no_containment()
    {
        var d = Licensed().Decide(Medium(), new ResponsePolicy { Mode = ResponseMode.Block, AllowlistedUsers = new HashSet<string> { @"CORP\ana" } });
        Assert.True(d.Alert);
        Assert.Empty(d.Actions);
    }

    [Fact]
    public void Monitor_does_nothing_at_all()
    {
        var d = Licensed().Decide(High(), new ResponsePolicy { Mode = ResponseMode.Monitor });

        Assert.Empty(d.Actions);
        Assert.False(d.Alert);
    }

    [Fact]
    public void Snapshot_and_deny_user_targets_are_validated()
    {
        Assert.True(ResponseTarget.IsSafe(new ResponseAction(ResponseStep.PreemptiveSnapshot, "FS01", @"\\FS01\Fin", "r")));
        Assert.True(ResponseTarget.IsSafe(new ResponseAction(ResponseStep.DenyUserOnShare, "FS01", @"\\FS01\Fin", "r", Account: @"CORP\ana")));
        Assert.False(ResponseTarget.IsSafe(new ResponseAction(ResponseStep.DenyUserOnShare, "FS01", @"\\FS01\Fin", "r", Account: null)));
        Assert.False(ResponseTarget.IsSafe(new ResponseAction(ResponseStep.DenyUserOnShare, "FS01", @"\\FS01\Fin", "r", Account: "ana; rm -rf")));
        Assert.False(ResponseTarget.IsSafe(new ResponseAction(ResponseStep.PreemptiveSnapshot, "FS01", "C:\\$(evil)", "r")));
    }

    [Fact]
    public async Task Runner_does_not_count_the_snapshot_as_containment()
    {
        var d = Licensed().Decide(High(), new ResponsePolicy { Mode = ResponseMode.Block });
        var runner = new ResponseRunner(new RecordingExecutor());
        var contained = await runner.RunAsync(d, T0);
        Assert.Equal(3, contained);                       // block, kill, deny
        Assert.Equal(4, runner.Audit.Count(a => a.Operation == "execute"));
    }

    [Fact]
    public void Snapshot_throttle_allows_one_per_volume_per_window()
    {
        var t = new SnapshotThrottle(TimeSpan.FromMinutes(10));
        Assert.True(t.ShouldSnapshot(@"\\FS01\Fin", T0));
        Assert.False(t.ShouldSnapshot(@"\\FS01\Fin", T0.AddMinutes(1)));
        Assert.True(t.ShouldSnapshot(@"\\FS01\RH", T0.AddMinutes(1)));
        Assert.True(t.ShouldSnapshot(@"\\FS01\Fin", T0.AddMinutes(11)));
    }
}

/// <summary>G4b — ataque de DENTRO do servidor: IP/sessão não existem; o alvo é o processo (PID do 4663).</summary>
public class LocalResponseTests
{
    private static readonly DateTime T0 = new(2026, 10, 4, 13, 0, 0, DateTimeKind.Utc);
    private static Detection.Detection Local(params LocalProcess[] procs) => new("FS01", @"FS01\rdp-user", Detection.Detection.LocalOrigin, "Financeiro",
        Confidence.High, new HashSet<DetectionReason> { DetectionReason.CanaryTouched }, 80, T0, T0.AddSeconds(10), procs.Length == 0 ? null : procs);

    [Fact]
    public void Local_attack_stops_the_process_and_skips_ip_and_session_steps()
    {
        var d = new ResponseLadder().Decide(Local(new LocalProcess(4321, @"C:\Users\x\AppData\Local\Temp\enc.exe")), new ResponsePolicy { Mode = ResponseMode.Block });
        Assert.Equal(new[] { ResponseStep.StopProcess, ResponseStep.DenyUserOnShare, ResponseStep.PreemptiveSnapshot }, d.Actions.Select(a => a.Step));
        var stop = d.Actions[0];
        Assert.Equal("4321", stop.Target);
        Assert.Contains("enc.exe", stop.Account);
        Assert.True(ResponseTarget.IsSafe(stop));
    }

    [Fact]
    public void Protected_system_processes_are_never_targeted()
    {
        var d = new ResponseLadder().Decide(Local(new LocalProcess(900, @"C:\Windows\System32\svchost.exe"), new LocalProcess(4, "System"), new LocalProcess(5555, @"D:\tools\x.exe")),
            new ResponsePolicy { Mode = ResponseMode.Block });
        var stops = d.Actions.Where(a => a.Step == ResponseStep.StopProcess).ToList();
        Assert.Equal("5555", Assert.Single(stops).Target);
    }

    [Fact]
    public void Local_attack_without_process_info_still_denies_the_user_on_the_share()
    {
        var d = new ResponseLadder().Decide(Local(), new ResponsePolicy { Mode = ResponseMode.Block });
        Assert.Equal(new[] { ResponseStep.DenyUserOnShare, ResponseStep.PreemptiveSnapshot }, d.Actions.Select(a => a.Step));
    }

    [Theory]
    [InlineData("0", false)]
    [InlineData("4", false)]
    [InlineData("abc", false)]
    [InlineData("1234; stop", false)]
    [InlineData("1234", true)]
    public void Process_targets_are_validated(string target, bool safe) =>
        Assert.Equal(safe, ResponseTarget.IsSafe(new ResponseAction(ResponseStep.StopProcess, "FS01", target, "r")));

    [Fact]
    public void Engine_collects_local_processes_from_4663_events()
    {
        var events = Enumerable.Range(0, 50).Select(i => new FileEvent(T0.AddSeconds(i), @"FS01\u", Detection.Detection.LocalOrigin, "Fin", FileOp.Rename, $"f{i}.xlsx", ".zzz",
            IsCanary: i == 2, ProcessId: i % 2 == 0 ? 4321 : 8765, ProcessName: i % 2 == 0 ? @"C:\tmp\a.exe" : @"C:\tmp\b.exe")).ToList();
        var d = new DetectionEngine().Analyze(events).Single();
        Assert.True(d.IsLocal);
        Assert.Equal(2, d.Processes!.Count);
        Assert.Contains(d.Processes, p => p.Pid == 4321 && p.Name.EndsWith("a.exe"));
    }
}
