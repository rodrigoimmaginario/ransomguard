using RansomGuard.Core.Detection;
using RansomGuard.Core.Incidents;
using RansomGuard.Core.Response;

namespace RansomGuard.Core.Tests;

public class AgentIncidentTests
{
    private static readonly DateTime T0 = new(2026, 10, 3, 12, 0, 0, DateTimeKind.Utc);
    private static Detection.Detection Det(DateTime? first = null) => new("FS01", @"CORP\ana", "10.0.9.66", @"\\FS01\Fin",
        Confidence.High, new HashSet<DetectionReason> { DetectionReason.CanaryTouched }, 120, first ?? T0, (first ?? T0).AddSeconds(30));

    [Fact]
    public void Id_is_deterministic_and_case_insensitive_on_names()
    {
        var a = AgentIncident.ComputeId("FS01", @"CORP\ana", "10.0.9.66", @"\\FS01\Fin", T0);
        var b = AgentIncident.ComputeId("fs01", @"corp\ANA", "10.0.9.66", @"\\fs01\fin", T0);
        Assert.Equal(a, b);
        Assert.Equal(24, a.Length);
        Assert.NotEqual(a, AgentIncident.ComputeId("FS01", @"CORP\ana", "10.0.9.66", @"\\FS01\Fin", T0.AddSeconds(1)));
        Assert.NotEqual(a, AgentIncident.ComputeId("FS01", @"CORP\ana", "10.0.9.67", @"\\FS01\Fin", T0));
    }

    [Fact]
    public async Task From_captures_decision_actions_and_outcomes()
    {
        var decision = new ResponseLadder().Decide(Det(), new ResponsePolicy { Mode = ResponseMode.Block, MaxStep = ResponseStep.BlockIp });
        var runner = new ResponseRunner(new RecordingExecutor());
        await runner.RunAsync(decision, T0.AddSeconds(31));

        var inc = AgentIncident.From(Det(), decision, runner.Audit, ResponseMode.Block);

        Assert.Equal("Block", inc.Mode);
        Assert.True(inc.Contained);
        Assert.Equal(2, inc.Report.Actions.Count);                       // snapshot + BlockIp (MaxStep)
        Assert.All(inc.Report.Actions, a => Assert.Equal("execute", a.Operation));
        Assert.Equal("PreemptiveSnapshot", inc.Report.Actions[^1].Step);   // L4: o snapshot vem depois do bloqueio
        Assert.Equal("BlockIp", inc.Report.Actions[0].Step);
        Assert.Contains("High", inc.Report.Confidence);
        Assert.False(string.IsNullOrWhiteSpace(inc.Rationale));
    }

    [Fact]
    public void Monitor_mode_incident_has_no_actions_and_is_not_contained()
    {
        var decision = new ResponseLadder().Decide(Det(), new ResponsePolicy { Mode = ResponseMode.Monitor });
        var inc = AgentIncident.From(Det(), decision, Array.Empty<AuditEntry>(), ResponseMode.Monitor);
        Assert.False(inc.Contained);
        Assert.Empty(inc.Report.Actions);
        Assert.Equal("Monitor", inc.Mode);
    }

    [Fact]
    public void Round_trips_through_json()
    {
        var inc = AgentIncident.From(Det(), ResponseDecision.None("x"), Array.Empty<AuditEntry>(), ResponseMode.Alert);
        var json = System.Text.Json.JsonSerializer.Serialize(inc);
        var back = System.Text.Json.JsonSerializer.Deserialize<AgentIncident>(json);
        Assert.Equal(inc.Id, back!.Id);
        Assert.Equal(inc.Report.User, back.Report.User);
        Assert.Equal("Alert", back.Mode);
    }
}
