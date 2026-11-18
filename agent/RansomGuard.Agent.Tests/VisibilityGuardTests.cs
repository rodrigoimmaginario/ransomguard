using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Tests;

/// <summary>G2 — cegar o agente nunca é silêncio: 4719/1102/canário sumido viram Alta; auditoria e log são reparados.</summary>
public class VisibilityGuardTests
{
    private static readonly DateTime T0 = new(2026, 10, 4, 11, 0, 0, DateTimeKind.Utc);

    private static string Xml(string id, string computer, params (string Name, string Value)[] data) =>
        $"""
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><EventID>{id}</EventID><TimeCreated SystemTime="2026-10-04T11:00:00.000Z"/><Computer>{computer}</Computer></System>
          <EventData>{string.Join("", data.Select(d => $"<Data Name=\"{d.Name}\">{d.Value}</Data>"))}</EventData>
        </Event>
        """;

    [Fact]
    public void Event_1102_becomes_security_log_cleared_signal()
    {
        var s = VisibilityEventParser.Parse(Xml("1102", "FS01.corp.local", ("SubjectUserName", "atacante"), ("SubjectDomainName", "CORP")));
        Assert.NotNull(s);
        Assert.Equal(HostSignalKind.SecurityLogCleared, s!.Kind);
        Assert.Equal("FS01", s.Server);
        Assert.Contains(@"CORP\atacante", s.Detail);
    }

    [Fact]
    public void Event_4719_on_file_share_subcategory_is_an_audit_policy_change()
    {
        var s = VisibilityEventParser.Parse(Xml("4719", "FS01", ("SubcategoryName", "Detailed File Share"), ("AuditPolicyChanges", "%%8448"), ("SubjectUserName", "x"), ("SubjectDomainName", "CORP")));
        Assert.Equal(HostSignalKind.AuditPolicyChanged, s!.Kind);
        Assert.Contains("Detailed File Share", s.Detail);
    }

    [Fact]
    public void Event_4719_by_guid_is_recognized_and_unrelated_subcategories_are_ignored()
    {
        Assert.Equal(HostSignalKind.AuditPolicyChanged,
            VisibilityEventParser.Parse(Xml("4719", "FS01", ("SubcategoryGuid", "{0CCE9244-69AE-11D9-BED3-505054503030}")))!.Kind);
        Assert.Null(VisibilityEventParser.Parse(Xml("4719", "FS01", ("SubcategoryName", "Logon"))));
        Assert.Null(VisibilityEventParser.Parse(Xml("4663", "FS01")));
        Assert.Null(VisibilityEventParser.Parse("<broken"));
    }

    [Fact]
    public void Visibility_signals_are_high_confidence_detections_and_repaired_is_not()
    {
        var engine = new DetectionEngine();
        var d = engine.Analyze(Array.Empty<FileEvent>(), new[]
        {
            new HostSignal(T0, HostSignalKind.SecurityLogCleared, "FS01", "x"),
            new HostSignal(T0, HostSignalKind.CanaryMissing, "FS01", "y"),
        });
        var det = Assert.Single(d);
        Assert.Equal(Confidence.High, det.Confidence);
        Assert.Contains(DetectionReason.VisibilityTamper, det.Reasons);

        Assert.Empty(engine.Analyze(Array.Empty<FileEvent>(), new[] { new HostSignal(T0, HostSignalKind.VisibilityRepaired, "FS01", "ok") }));
    }

    /// <summary>
    /// D4 — sem a subcategoria 'File System' o Windows não grava o 4663, e o canário tocado por um processo LOCAL não
    /// aparece. Vem desligada de fábrica: não é adulteração (sem sinal de Alta), é só reparo.
    /// </summary>
    [Fact]
    public void Guard_turns_on_file_system_auditing_without_treating_the_default_as_tampering()
    {
        var plan = VisibilityGuard.Evaluate(true, 1024L * 1024 * 1024, autoRepair: true, "FS01", T0, fileSystemAuditEnabled: false);
        Assert.Equal(new[] { RepairAction.EnableFileSystemAudit }, plan.Repairs);
        Assert.Empty(plan.Signals);

        Assert.Empty(VisibilityGuard.Evaluate(true, 1024L * 1024 * 1024, autoRepair: false, "FS01", T0, fileSystemAuditEnabled: false).Repairs);
        Assert.Empty(VisibilityGuard.Evaluate(true, 1024L * 1024 * 1024, autoRepair: true, "FS01", T0, fileSystemAuditEnabled: true).Repairs);
        Assert.Empty(VisibilityGuard.Evaluate(true, 1024L * 1024 * 1024, autoRepair: true, "FS01", T0, fileSystemAuditEnabled: null).Repairs);
        Assert.Equal(HostSignalKind.VisibilityRepaired, VisibilityGuard.Repaired(RepairAction.EnableFileSystemAudit, "FS01", T0).Kind);
    }

    [Fact]
    public void Guard_plans_repairs_only_when_auto_repair_is_on_and_always_signals_disabled_audit()
    {
        var on = VisibilityGuard.Evaluate(detailedFileShareAuditEnabled: false, securityLogMaxBytes: 20L * 1024 * 1024, autoRepair: true, "FS01", T0);
        Assert.Equal(new[] { RepairAction.EnableDetailedFileShareAudit, RepairAction.GrowSecurityLog }, on.Repairs);
        Assert.Equal(HostSignalKind.AuditDisabled, Assert.Single(on.Signals).Kind);

        var off = VisibilityGuard.Evaluate(false, 20L * 1024 * 1024, autoRepair: false, "FS01", T0);
        Assert.Empty(off.Repairs);
        Assert.Single(off.Signals);

        var healthy = VisibilityGuard.Evaluate(true, 1024L * 1024 * 1024, true, "FS01", T0);
        Assert.Empty(healthy.Repairs); Assert.Empty(healthy.Signals);

        var unknown = VisibilityGuard.Evaluate(null, null, true, "FS01", T0);
        Assert.Empty(unknown.Repairs); Assert.Empty(unknown.Signals);   // não sabe = não mexe
    }

    [Fact]
    public void Buffer_delivers_each_signal_once()
    {
        var b = new HostSignalBuffer();
        b.Push(new HostSignal(T0, HostSignalKind.CanaryMissing, "FS01", "a"));
        b.Push(new HostSignal(T0, HostSignalKind.VisibilityRepaired, "FS01", "b"));
        Assert.Equal(2, b.Drain().Count);
        Assert.Empty(b.Drain());
    }
}

public class SecurityLogReaderTests
{
    [Fact]
    public void Reads_max_size_from_wevtutil_output()
    {
        var output = "name: Security\r\nenabled: true\r\ntype: Admin\r\nowningPublisher: \r\nisolation: Custom\r\nchannelAccess: ...\r\nlogging:\r\n  logFileName: %SystemRoot%\\System32\\Winevt\\Logs\\Security.evtx\r\n  retention: false\r\n  autoBackup: false\r\n  maxSize: 20971520\r\n";
        Assert.Equal(20971520L, RansomGuard.Agent.Posture.SecurityLogReader.TryReadMaxBytes(output));
        Assert.Null(RansomGuard.Agent.Posture.SecurityLogReader.TryReadMaxBytes("garbage"));
        Assert.Null(RansomGuard.Agent.Posture.SecurityLogReader.TryReadMaxBytes(null));
    }
}
