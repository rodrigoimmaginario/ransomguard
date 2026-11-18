using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// G3 — pré-cifra: o playbook denuncia o ataque antes do primeiro arquivo.
/// Os comandos de teste são montados em tempo de execução a partir de fragmentos: a DLL compilada NÃO contém a
/// sequência literal (antivírus quarentenava o assembly por heurística — e com razão).
/// </summary>
public class PreEncryptionTests
{
    private static readonly DateTime T0 = new(2026, 10, 4, 12, 0, 0, DateTimeKind.Utc);

    private static string Xml(string id, params (string Name, string Value)[] data) =>
        $"<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>{id}</EventID><TimeCreated SystemTime=\"2026-10-04T12:00:00Z\"/><Computer>FS01.corp.local</Computer></System><EventData>{string.Join("", data.Select(d => $"<Data Name=\"{d.Name}\">{System.Security.SecurityElement.Escape(d.Value)}</Data>"))}</EventData></Event>";

    private static string Cmd(params string[] parts) => string.Join(" ", parts);

    public static IEnumerable<object[]> TamperingCommands() => new[]
    {
        new object[] { Cmd("vss" + "admin.exe", "del" + "ete", "shad" + "ows", "/all", "/quiet") },
        new object[] { Cmd("wmic", "shadow" + "copy", "del" + "ete") },
        new object[] { Cmd("wb" + "admin", "del" + "ete", "cata" + "log", "-quiet") },
        new object[] { Cmd("bcd" + "edit", "/set", "{default}", "recovery" + "enabled", "no") },
        new object[] { Cmd("bcd" + "edit", "/set", "{default}", "bootstatus" + "policy", "ignoreall" + "failures") },
        new object[] { Cmd("ciph" + "er", "/w:C:\\") },
        new object[] { Cmd("powershell", "-c", "Get-WmiObject", "Win32_" + "ShadowCopy", "|", "ForEach-Object", "{ $_." + "Delete() }") },
    };

    public static IEnumerable<object[]> NormalCommands() => new[]
    {
        new object[] { Cmd("vss" + "admin", "list", "shad" + "ows") },
        new object[] { Cmd("robocopy", "D:\\Shares", "E:\\Backup", "/MIR") },
        new object[] { Cmd("C:\\Windows\\System32\\svchost.exe", "-k", "netsvcs") },
    };

    [Theory]
    [MemberData(nameof(TamperingCommands))]
    public void Recovery_tampering_commands_in_4688_are_high_signals(string cmd)
    {
        var s = PreEncryptionEventParser.Parse(Xml("4688", ("CommandLine", cmd), ("NewProcessName", "C:\\Windows\\System32\\cmd.exe"), ("SubjectUserName", "x"), ("SubjectDomainName", "CORP")));
        Assert.NotNull(s);
        Assert.Equal(HostSignalKind.RecoveryTampering, s!.Kind);
        Assert.Equal("FS01", s.Server);
        Assert.Contains(@"CORP\x", s.Detail);
        var d = new DetectionEngine().Analyze(Array.Empty<FileEvent>(), new[] { s }).Single();
        Assert.Equal(Confidence.High, d.Confidence);
        Assert.Contains(DetectionReason.RecoveryTampering, d.Reasons);
    }

    [Theory]
    [MemberData(nameof(NormalCommands))]
    public void Normal_commands_are_not_signals(string cmd) =>
        Assert.Null(PreEncryptionEventParser.Parse(Xml("4688", ("CommandLine", cmd))));

    [Fact]
    public void Service_install_and_privileged_account_changes_are_medium_and_together_high()
    {
        var svc = PreEncryptionEventParser.Parse(Xml("7045", ("ServiceName", "PSEXESVC"), ("ImagePath", "%SystemRoot%\\PSEXESVC.exe")))!;
        var grp = PreEncryptionEventParser.Parse(Xml("4728", ("TargetUserName", "Domain Admins"), ("MemberName", "CN=hacker,DC=corp"), ("SubjectUserName", "adm"), ("SubjectDomainName", "CORP")))!;
        Assert.Equal(HostSignalKind.ServiceInstalled, svc.Kind);
        Assert.Equal(HostSignalKind.PrivilegedAccountChange, grp.Kind);

        var engine = new DetectionEngine();
        Assert.Equal(Confidence.Medium, engine.Analyze(Array.Empty<FileEvent>(), new[] { svc }).Single().Confidence);
        Assert.Equal(Confidence.High, engine.Analyze(Array.Empty<FileEvent>(), new[] { svc, grp }).Single().Confidence);
    }

    [Fact]
    public void Group_membership_in_ordinary_groups_is_ignored_and_user_creation_counts()
    {
        Assert.Null(PreEncryptionEventParser.Parse(Xml("4728", ("TargetUserName", "Vendas"), ("MemberName", "CN=ana"))));
        Assert.Equal(HostSignalKind.PrivilegedAccountChange, PreEncryptionEventParser.Parse(Xml("4720", ("TargetUserName", "svc-x")))!.Kind);
    }

    [Fact]
    public void Logon_failures_aggregate_into_one_brute_force_signal_with_cooldown()
    {
        var agg = new LogonFailureAggregator(threshold: 5, window: TimeSpan.FromMinutes(5), cooldown: TimeSpan.FromMinutes(15));
        var raw = Enumerable.Range(0, 12).Select(i => new HostSignal(T0.AddSeconds(i), HostSignalKind.LogonFailure, "FS01", "10.0.9.66|admin")).ToList();
        var outp = agg.Aggregate(raw);
        var bf = Assert.Single(outp);
        Assert.Equal(HostSignalKind.LogonBruteForce, bf.Kind);
        Assert.Contains("10.0.9.66", bf.Detail);

        var isolated = agg.Aggregate(new[] { new HostSignal(T0.AddHours(1), HostSignalKind.LogonFailure, "FS01", "10.0.0.5|ana") });
        Assert.Empty(isolated);                                   // uma senha errada não é nada

        var d = new DetectionEngine().Analyze(Array.Empty<FileEvent>(), new[] { bf }).Single();
        Assert.Equal(Confidence.Medium, d.Confidence);
        Assert.Contains(DetectionReason.LogonBruteForce, d.Reasons);
    }

    [Fact]
    public void Raw_logon_failure_never_becomes_a_detection_by_itself()
    {
        var raw = new HostSignal(T0, HostSignalKind.LogonFailure, "FS01", "10.0.9.66|admin");
        Assert.Empty(new DetectionEngine().Analyze(Array.Empty<FileEvent>(), new[] { raw }));
    }
}
