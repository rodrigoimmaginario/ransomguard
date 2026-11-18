using System.Text;
using RansomGuard.Core.Audit;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;
using RansomGuard.Core.Siem;
using RansomGuard.Core.Signing;
using DetectionModel = RansomGuard.Core.Detection.Detection;

namespace RansomGuard.Core.Tests;

public class CefExporterTests
{
    private static readonly DateTime T0 = new(2026, 7, 23, 2, 0, 0, DateTimeKind.Utc);

    private static DetectionModel Incident(string share = @"\\FS01\Financeiro") =>
        new("FS01", @"CORP\vendas1", "10.0.9.66", share, Confidence.High,
            new HashSet<DetectionReason> { DetectionReason.CanaryTouched, DetectionReason.VssDeletion },
            120, T0, T0.AddSeconds(30));

    [Fact]
    public void Incident_produces_valid_cef_header_and_fields()
    {
        var cef = CefExporter.Incident(Incident());

        Assert.StartsWith("CEF:0|RansomGuard|RansomGuard|1.0|100|", cef);
        Assert.Contains("dvchost=FS01", cef);
        Assert.Contains("src=10.0.9.66", cef);
        // CEF escapa '\' → '\\' nas extensões: CORP\vendas1 vira CORP\\vendas1.
        Assert.Contains(@"suser=CORP\\vendas1", cef);
        Assert.Contains("|9|", cef); // severidade High
    }

    [Fact]
    public void Extension_escapes_equals_and_backslash()
    {
        // Extensão CEF escapa '\' → '\\' e '=' → '\='. Share \\FS01\od=d vira \\\\FS01\\od\=d.
        var cef = CefExporter.Incident(Incident(share: @"\\FS01\od=d"));
        Assert.Contains(@"fname=\\\\FS01\\od\=d", cef);
    }

    [Fact]
    public void Response_action_exports_act_and_target()
    {
        var action = new Core.Response.ResponseAction(ResponseStep.DisableAdAccount, "FS01", @"CORP\vendas1", "incidente");
        var entry = new AuditEntry(T0, "RansomGuard", "execute", action, "contenção automática");
        var cef = CefExporter.ResponseAction(entry);

        Assert.Contains("act=DisableAdAccount", cef);
        Assert.Contains(@"dst=CORP\\vendas1", cef);
    }

    [Fact]
    public void Cef_is_single_line()
    {
        var cef = CefExporter.Incident(Incident());
        Assert.DoesNotContain('\n', cef);
        Assert.DoesNotContain('\r', cef);
    }
}

public class IncidentReportTests
{
    private static readonly byte[] Seed = Enumerable.Range(70, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] KeyId = { 5, 5, 6, 6, 7, 7, 8, 8 };
    private static readonly DateTime T0 = new(2026, 7, 23, 2, 0, 0, DateTimeKind.Utc);

    private static MinisignPublicKey Pub() => MinisignPublicKey.FromRaw(KeyId, Minisign.PublicKeyFromSeed(Seed));

    private static (IncidentReport report, List<AuditEntry> audit) Sample()
    {
        var d = new DetectionModel("FS01", @"CORP\v", "10.0.9.66", @"\\FS01\Fin", Confidence.High,
            new HashSet<DetectionReason> { DetectionReason.CanaryTouched }, 120, T0, T0.AddSeconds(30));
        var audit = new List<AuditEntry>
        {
            new(T0, "RansomGuard", "execute",
                new Core.Response.ResponseAction(ResponseStep.KillSmbSession, "FS01", "10.0.9.66", "x"), "auto")
        };
        return (IncidentReport.From(d, audit), audit);
    }

    [Fact]
    public void Signed_report_verifies()
    {
        var (report, _) = Sample();
        var (json, sig) = report.Sign(Seed, KeyId);

        Assert.Equal(MinisignVerificationResult.Valid, IncidentReport.Verify(json, sig, Pub()));
        Assert.Contains("FS01", json);
        Assert.Contains("KillSmbSession", json);
    }

    [Fact]
    public void One_byte_change_invalidates_report()
    {
        var (report, _) = Sample();
        var (json, sig) = report.Sign(Seed, KeyId);

        var tampered = json.Replace("10.0.9.66", "10.0.9.99");
        Assert.Equal(MinisignVerificationResult.InvalidSignature,
            IncidentReport.Verify(tampered, sig, Pub()));
    }

    [Fact]
    public void Canonical_json_is_deterministic()
    {
        var (r1, _) = Sample();
        var (r2, _) = Sample();
        Assert.Equal(r1.ToCanonicalJson(), r2.ToCanonicalJson());
    }
}
