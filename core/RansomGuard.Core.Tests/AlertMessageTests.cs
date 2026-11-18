using RansomGuard.Core.Detection;
using RansomGuard.Core.Notifications;
using DetectionModel = RansomGuard.Core.Detection.Detection;

namespace RansomGuard.Core.Tests;

public class AlertComposerTests
{
    private static readonly DateTime T0 = new(2026, 7, 26, 14, 30, 0, DateTimeKind.Utc);

    private static DetectionModel Incident(
        Confidence confidence = Confidence.High,
        params DetectionReason[] reasons) =>
        new("FS01", @"CORP\vendas1", "10.0.9.66", @"\\FS01\Financeiro", confidence,
            new HashSet<DetectionReason>(reasons.Length > 0 ? reasons
                : new[] { DetectionReason.CanaryTouched, DetectionReason.VssDeletion }),
            120, T0, T0.AddSeconds(30));

    [Fact]
    public void Detection_alert_answers_the_five_questions()
    {
        var m = AlertComposer.ForDetection(Incident(), "sessão + IP + conta");

        // Onde, quem, de onde, quanto — tudo no corpo curto (o que chega no push).
        Assert.Contains("FS01", m.Title);
        Assert.Contains(@"CORP\vendas1", m.ShortBody);
        Assert.Contains("10.0.9.66", m.ShortBody);
        Assert.Contains("120 arquivos", m.ShortBody);
        Assert.Contains(@"\\FS01\Financeiro", m.ShortBody);
        // E o mais importante: o que já foi feito.
        Assert.Contains("CONTIDO", m.ShortBody);
    }

    [Fact]
    public void Without_containment_says_only_alerted()
    {
        var m = AlertComposer.ForDetection(Incident());
        Assert.Contains("Somente alertado", m.ShortBody);
        Assert.DoesNotContain("CONTIDO", m.ShortBody);
    }

    [Fact]
    public void High_confidence_is_critical_medium_is_warning()
    {
        Assert.Equal(AlertSeverity.Critical, AlertComposer.ForDetection(Incident(Confidence.High)).Severity);
        Assert.Equal(AlertSeverity.Warning, AlertComposer.ForDetection(Incident(Confidence.Medium)).Severity);
    }

    [Fact]
    public void Reasons_are_humanized_not_enum_names()
    {
        var m = AlertComposer.ForDetection(Incident(Confidence.High,
            DetectionReason.CanaryTouched, DetectionReason.VssDeletion));

        Assert.Contains("canário tocado", m.ShortBody);
        Assert.Contains("VSS apagado", m.ShortBody);
        Assert.DoesNotContain("CanaryTouched", m.ShortBody);
        Assert.DoesNotContain("VssDeletion", m.ShortBody);
    }

    [Theory]
    [InlineData(DetectionReason.MassRewrite, "reescrita em massa")]
    [InlineData(DetectionReason.MassRename, "renomeação em massa")]
    [InlineData(DetectionReason.ExtensionFlip, "troca de extensão")]
    [InlineData(DetectionReason.AgentTamper, "agente adulterado")]
    public void Every_reason_has_plain_language(DetectionReason reason, string expected)
        => Assert.Contains(expected, AlertComposer.ForDetection(Incident(Confidence.High, reason)).ShortBody);

    [Fact]
    public void Rich_body_has_more_detail_than_short()
    {
        var m = AlertComposer.ForDetection(Incident(), "sessão");
        Assert.True(m.RichBody.Length > m.ShortBody.Length);
        Assert.Contains("Janela:", m.RichBody);      // detalhe que não cabe no push
        Assert.Contains("Confiança:", m.RichBody);
    }

    /// <summary>Princípio inegociável do produto: metadado, nunca conteúdo de arquivo.</summary>
    [Fact]
    public void Never_leaks_file_content_or_individual_names()
    {
        var m = AlertComposer.ForDetection(Incident(), "sessão");
        var tudo = m.Title + m.ShortBody + m.RichBody;

        // O modelo de detecção carrega contagem e share — nunca nomes de arquivo individuais.
        Assert.DoesNotContain(".docx", tudo);
        Assert.DoesNotContain(".xlsx", tudo);
        Assert.Contains("120", tudo); // só a contagem
    }

    [Fact]
    public void Dedup_key_groups_same_actor_and_share()
    {
        var a = AlertComposer.ForDetection(Incident());
        var b = AlertComposer.ForDetection(Incident());
        Assert.Equal(a.DedupKey, b.DedupKey);
        Assert.NotNull(a.DedupKey);
    }

    [Fact]
    public void Agent_silent_alert_is_critical_and_explains_the_risk()
    {
        var m = AlertComposer.ForAgentSilent("FS02", T0.AddMinutes(-25), T0);

        Assert.Equal(AlertSeverity.Critical, m.Severity);
        Assert.Contains("FS02", m.Title);
        Assert.Contains("25 min", m.ShortBody);
        Assert.Contains("adultera", m.RichBody);   // explica por que isso importa
        Assert.Equal("silent:FS02", m.DedupKey);
    }

    [Fact]
    public void Test_message_is_info_and_names_the_channel()
    {
        var m = AlertComposer.ForTest("ntfy");
        Assert.Equal(AlertSeverity.Info, m.Severity);
        Assert.Contains("ntfy", m.ShortBody);
        Assert.Null(m.DedupKey);   // teste nunca é agrupado
    }
}

public class NotificationPolicyTests
{
    private static readonly DateTime T0 = new(2026, 7, 26, 14, 0, 0, DateTimeKind.Utc);

    private static AlertMessage Msg(AlertSeverity sev, string? key = "k") =>
        new(sev, "t", "s", "r", Array.Empty<string>()) { DedupKey = key };

    [Fact]
    public void Default_policy_sends_only_critical()
    {
        var p = new NotificationPolicy();
        Assert.Equal(NotificationPolicy.Decision.Send, p.Evaluate(Msg(AlertSeverity.Critical), T0));
        Assert.Equal(NotificationPolicy.Decision.BelowSeverity, p.Evaluate(Msg(AlertSeverity.Warning, "k2"), T0));
        Assert.Equal(NotificationPolicy.Decision.BelowSeverity, p.Evaluate(Msg(AlertSeverity.Info, "k3"), T0));
    }

    [Fact]
    public void Admin_can_opt_into_warnings()
    {
        var p = new NotificationPolicy { MinimumSeverity = AlertSeverity.Warning };
        Assert.Equal(NotificationPolicy.Decision.Send, p.Evaluate(Msg(AlertSeverity.Warning), T0));
        Assert.Equal(NotificationPolicy.Decision.BelowSeverity, p.Evaluate(Msg(AlertSeverity.Info, "k2"), T0));
    }

    [Fact]
    public void Repeat_within_window_is_suppressed()
    {
        var p = new NotificationPolicy { FloodWindow = TimeSpan.FromMinutes(10) };
        Assert.Equal(NotificationPolicy.Decision.Send, p.Evaluate(Msg(AlertSeverity.Critical), T0));
        Assert.Equal(NotificationPolicy.Decision.Flooded, p.Evaluate(Msg(AlertSeverity.Critical), T0.AddMinutes(3)));
    }

    [Fact]
    public void After_the_window_it_sends_again()
    {
        var p = new NotificationPolicy { FloodWindow = TimeSpan.FromMinutes(10) };
        p.Evaluate(Msg(AlertSeverity.Critical), T0);
        Assert.Equal(NotificationPolicy.Decision.Send, p.Evaluate(Msg(AlertSeverity.Critical), T0.AddMinutes(11)));
    }

    [Fact]
    public void Different_actors_are_not_grouped_together()
    {
        var p = new NotificationPolicy();
        Assert.Equal(NotificationPolicy.Decision.Send, p.Evaluate(Msg(AlertSeverity.Critical, "servidor-A"), T0));
        Assert.Equal(NotificationPolicy.Decision.Send, p.Evaluate(Msg(AlertSeverity.Critical, "servidor-B"), T0));
    }

    [Fact]
    public void Messages_without_key_are_never_suppressed()
    {
        var p = new NotificationPolicy();
        Assert.Equal(NotificationPolicy.Decision.Send, p.Evaluate(Msg(AlertSeverity.Critical, null), T0));
        Assert.Equal(NotificationPolicy.Decision.Send, p.Evaluate(Msg(AlertSeverity.Critical, null), T0.AddSeconds(1)));
    }
}
