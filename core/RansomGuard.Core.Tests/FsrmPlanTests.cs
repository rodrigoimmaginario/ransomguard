using RansomGuard.Core.Fsrm;

namespace RansomGuard.Core.Tests;

public class FsrmPlanTests
{
    private static RansomwareCatalog Sample() => new()
    {
        Version = 7,
        Patterns = new[] { "*.locked", "*.crypted", "HOW_TO_DECRYPT*" }
    };

    [Fact]
    public void Catalog_round_trips_through_json()
    {
        var json = Sample().ToJson();
        var back = RansomwareCatalog.FromJson(json);

        Assert.Equal(7, back.Version);
        Assert.Contains("*.locked", back.Patterns);
        Assert.Equal(3, back.Patterns.Count);
    }

    [Fact]
    public void Plan_creates_file_group_with_all_patterns()
    {
        var ps = FsrmPlan.BuildPowerShell(Sample(), new[] { @"D:\Shares\Financeiro" });

        Assert.Contains(FsrmPlan.FileGroupName, ps);
        Assert.Contains("'*.locked'", ps);
        Assert.Contains("'*.crypted'", ps);
        Assert.Contains("'HOW_TO_DECRYPT*'", ps);
        Assert.Contains("New-FsrmFileScreen", ps);
        Assert.Contains(@"D:\Shares\Financeiro", ps);
    }

    [Fact]
    public void Plan_is_idempotent_updates_when_group_exists()
    {
        var ps = FsrmPlan.BuildPowerShell(Sample(), new[] { @"D:\Shares\X" });

        Assert.Contains("Get-FsrmFileGroup", ps);
        Assert.Contains("Set-FsrmFileGroup", ps);
        Assert.Contains("New-FsrmFileGroup", ps);
    }

    [Fact]
    public void Passive_mode_produces_inactive_screen()
    {
        var ps = FsrmPlan.BuildPowerShell(Sample(), new[] { @"D:\Shares\X" }, active: false);

        Assert.Contains("-Active:$false", ps);
        Assert.DoesNotContain("-Active:$true", ps);
    }

    // ── D3 / E3: o file screen precisa gerar sinal, respeitar o que já existe e poder ser desfeito ───────────────────

    /// <summary>Sem notificação, um file screen em auditoria não avisa ninguém: era decorativo.</summary>
    [Fact]
    public void Screen_carries_an_event_notification_the_agent_can_read()
    {
        var ps = FsrmPlan.BuildPowerShell(Sample(), new[] { @"D:\Shares\X" }, active: false);

        Assert.Contains("New-FsrmAction -Type Event", ps);
        Assert.Contains(FsrmPlan.EventMarker, ps);
        Assert.Contains("[Source Io Owner]", ps);
        Assert.Contains("[Source File Path]", ps);
        Assert.Contains("-Notification $notify", ps);
    }

    /// <summary>A pasta pode já ter um file screen do cliente. O produto não troca os grupos nem o modo dele.</summary>
    [Fact]
    public void A_screen_the_product_did_not_create_is_left_untouched_and_reported()
    {
        var ps = FsrmPlan.BuildPowerShell(Sample(), new[] { @"D:\Shares\X" });

        Assert.Contains($"-Description '{FsrmPlan.ScreenDescription}'", ps);          // marca o que é nosso
        Assert.Contains(FsrmPlan.ForeignScreenMarker, ps);                            // relata o que não é
        var foreign = ps.IndexOf(FsrmPlan.ForeignScreenMarker, StringComparison.Ordinal);
        var set = ps.IndexOf("Set-FsrmFileScreen", StringComparison.Ordinal);
        Assert.True(foreign >= 0 && foreign < set, "a checagem de file screen alheio vem antes de qualquer alteração");
    }

    [Fact]
    public void Foreign_screens_reported_by_the_script_are_parsed()
    {
        var output = $"algum ruído\r\n{FsrmPlan.ForeignScreenMarker}|D:\\Shares\\Legado\r\n{FsrmPlan.ForeignScreenMarker}|E:\\Dados\r\n";

        Assert.Equal(new[] { @"D:\Shares\Legado", @"E:\Dados" }, FsrmPlan.ForeignScreens(output));
        Assert.Empty(FsrmPlan.ForeignScreens(""));
    }

    [Fact]
    public void Script_fails_loudly_instead_of_continuing_after_an_error()
        => Assert.Contains("$ErrorActionPreference = 'Stop'", FsrmPlan.BuildPowerShell(Sample(), new[] { @"D:\Shares\X" }));

    /// <summary>Reverter remove o que o produto criou — e só isso.</summary>
    [Fact]
    public void Removal_deletes_only_the_product_screens_and_then_the_group()
    {
        var ps = FsrmPlan.BuildRemovalPowerShell();

        Assert.Contains("Remove-FsrmFileScreen", ps);
        Assert.Contains($"$_.Description -eq '{FsrmPlan.ScreenDescription}'", ps);
        Assert.Contains("Remove-FsrmFileGroup", ps);
        Assert.Contains(FsrmPlan.FileGroupName, ps);
        Assert.True(ps.IndexOf("Remove-FsrmFileScreen", StringComparison.Ordinal) < ps.IndexOf("Remove-FsrmFileGroup", StringComparison.Ordinal));
    }

    [Fact]
    public void Empty_catalog_is_rejected()
    {
        var empty = new RansomwareCatalog { Patterns = Array.Empty<string>() };
        Assert.Throws<ArgumentException>(() =>
            FsrmPlan.BuildPowerShell(empty, new[] { @"D:\X" }));
    }

    [Fact]
    public void No_paths_is_rejected()
    {
        Assert.Throws<ArgumentException>(() =>
            FsrmPlan.BuildPowerShell(Sample(), Array.Empty<string>()));
    }
}

public class CanaryPlanTests
{
    [Fact]
    public void Generates_canaries_at_both_ends_of_the_directory()
    {
        var names = CanaryPlan.NamesFor(@"\\FS01\Financeiro");

        Assert.Contains(names, n => n.StartsWith("!0_"));    // G1: primeiro na ordenação NTFS
        Assert.Contains(names, n => n.StartsWith("_aaa"));
        Assert.Contains(names, n => n.StartsWith("~zz_"));    // último printável ASCII
        Assert.All(names, n => Assert.True(CanaryPlan.IsCanary(n)));
    }

    [Fact]
    public void Recognizes_a_planted_canary_path()
    {
        Assert.True(CanaryPlan.IsCanary(@"\\FS01\Financeiro\_aaa_ransomguard_canary.docx"));
        Assert.False(CanaryPlan.IsCanary(@"\\FS01\Financeiro\relatorio.xlsx"));
    }
}
