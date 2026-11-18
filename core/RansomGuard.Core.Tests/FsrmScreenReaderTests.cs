using RansomGuard.Core.Fsrm;

namespace RansomGuard.Core.Tests;

/// <summary>
/// R7 — o Score precisa medir se o **file screen do RansomGuard** está aplicado, não se a *role* do
/// FSRM está instalada. Um servidor com FSRM instalado mas sem o screen aparecia como protegido —
/// nota mentirosa, o mesmo pecado que o resto do Score evita. Este leitor decide pela saída do
/// `Get-FsrmFileScreen`, com tri-estado (desconhecido quando não dá para ler).
/// </summary>
public class FsrmScreenReaderTests
{
    [Fact]
    public void Screen_with_ransomguard_group_is_active()
    {
        // Saída típica do Get-FsrmFileScreen quando o screen do produto está aplicado.
        var output = """
            Path              : D:\Shares\Financeiro
            Active            : True
            IncludeGroup      : {RansomGuard_Ransomware}
            """;
        Assert.True(FsrmScreenReader.TryRead(output));
    }

    [Fact]
    public void Screen_from_another_group_does_not_count()
    {
        var output = """
            Path              : D:\Shares\Financeiro
            Active            : True
            IncludeGroup      : {Blocked Executables}
            """;
        Assert.False(FsrmScreenReader.TryRead(output));
    }

    [Fact]
    public void No_screen_applied_is_false()
    {
        Assert.False(FsrmScreenReader.TryRead(""));   // vazio = nenhum screen
    }

    [Fact]
    public void Error_or_unreadable_output_is_unknown()
    {
        // Comando ausente / sem permissão: não afirmamos nem que tem nem que falta.
        Assert.Null(FsrmScreenReader.TryRead(null));
        Assert.Null(FsrmScreenReader.TryRead("Get-FsrmFileScreen : O termo não é reconhecido"));
    }
}
