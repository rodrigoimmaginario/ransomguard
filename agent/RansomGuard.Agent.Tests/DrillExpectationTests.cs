using RansomGuard.Agent.Drill;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// O relatório do que esperar é o que separa "vi o produto pegar o ataque" de "vi arquivos mudando
/// e não sei o que era para acontecer". Precisa dizer, sem ambiguidade, o que conferir no painel.
/// </summary>
public class DrillExpectationTests
{
    private static DrillAction A(string kind, string target = "x.docx", string? novo = null)
        => new(kind, target, novo);

    [Fact]
    public void Canario_e_a_primeira_expectativa_por_ser_o_sinal_mais_forte()
    {
        var linhas = DrillExpectation.ForPlan(new[]
        {
            A("reescrita", "a.docx", "a.docx.locked"),
            A("canário", "_aaa_ransomguard_canary.docx")
        });

        Assert.Contains("ALTA confiança", linhas[0]);
        Assert.Contains("canário", linhas[0]);
    }

    [Fact]
    public void Descreve_reescrita_com_a_extensao_certa()
    {
        var linhas = DrillExpectation.ForPlan(new[] { A("reescrita", "a.docx", "a.docx.locked") });

        Assert.Contains(linhas, l => l.Contains(".locked"));
    }

    [Fact]
    public void Descreve_o_bilhete_de_resgate()
    {
        var linhas = DrillExpectation.ForPlan(new[] { A("bilhete de resgate", AttackDrill.RansomNoteName) });

        Assert.Contains(linhas, l => l.Contains(AttackDrill.RansomNoteName));
    }

    /// <summary>
    /// A honestidade que evita o falso "bug": neste ensaio a origem é loopback, então o operador
    /// não deve estranhar que o painel não mostre um IP remoto.
    /// </summary>
    [Fact]
    public void Avisa_que_a_origem_local_e_esperada()
    {
        var linhas = DrillExpectation.ForPlan(new[] { A("reescrita", "a.docx", "a.docx.locked") });

        Assert.Contains(linhas, l => l.Contains("LOCAL") && l.Contains("::1"));
    }

    [Fact]
    public void Plano_vazio_diz_que_nao_ha_o_que_detectar()
    {
        var linhas = DrillExpectation.ForPlan(Array.Empty<DrillAction>());

        Assert.Single(linhas);
        Assert.Contains("vazio", linhas[0]);
    }

    [Fact]
    public void Conta_corretamente_as_acoes()
    {
        var plan = new[]
        {
            A("canário", "c1"), A("canário", "c2"),
            A("reescrita", "a.docx", "a.docx.locked"),
        };

        var linhas = DrillExpectation.ForPlan(plan);

        Assert.Contains("2 canário", linhas[0]);
        Assert.Contains(linhas, l => l.Contains("1 arquivo"));
    }
}
