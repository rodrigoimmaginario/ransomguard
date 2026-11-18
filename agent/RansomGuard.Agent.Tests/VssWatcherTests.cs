using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// Apagar as cópias de sombra é passo quase universal do playbook de ransomware — vem antes do
/// pedido de resgate, para tirar a saída fácil da vítima. O <c>DetectionEngine</c> trata isso como
/// alta confiança, então um falso positivo aqui derruba sessão de gente inocente.
/// </summary>
public class VssWatcherTests
{
    private static readonly DateTime T0 = new(2026, 7, 26, 3, 14, 0, DateTimeKind.Utc);

    [Fact]
    public void Primeira_leitura_so_estabelece_a_linha_de_base()
        => Assert.Null(new VssWatcher("FS01").Observe(12, T0));

    [Fact]
    public void Queda_na_contagem_vira_sinal_de_alta_confianca()
    {
        var w = new VssWatcher("FS01");
        w.Observe(12, T0);

        var s = w.Observe(0, T0.AddMinutes(1))!;

        Assert.Equal(HostSignalKind.VssDeleted, s.Kind);
        Assert.Equal("FS01", s.Server);
        Assert.Contains("12", s.Detail);   // o admin precisa saber quantas sumiram
    }

    [Fact]
    public void Contagem_estavel_nao_gera_sinal()
    {
        var w = new VssWatcher("FS01");
        w.Observe(12, T0);
        Assert.Null(w.Observe(12, T0.AddMinutes(1)));
    }

    /// <summary>Backup criando cópias novas é o caminho feliz — jamais pode alarmar.</summary>
    [Fact]
    public void Aumento_na_contagem_nao_gera_sinal()
    {
        var w = new VssWatcher("FS01");
        w.Observe(12, T0);
        Assert.Null(w.Observe(15, T0.AddMinutes(1)));
    }

    /// <summary>
    /// Leitura falha (WMI indisponível, sem permissão) **não** pode virar "apagaram seu VSS".
    /// Alarme falso às três da manhã custa a confiança do admin — e confiança perdida não volta.
    /// </summary>
    [Fact]
    public void Leitura_falha_nao_inventa_sinal()
    {
        var w = new VssWatcher("FS01");
        w.Observe(12, T0);

        Assert.Null(w.Observe(null, T0.AddMinutes(1)));
    }

    /// <summary>E a falha não pode apagar a linha de base, senão a queda seguinte passa batida.</summary>
    [Fact]
    public void Falha_de_leitura_preserva_a_linha_de_base()
    {
        var w = new VssWatcher("FS01");
        w.Observe(12, T0);
        w.Observe(null, T0.AddMinutes(1));

        var s = w.Observe(2, T0.AddMinutes(2));

        Assert.NotNull(s);
        Assert.Contains("12", s!.Detail);
    }

    [Fact]
    public void Queda_parcial_tambem_conta()
    {
        var w = new VssWatcher("FS01");
        w.Observe(10, T0);

        var s = w.Observe(7, T0.AddMinutes(1))!;

        Assert.Contains("3", s.Detail);
    }

    [Fact]
    public void Nova_queda_apos_um_sinal_gera_outro_sinal()
    {
        var w = new VssWatcher("FS01");
        w.Observe(10, T0);
        w.Observe(5, T0.AddMinutes(1));

        Assert.NotNull(w.Observe(1, T0.AddMinutes(2)));
    }

    [Fact]
    public void Rebaseline_aceita_queda_legitima_sem_alarmar()
    {
        var w = new VssWatcher("FS01");
        w.Observe(10, T0);

        w.Rebaseline(3);                     // rotação agendada, conhecida pelo admin

        Assert.Null(w.Observe(3, T0.AddMinutes(1)));
    }
}

/// <summary>
/// Coletor que falha em silêncio é pior que coletor ausente: o painel mostra "tudo calmo" enquanto
/// o agente está cego. Cegar o sensor é justamente o que um EDR killer faria antes de agir.
/// </summary>
public class SensorHealthTests
{
    private static readonly DateTime T0 = new(2026, 7, 26, 3, 14, 0, DateTimeKind.Utc);

    [Fact]
    public void Sem_falhas_nao_ha_sinal()
        => Assert.Null(SensorHealth.Evaluate(0, "FS01", T0));

    /// <summary>Falha isolada é ruído (log ocupado, timeout) — não vale acordar ninguém.</summary>
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void Falha_isolada_nao_gera_sinal(int falhas)
        => Assert.Null(SensorHealth.Evaluate(falhas, "FS01", T0));

    [Fact]
    public void Falhas_seguidas_viram_sinal_de_tamper()
    {
        var s = SensorHealth.Evaluate(SensorHealth.FailureThreshold, "FS01", T0)!;

        Assert.Equal(HostSignalKind.AgentTamper, s.Kind);
        Assert.Contains("cego", s.Detail);
    }

    [Fact]
    public void Continua_sinalizando_enquanto_o_problema_persiste()
        => Assert.NotNull(SensorHealth.Evaluate(50, "FS01", T0));
}
