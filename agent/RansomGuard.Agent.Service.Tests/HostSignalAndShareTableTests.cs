using System.Runtime.Versioning;
using Microsoft.Extensions.Logging.Abstractions;
using RansomGuard.Agent.Service.Windows;
using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Service.Tests;

/// <summary>D5 — a contagem de cópias de sombra tem ritmo próprio; o ciclo de 1–5 s não a dispara toda vez.</summary>
[SupportedOSPlatform("windows")]
public sealed class HostSignalCadenceTests
{
    [Fact]
    public void Copias_de_sombra_sao_contadas_uma_vez_por_intervalo_e_nao_a_cada_ciclo()
    {
        var now = new DateTime(2026, 11, 16, 12, 0, 0, DateTimeKind.Utc);
        var consultas = 0;
        var coletor = new WindowsHostSignalCollector(NullLogger<WindowsHostSignalCollector>.Instance, "FS01",
            countShadowCopies: () => { consultas++; return 3; }, clock: () => now);

        for (var ciclo = 0; ciclo < 12; ciclo++)      // um minuto de ciclos de 5 s
        {
            coletor.Drain();
            now = now.AddSeconds(5);
        }

        Assert.Equal(2, consultas);                   // t=0 e t=30 s
    }

    [Fact]
    public void Queda_na_contagem_continua_virando_sinal_de_alta_confianca()
    {
        var now = new DateTime(2026, 11, 16, 12, 0, 0, DateTimeKind.Utc);
        var contagem = 3;
        var coletor = new WindowsHostSignalCollector(NullLogger<WindowsHostSignalCollector>.Instance, "FS01",
            countShadowCopies: () => contagem, clock: () => now);

        Assert.Empty(coletor.Drain());                // linha de base
        contagem = 0;
        now += WindowsHostSignalCollector.VssInterval;

        var sinal = Assert.Single(coletor.Drain());
        Assert.Equal(HostSignalKind.VssDeleted, sinal.Kind);
        Assert.Equal("FS01", sinal.Server);
    }

    [Fact]
    public void Falha_na_contagem_nao_inventa_sinal()
    {
        var coletor = new WindowsHostSignalCollector(NullLogger<WindowsHostSignalCollector>.Instance, "FS01",
            countShadowCopies: () => throw new UnauthorizedAccessException());

        Assert.Empty(coletor.Drain());
    }
}

/// <summary>D1 — a tabela de shares vem do registro, sem processo auxiliar e sem depender do idioma.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsShareTableTests
{
    [Fact]
    public void Leitura_do_registro_nao_exige_elevacao_nem_lanca()
    {
        var shares = WindowsShareTable.ReadRegistry();

        Assert.NotNull(shares);
        Assert.All(shares, s => { Assert.NotEmpty(s.Name); Assert.NotEmpty(s.LocalPath); });
    }

    [Fact]
    public void Tabela_fica_em_cache_ate_o_intervalo_vencer()
    {
        var now = DateTime.UtcNow;
        var tabela = new WindowsShareTable("FS01", TimeSpan.FromSeconds(60), () => now);

        var primeira = tabela.Current();
        now = now.AddSeconds(30);
        Assert.Same(primeira, tabela.Current());

        now = now.AddSeconds(31);
        Assert.NotSame(primeira, tabela.Current());
        Assert.Equal("FS01", tabela.Current().Server);
    }
}
