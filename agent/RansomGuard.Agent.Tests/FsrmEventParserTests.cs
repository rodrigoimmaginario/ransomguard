using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// E3 — o evento que o file screen do produto grava num FSRM REAL (capturado na CI, Windows Server 2025). É por ele
/// que o agente vê o nome de DESTINO de uma renomeação, coisa que o evento de share (5145) não mostra.
/// </summary>
public class FsrmEventParserTests
{
    private static string Real(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "real", name));

    [Fact]
    public void Arquivo_criado_localmente_traz_usuario_destino_e_processo()
    {
        var p = FsrmEventParser.Parse(Real("8215-fsrm-criado-local.xml"))!;

        Assert.Equal(@"runnervmm7ud1\runneradmin", p.Event.User);
        Assert.Equal(@"C:\rg-it-553d93e9\Financeiro\criado-local.xlsx.rglocked", p.LocalFullPath);
        Assert.Equal(".rglocked", p.Event.NewExtension);
        Assert.Equal(FileOp.Write, p.Event.Op);
        Assert.Equal(SecurityEventParser.LocalOrigin, p.Event.SourceIp);
        Assert.Equal(5692, p.Event.ProcessId);
        Assert.EndsWith("testhost.exe", p.Event.ProcessName);
        Assert.Equal(new DateTime(2026, 11, 16, 15, 2, 41, DateTimeKind.Utc), p.Event.At.AddTicks(-(p.Event.At.Ticks % TimeSpan.TicksPerSecond)));
    }

    /// <summary>Pela rede o FSRM atribui a operação ao sistema (PID 4): não há processo local a encerrar.</summary>
    [Fact]
    public void Renomeacao_pela_rede_traz_o_nome_de_destino_e_nenhum_processo_local()
    {
        var p = FsrmEventParser.Parse(Real("8215-fsrm-renomeado-pela-rede.xml"))!;

        Assert.Equal(@"C:\rg-it-553d93e9\Financeiro\renomeado-rede.dwg.rglocked", p.LocalFullPath);
        Assert.Equal(".rglocked", p.Event.NewExtension);
        Assert.Null(p.Event.ProcessId);
        Assert.Null(p.Event.ProcessName);
        Assert.Equal(@"runnervmm7ud1\runneradmin", p.Event.User);
    }

    [Fact]
    public void Share_canonico_e_caminho_relativo_saem_do_caminho_local()
    {
        var map = new ShareMap("FS01", new[] { new ShareEntry("Financeiro", @"C:\rg-it-553d93e9\Financeiro") });

        var e = map.Canonicalize(FsrmEventParser.Parse(Real("8215-fsrm-renomeado-pela-rede.xml"))!);

        Assert.Equal(@"\\FS01\Financeiro", e.Share);
        Assert.Equal("renomeado-rede.dwg.rglocked", e.Path);
    }

    [Theory]
    [InlineData("")]
    [InlineData("<Event")]
    [InlineData("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>8215</EventID></System><EventData><Data>Outro file screen do cliente, sem a marca do produto</Data></EventData></Event>")]
    [InlineData("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>8215</EventID></System><EventData><Data>RansomGuard-FSRM|user=CORP\\ana</Data></EventData></Event>")]
    public void Evento_que_nao_e_do_file_screen_do_produto_ou_esta_incompleto_e_ignorado(string xml)
        => Assert.Null(FsrmEventParser.Parse(xml));
}
