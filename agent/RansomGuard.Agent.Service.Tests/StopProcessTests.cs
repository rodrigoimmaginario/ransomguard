using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging.Abstractions;
using RansomGuard.Agent.Service.Windows;
using RansomGuard.Core.Response;

namespace RansomGuard.Agent.Service.Tests;

/// <summary>
/// E5 — encerrar o processo local que está cifrando. O evento real (4663) identifica o processo por PID e por um
/// caminho de DISPOSITIVO (<c>\Device\HarddiskVolume4\...\x.exe</c>); comparar isso com <c>C:\...</c> nunca batia, e o
/// degrau falhava sempre. Aqui o executor de produção age sobre um processo de verdade.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class StopProcessTests : IDisposable
{
    private readonly WindowsResponseExecutor _executor = new(NullLogger<WindowsResponseExecutor>.Instance);
    private readonly Process _victim;

    public StopProcessTests()
    {
        // Um processo inofensivo e duradouro: ping contra o loopback.
        _victim = Process.Start(new ProcessStartInfo("ping.exe", "-n 120 127.0.0.1")
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true
        })!;
    }

    public void Dispose()
    {
        try { if (!_victim.HasExited) _victim.Kill(); } catch (Exception) { }
        _victim.Dispose();
    }

    private ResponseAction Stop(int pid, string? image) =>
        new(ResponseStep.StopProcess, "FS01", pid.ToString(), "teste de integração", Account: image);

    [Fact]
    public async Task Encerra_o_processo_quando_a_imagem_do_evento_vem_como_caminho_de_dispositivo()
    {
        var outcome = await _executor.ExecuteAsync(Stop(_victim.Id, @"\Device\HarddiskVolume4\Windows\System32\PING.EXE"));

        Assert.Equal(ResponseStatus.Executed, outcome.Status);
        Assert.True(_victim.WaitForExit(5_000), "o processo deveria ter sido encerrado");
    }

    [Fact]
    public async Task Encerra_tambem_com_caminho_comum_e_sem_distinguir_caixa()
    {
        var outcome = await _executor.ExecuteAsync(Stop(_victim.Id, @"c:\windows\system32\ping.exe"));

        Assert.Equal(ResponseStatus.Executed, outcome.Status);
        Assert.True(_victim.WaitForExit(5_000));
    }

    /// <summary>PID reciclado: entre o evento e a resposta, o número passou a ser de outro programa. Não se encerra.</summary>
    [Fact]
    public async Task Nao_encerra_quando_o_pid_hoje_e_de_outro_programa()
    {
        var outcome = await _executor.ExecuteAsync(Stop(_victim.Id, @"\Device\HarddiskVolume4\Users\x\AppData\Local\Temp\enc.exe"));

        Assert.Equal(ResponseStatus.Failed, outcome.Status);
        Assert.Contains("reciclado", outcome.Detail);
        Assert.False(_victim.HasExited);
    }

    [Fact]
    public async Task Sem_imagem_no_evento_nao_ha_como_conferir_e_nao_se_encerra()
    {
        var outcome = await _executor.ExecuteAsync(Stop(_victim.Id, null));

        Assert.Equal(ResponseStatus.Failed, outcome.Status);
        Assert.False(_victim.HasExited);
    }

    [Fact]
    public async Task Processo_que_ja_terminou_e_falha_declarada_e_nao_sucesso()
    {
        var pid = _victim.Id;
        _victim.Kill();
        _victim.WaitForExit(5_000);

        var outcome = await _executor.ExecuteAsync(Stop(pid, @"C:\Windows\System32\PING.EXE"));

        Assert.NotEqual(ResponseStatus.Executed, outcome.Status);
    }

    [Fact]
    public async Task O_proprio_agente_nunca_e_alvo()
    {
        using var self = Process.GetCurrentProcess();

        var outcome = await _executor.ExecuteAsync(Stop(self.Id, self.MainModule?.FileName));

        Assert.Equal(ResponseStatus.Skipped, outcome.Status);
    }
}
