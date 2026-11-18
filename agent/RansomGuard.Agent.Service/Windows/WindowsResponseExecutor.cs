using RansomGuard.Core.Response;

namespace RansomGuard.Agent.Service.Windows;

/// <summary>
/// Efetor real da escada de contenção no Windows. É o único ponto que causa efeito colateral real — por isso vem
/// depois de toda a decisão/guard-rail do Core.
///
/// A2: "executada" quer dizer que o efeito foi CONFERIDO. Cada passo roda um script que age e depois pergunta ao
/// Windows se a regra, a negação ou o fechamento estão lá; se não estão, o passo é registrado como falha.
/// Bloqueio de IP, sessões, negação no share e encerramento de processo são exercitados em Windows real na CI;
/// snapshot, conta no AD e isolamento do share dependem do laboratório.
///
/// Reversível: RevertAsync desfaz (libera o IP, retira a negação, reabilita a conta) para a remediação pelo admin.
/// </summary>
public sealed class WindowsResponseExecutor(ILogger<WindowsResponseExecutor> log) : IResponseExecutor
{
    // G4a: um snapshot preventivo por share a cada 10 min — rajada de detecções não enche o volume.
    // D7: e no máximo 6 por dia por share, 12 por dia no servidor — ruído sustentado não expulsa os pontos de
    // restauração que o cliente já tinha.
    private readonly SnapshotThrottle _snapshots = new(TimeSpan.FromMinutes(10), maxPerShareDaily: 6, maxPerServerDaily: 12);

    public Task<ResponseOutcome> ExecuteAsync(ResponseAction action, CancellationToken ct = default)
    {
        // R3 (defesa em profundidade): o runner já recusa alvo inseguro, mas o executor não confia
        // — revalida antes de compor qualquer comando com metadado de evento.
        if (!ResponseTarget.IsSafe(action))
        {
            log.LogWarning("Contenção recusada: alvo com forma insegura para {Step}", action.Step);
            return Task.FromResult(ResponseOutcome.Skip("alvo com forma insegura"));
        }

        if (action.Step == ResponseStep.PreemptiveSnapshot && !_snapshots.ShouldSnapshot(action.Target, DateTime.UtcNow))
            return Task.FromResult(ResponseOutcome.Skip(_snapshots.LastRefusal));

        // G4b/E5: processo local é encerrado em processo (sem PowerShell), depois de conferir que o PID ainda é do
        // mesmo programa que o evento apontou.
        if (action.Step == ResponseStep.StopProcess)
            return Task.FromResult(StopProcess(action));

        // A2: cada script age e confere o próprio efeito (ContainmentScripts); roda em modo estrito.
        return RunGuarded(action, ContainmentScripts.Execute(action), "executar");
    }

    public Task<ResponseOutcome> RevertAsync(ResponseAction action, CancellationToken ct = default)
    {
        if (!ResponseTarget.IsSafe(action))
        {
            log.LogWarning("Reversão recusada: alvo com forma insegura para {Step}", action.Step);
            return Task.FromResult(ResponseOutcome.Skip("alvo com forma insegura"));
        }

        // Derrubar sessão, snapshot e processo encerrado não se "desfazem": para eles não há script.
        return RunGuarded(action, ContainmentScripts.Revert(action), "reverter");
    }

    private Task<ResponseOutcome> RunGuarded(ResponseAction action, string? script, string verb)
    {
        // Passo sem comando (ex.: reverter KillSmbSession) não é falha — é no-op legítimo.
        if (script is null) return Task.FromResult(ResponseOutcome.Skip("sem operação para este passo"));
        try
        {
            PowerShellRunner.RunStrict(script);
            log.LogWarning("Contenção ({Verb}) {Step} → {Target} em {Server}", verb, action.Step, action.Target, action.Server);
            return Task.FromResult(ResponseOutcome.Done($"{verb} {action.Step}"));
        }
        catch (Exception ex)
        {
            // R4: falha é falha — nunca mascarada como sucesso. A auditoria registra o desfecho real.
            log.LogError(ex, "Falha ao {Verb} {Step} → {Target}", verb, action.Step, action.Target);
            return Task.FromResult(ResponseOutcome.Fail($"{verb} {action.Step}: {ex.Message}"));
        }
    }

    /// <summary>
    /// Encerra o processo local identificado pelo evento. Três recusas antes de agir:
    /// <list type="bullet">
    ///   <item>o processo não existe mais → falha declarada (nada foi contido);</item>
    ///   <item>o PID hoje pertence a outro programa (reciclado) ou o evento não trouxe a imagem → não encerra;</item>
    ///   <item>o programa está na lista de protegidos (sistema, segurança, backup nativo) → não encerra.</item>
    /// </list>
    /// A conferência é pelo NOME da imagem: o 4663 real traz o caminho de dispositivo
    /// (<c>\Device\HarddiskVolume4\...\x.exe</c>), que não é comparável ao caminho <c>C:\...</c> do processo vivo.
    /// </summary>
    private ResponseOutcome StopProcess(ResponseAction action)
    {
        var pid = int.Parse(action.Target, System.Globalization.CultureInfo.InvariantCulture);   // forma já validada por ResponseTarget
        var expected = ImageName(action.Account);
        if (expected.Length == 0)
            return Fail(action, "o evento não trouxe a imagem do processo; sem ela não há como conferir o PID");

        System.Diagnostics.Process process;
        try { process = System.Diagnostics.Process.GetProcessById(pid); }
        catch (ArgumentException) { return Fail(action, $"o processo {pid} não existe mais"); }

        using (process)
        {
            try
            {
                if (process.HasExited) return Fail(action, $"o processo {pid} já terminou");
                var actual = process.ProcessName;   // sem extensão; disponível mesmo quando o caminho completo não é
                if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
                    return Fail(action, $"PID reciclado: o evento apontou {expected}, hoje o {pid} é {actual}");
                if (ResponseTarget.IsProtectedProcess(actual + ".exe") || ResponseTarget.IsProtectedProcess(actual))
                    return Fail(action, $"processo protegido: {actual}");

                process.Kill();
                process.WaitForExit(5_000);
                log.LogWarning("Contenção (executar) StopProcess → {Pid} ({Image}) em {Server}", pid, actual, action.Server);
                return ResponseOutcome.Done($"executar StopProcess: {actual} ({pid})");
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
            {
                return Fail(action, $"não foi possível encerrar o processo {pid}: {ex.Message}");
            }
        }
    }

    private ResponseOutcome Fail(ResponseAction action, string detail)
    {
        log.LogError("Falha ao executar {Step} → {Target}: {Detail}", action.Step, action.Target, detail);
        return ResponseOutcome.Fail($"executar {action.Step}: {detail}");
    }

    /// <summary>Nome da imagem sem pasta e sem extensão, de um caminho comum ou de dispositivo.</summary>
    private static string ImageName(string? image)
    {
        var name = (image ?? "").Trim().Replace('/', '\\');
        var slash = name.LastIndexOf('\\');
        if (slash >= 0) name = name[(slash + 1)..];
        return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
    }
}
