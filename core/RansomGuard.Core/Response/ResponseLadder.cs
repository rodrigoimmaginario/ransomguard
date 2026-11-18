using RansomGuard.Core.Detection;
using DetectionModel = RansomGuard.Core.Detection.Detection;

namespace RansomGuard.Core.Response;

/// <summary>O que a resposta decidiu fazer diante de um incidente.</summary>
/// <param name="Alert">Se deve alertar (painel/e-mail/SIEM).</param>
/// <param name="Actions">Ações de contenção a executar, em ordem (vazio se não age).</param>
/// <param name="Rationale">Explicação da decisão (auditoria/painel).</param>
public sealed record ResponseDecision(bool Alert, IReadOnlyList<ResponseAction> Actions, string Rationale)
{
    /// <summary>Há contenção real (o snapshot preventivo da G4a não conta: protege, não contém).</summary>
    public bool Contains => Actions.Any(a => a.Step != ResponseStep.PreemptiveSnapshot);
    public static ResponseDecision None(string why) => new(false, Array.Empty<ResponseAction>(), why);
    public static ResponseDecision AlertOnly(string why) => new(true, Array.Empty<ResponseAction>(), why);
}

/// <summary>
/// Decide a resposta a um incidente, aplicando modo e guard-rails — SEM executar nada
/// (a execução é do <see cref="IResponseExecutor"/>). Lógica pura e determinística; é o alvo do
/// FalsePositiveSimulator.
///
/// O produto é gratuito: não existe licença no caminho da decisão. Quem liga a contenção é o
/// administrador, pelo modo e pela política (assinada pelo painel).
///
/// Precedência (a ordem importa):
///  1. Modo Monitor → nunca age nem alerta.
///  2. Guard-rail allowlist: ator allowlisted E sem canário → no máximo alerta (nunca contém).
///  3. Modo Alert OU período de aprendizado → alerta + snapshot preventivo (G4a), sem contenção.
///  4. Modo Block: confiança High → snapshot + escada até MaxStep; Medium → snapshot + alerta.
/// </summary>
public sealed class ResponseLadder
{
    public ResponseDecision Decide(DetectionModel d, ResponsePolicy policy)
    {
        // 1. Monitor: registra e cala.
        if (policy.Mode == ResponseMode.Monitor)
            return ResponseDecision.None("Modo monitor — apenas registro.");

        var canaryTripped = d.Reasons.Contains(DetectionReason.CanaryTouched);
        var allowlisted = policy.AllowlistedUsers.Contains(d.User)
                          || policy.AllowlistedIps.Contains(d.SourceIp);

        // 3. Guard-rail: ator legítimo (allowlist) sem tocar canário → nunca contém.
        if (allowlisted && !canaryTripped)
            return ResponseDecision.AlertOnly(
                $"Ator na allowlist ({d.User}/{d.SourceIp}) sem canário — contenção suprimida (guard-rail).");

        // G4a: a partir daqui há sinal real de um ator não allowlisted — snapshot preventivo do volume do
        // share ANTES de qualquer coisa. Não contém, não afeta ninguém, garante o restore. Só a escada conta.
        var snapshot = new ResponseAction(ResponseStep.PreemptiveSnapshot, d.Server, d.Share,
            $"Snapshot preventivo ({d.Confidence}, {string.Join("+", d.Reasons)})");

        // 4. Alerta puro, ou período de aprendizado (observa, não contém mesmo em Block).
        if (policy.Mode == ResponseMode.Alert)
            return new ResponseDecision(true, new[] { snapshot }, "Modo alerta — snapshot preventivo; sem contenção automática.");
        if (policy.LearningMode)
            return new ResponseDecision(true, new[] { snapshot }, "Modo aprendizado — snapshot preventivo; contenção suprimida enquanto coleta baseline.");

        // 5. Block: só High autoriza contenção; Medium alerta (com snapshot) e aguarda confirmação.
        if (d.Confidence != Confidence.High)
            return new ResponseDecision(true, new[] { snapshot },
                $"Confiança {d.Confidence} — snapshot preventivo e alerta; contenção exige alta confiança (evita falso positivo).");

        // L4 (laboratório, sessão 1): primeiro se fecha a porta, depois se tira o snapshot. Com o snapshot na frente — ele
        // leva segundos — o atacante continuou regravando: dos 169 arquivos tocados, cerca de 150 foram depois da decisão.
        var actions = new List<ResponseAction>(BuildLadder(d, policy)) { snapshot };
        return new ResponseDecision(true, actions,
            $"Bloqueio: incidente de alta confiança contido até {policy.MaxStep}.");
    }

    private static IReadOnlyList<ResponseAction> BuildLadder(DetectionModel d, ResponsePolicy policy)
    {
        var reason = $"Incidente {d.Confidence} em {d.Share} ({string.Join("+", d.Reasons)})";
        // Ordem importa. L5 (laboratório, sessão 5): a regra de firewall NÃO derruba conexão TCP já aberta, e o cliente
        // SMB reconecta a sessão por ela logo depois de derrubada. Por isso a negação no share vem ANTES de derrubar a
        // sessão — a reconexão encontra o acesso negado. Negar no share também vem antes de mexer no AD (reversível,
        // sem direitos de domínio).
        var all = new List<ResponseAction>();
        if (d.IsLocal)
        {
            // G4b: ataque de DENTRO do servidor — IP/sessão não existem; o que existe é o processo (4663).
            foreach (var p in d.Processes ?? Array.Empty<LocalProcess>())
                if (!ResponseTarget.IsProtectedProcess(p.Name))
                    all.Add(new ResponseAction(ResponseStep.StopProcess, d.Server, p.Pid.ToString(), reason, Account: p.Name));
            all.Add(new(ResponseStep.DenyUserOnShare, d.Server, d.Share, reason, Account: d.User));
        }
        else
        {
            all.Add(new(ResponseStep.BlockIp, d.Server, d.SourceIp, reason));
            all.Add(new(ResponseStep.DenyUserOnShare, d.Server, d.Share, reason, Account: d.User));
            all.Add(new(ResponseStep.KillSmbSession, d.Server, d.SourceIp, reason));
        }
        all.Add(new(ResponseStep.DisableAdAccount, d.Server, d.User, reason));
        all.Add(new(ResponseStep.IsolateShare, d.Server, d.Share, reason));
        return all.Where(a => a.Step <= policy.MaxStep).ToList();
    }
}
