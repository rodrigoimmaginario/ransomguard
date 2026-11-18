namespace RansomGuard.Core.Response;

/// <summary>Desfecho real de uma ação de contenção (R4). Êxito nunca é presumido.</summary>
public enum ResponseStatus
{
    /// <summary>Executada com sucesso no servidor.</summary>
    Executed,
    /// <summary>Não executada por decisão de segurança (ex.: alvo com forma insegura — R3).</summary>
    Skipped,
    /// <summary>Tentada, mas o comando falhou.</summary>
    Failed
}

/// <param name="Status">Desfecho.</param>
/// <param name="Detail">Motivo/observação legível para a auditoria.</param>
public sealed record ResponseOutcome(ResponseStatus Status, string Detail = "")
{
    public bool Ok => Status == ResponseStatus.Executed;
    public static ResponseOutcome Done(string detail = "") => new(ResponseStatus.Executed, detail);
    public static ResponseOutcome Skip(string detail) => new(ResponseStatus.Skipped, detail);
    public static ResponseOutcome Fail(string detail) => new(ResponseStatus.Failed, detail);
}

/// <summary>
/// Executa (ou reverte) uma ação de contenção. A implementação real no Windows (Close-SmbSession,
/// New-NetFirewallRule, Disable-ADAccount, Block-SmbShareAccess) vive no serviço do agente
/// (net10-windows) e é validada no lab. O Core decide; o executor age. Decisão de credencial de
/// menor privilégio (gMSA/delegação) = D3, e não afeta esta interface.
///
/// R4: devolve o <see cref="ResponseOutcome"/> real — sucesso, pulado ou falha — para a auditoria
/// nunca registrar como "executada" uma ação que falhou.
/// </summary>
public interface IResponseExecutor
{
    Task<ResponseOutcome> ExecuteAsync(ResponseAction action, CancellationToken ct = default);

    /// <summary>Reverte uma ação (reabilitar conta, desbloquear IP) — usado na remediação.</summary>
    Task<ResponseOutcome> RevertAsync(ResponseAction action, CancellationToken ct = default);
}

/// <summary>Executor que apenas registra o que faria — para testes, simuladores e modo dry-run.</summary>
public sealed class RecordingExecutor : IResponseExecutor
{
    public List<ResponseAction> Executed { get; } = new();
    public List<ResponseAction> Reverted { get; } = new();

    public Task<ResponseOutcome> ExecuteAsync(ResponseAction action, CancellationToken ct = default)
    {
        Executed.Add(action);
        return Task.FromResult(ResponseOutcome.Done());
    }

    public Task<ResponseOutcome> RevertAsync(ResponseAction action, CancellationToken ct = default)
    {
        Reverted.Add(action);
        return Task.FromResult(ResponseOutcome.Done());
    }
}

/// <summary>
/// Orquestra decisão → execução, produzindo uma trilha de auditoria. Cada ação executada vira um
/// registro; a remediação (desbloqueio) também é auditada — evolução do Desbloqueia_Usuario.txt.
/// </summary>
public sealed class ResponseRunner
{
    private readonly IResponseExecutor _executor;
    public List<AuditEntry> Audit { get; } = new();

    /// <summary>Quantas ações de fato executaram com sucesso (R4 — contenção real, não decidida).</summary>
    public int ExecutedCount { get; private set; }

    public ResponseRunner(IResponseExecutor executor) => _executor = executor;

    /// <summary>
    /// Executa as ações de uma decisão (se houver), auditando o desfecho REAL de cada passo.
    ///
    /// R3: um alvo com forma insegura é <b>pulado e auditado</b> — nunca chega ao executor, para que
    /// metadado de evento manipulado não componha um comando no servidor.
    /// R4: só conta como contenção o que o executor confirma como executado; falha vira auditoria
    /// <c>fail</c>, jamais <c>execute</c>.
    /// </summary>
    /// <returns>Número de ações executadas com sucesso.</returns>
    public async Task<int> RunAsync(ResponseDecision decision, DateTime at, string actor = "RansomGuard",
        CancellationToken ct = default)
    {
        foreach (var action in decision.Actions)
        {
            if (!ResponseTarget.IsSafe(action))
            {
                Audit.Add(new AuditEntry(at, actor, "skip", action,
                    $"Alvo recusado (forma insegura): {action.Reason}"));
                continue;
            }

            var outcome = await _executor.ExecuteAsync(action, ct);
            switch (outcome.Status)
            {
                case ResponseStatus.Executed:
                    Audit.Add(new AuditEntry(at, actor, "execute", action, action.Reason));
                    // G4a: o snapshot preventivo protege, não contém — não entra na contagem de contenção.
                    if (action.Step != ResponseStep.PreemptiveSnapshot) ExecutedCount++;
                    break;
                case ResponseStatus.Skipped:
                    Audit.Add(new AuditEntry(at, actor, "skip", action, outcome.Detail));
                    break;
                default:
                    Audit.Add(new AuditEntry(at, actor, "fail", action, outcome.Detail));
                    break;
            }
        }
        return ExecutedCount;
    }

    /// <summary>Reverte uma ação previamente executada (remediação manual pelo admin), auditando.</summary>
    public async Task RevertAsync(ResponseAction action, DateTime at, string actor, string justification,
        CancellationToken ct = default)
    {
        await _executor.RevertAsync(action, ct);
        Audit.Add(new AuditEntry(at, actor, "revert", action, justification));
    }
}

/// <summary>Um registro de auditoria de resposta (metadado; base do relatório de incidente assinado).</summary>
public sealed record AuditEntry(
    DateTime At, string Actor, string Operation, ResponseAction Action, string Justification);

/// <summary>
/// G4a — um snapshot por share por janela: numa rajada de detecções o agente não enche o volume de
/// shadow copies. Lógica pura; o executor Windows consulta antes de criar.
///
/// D7 — e um teto por dia, por share e para o servidor inteiro. Cada volume guarda um número limitado de cópias de
/// sombra: sob ruído sustentado (detecções de Média durante dias), snapshots a cada 10 minutos empurrariam para fora
/// os pontos de restauração que o cliente já tinha — o produto destruindo a recuperação que diz proteger.
/// </summary>
public sealed class SnapshotThrottle(TimeSpan window, int maxPerShareDaily = 6, int maxPerServerDaily = 12)
{
    private static readonly TimeSpan Day = TimeSpan.FromHours(24);
    private readonly Dictionary<string, DateTime> _last = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(string Share, DateTime At)> _taken = new();
    /// <summary>Por que o último pedido foi recusado (para a trilha do incidente).</summary>
    public string LastRefusal { get; private set; } = "";

    public bool ShouldSnapshot(string share, DateTime now)
    {
        lock (_last)
        {
            if (_last.TryGetValue(share, out var last) && now - last < window)
                return Refuse($"snapshot recente deste share (janela de {window.TotalMinutes:0} min)");
            _taken.RemoveAll(t => now - t.At >= Day);
            if (_taken.Count(t => t.Share.Equals(share, StringComparison.OrdinalIgnoreCase)) >= maxPerShareDaily)
                return Refuse($"teto de {maxPerShareDaily} snapshots preventivos por dia para este share atingido");
            if (_taken.Count >= maxPerServerDaily)
                return Refuse($"teto de {maxPerServerDaily} snapshots preventivos por dia neste servidor atingido");
            _last[share] = now;
            _taken.Add((share, now));
            LastRefusal = "";
            return true;
        }
    }

    private bool Refuse(string why) { LastRefusal = why; return false; }
}
