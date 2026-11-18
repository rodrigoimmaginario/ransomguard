namespace RansomGuard.Core.Detection;

/// <summary>
/// Sinais de host de alta confiança que fazem parte do playbook de ransomware, coletados fora do
/// fluxo de arquivos: deleção de shadow copies, parada de serviço de backup e adulteração do
/// próprio agente (heartbeat perdido = resposta ao cenário de EDR killer).
/// </summary>
public enum HostSignalKind
{
    VssDeleted,
    BackupServiceStopped,
    AgentTamper,
    // G2 — visibilidade auto-reparável: cegar o agente é parte do playbook; cegueira nunca é silêncio.
    /// <summary>Evento 4719: a política de auditoria de file share/file system foi alterada.</summary>
    AuditPolicyChanged,
    /// <summary>Evento 1102: o Security log foi limpo.</summary>
    SecurityLogCleared,
    /// <summary>Canário plantado desapareceu (apagado ou movido) — ninguém legítimo apaga canário.</summary>
    CanaryMissing,
    /// <summary>A auditoria necessária (Detailed File Share) foi encontrada desligada.</summary>
    AuditDisabled,
    /// <summary>Informativo: o agente religou a auditoria / ampliou o log (não é detecção).</summary>
    VisibilityRepaired,
    // G3 — pré-cifra: o que acontece ANTES do primeiro arquivo
    /// <summary>4688: comando que destrói a recuperação (shadow copies, catálogo de backup, boot recovery) — Alta.</summary>
    RecoveryTampering,
    /// <summary>4697/7045: serviço novo instalado (PsExec, loaders) — Média.</summary>
    ServiceInstalled,
    /// <summary>4720/4728/4732/4756: conta criada ou membro em grupo privilegiado — Média.</summary>
    PrivilegedAccountChange,
    /// <summary>4625 bruto (uma falha). Nunca vira detecção sozinho: o agregador converte rajadas em LogonBruteForce.</summary>
    LogonFailure,
    /// <summary>Rajada de falhas de logon do mesmo IP — Média.</summary>
    LogonBruteForce,
    // D6 — sinais fracos (ficam no fim do enum: os valores anteriores não mudam).
    /// <summary>Menos cópias de sombra do que antes, mas não todas — backup que remove o próprio snapshot, rotação por espaço. Média.</summary>
    VssReduced,
    /// <summary>Utilitário de snapshot executado sem comando destrutivo visível (script de backup faz isso). Média.</summary>
    RecoveryToolUsed
}

/// <param name="At">Instante do sinal (UTC).</param>
/// <param name="Kind">Natureza do sinal.</param>
/// <param name="Server">Servidor onde o sinal foi observado.</param>
/// <param name="Detail">Detalhe livre (ex.: nome do serviço), metadado apenas.</param>
public sealed record HostSignal(
    DateTime At,
    HostSignalKind Kind,
    string Server,
    string Detail = "");
