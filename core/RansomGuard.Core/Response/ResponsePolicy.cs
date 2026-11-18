namespace RansomGuard.Core.Response;

/// <summary>Modo de operação da resposta para um escopo (servidor/share/grupo).</summary>
public enum ResponseMode
{
    /// <summary>Só registra; nunca alerta nem age. Fail-safe: é o default de tudo.</summary>
    Monitor,
    /// <summary>Alerta, mas não executa contenção.</summary>
    Alert,
    /// <summary>Executa a escada de contenção conforme a confiança.</summary>
    Block
}

/// <summary>
/// Política de resposta aplicável a um incidente. Guarda o modo e os guard-rails contra falso
/// positivo. Um servidor/share nasce em <see cref="ResponseMode.Monitor"/> — nunca em bloqueio.
/// </summary>
public sealed class ResponsePolicy
{
    /// <summary>Modo efetivo. Default fail-safe = Monitor.</summary>
    public ResponseMode Mode { get; init; } = ResponseMode.Monitor;

    /// <summary>Passo máximo permitido (limita a escada; ex.: nunca isolar o share automaticamente).</summary>
    public ResponseStep MaxStep { get; init; } = ResponseStep.DenyUserOnShare;

    /// <summary>
    /// Contas cujo comportamento nunca gera contenção por volume (backup, AV, robocopy). Herda a
    /// mesma allowlist do motor de detecção. Um canário tocado ignora a allowlist.
    /// </summary>
    public IReadOnlySet<string> AllowlistedUsers { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    public IReadOnlySet<string> AllowlistedIps { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Se true, está no período de aprendizado (baseline): observa e alerta, nunca contém, mesmo em
    /// modo Block. Evita conter tráfego legítimo antes de conhecer o normal do ambiente.
    /// </summary>
    public bool LearningMode { get; init; }
}
