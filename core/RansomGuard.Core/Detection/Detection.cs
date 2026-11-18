namespace RansomGuard.Core.Detection;

/// <summary>Nível de confiança de uma detecção — dirige a escada de resposta (fatia paga).</summary>
public enum Confidence
{
    /// <summary>Sinal isolado que pode ser I/O legítimo (backup, sync). Alerta antes de agir.</summary>
    Low,
    /// <summary>Padrão consistente com ransomware, mas sem prova irrefutável. Alerta forte.</summary>
    Medium,
    /// <summary>Canário tocado ou combinação inequívoca. Autoriza contenção automática.</summary>
    High
}

/// <summary>Por que a detecção disparou — usado no painel e no relatório de incidente.</summary>
public enum DetectionReason
{
    CanaryTouched,
    MassRewrite,
    MassRename,
    ExtensionFlip,
    VssDeletion,
    AgentTamper,
    // G1 — detecção em profundidade
    /// <summary>Nota de resgate escrita em vários diretórios (Alta: nenhum processo legítimo faz isso).</summary>
    RansomNote,
    /// <summary>Arquivos renomeados para extensão conhecida do catálogo (Alta, poucos arquivos bastam).</summary>
    KnownRansomExtension,
    /// <summary>Qualquer acesso a um share-isca que ninguém deveria usar (Alta).</summary>
    DecoyShareTouched,
    /// <summary>Volume acumulado numa janela longa — low-and-slow (Média).</summary>
    SustainedRewrite,
    /// <summary>Ritmo muito acima da linha de base do próprio ator (Média).</summary>
    RateAnomaly,
    /// <summary>G2: alguém tentou cegar o agente (auditoria alterada/desligada, log limpo, canário apagado) — Alta.</summary>
    VisibilityTamper,
    // G3 — pré-cifra
    /// <summary>Comando contra a recuperação (vssadmin/wbadmin/bcdedit/wmic/diskshadow/cipher) — Alta.</summary>
    RecoveryTampering,
    /// <summary>Serviço novo instalado — Média (duas razões de pré-cifra juntas = Alta).</summary>
    ServiceInstalled,
    /// <summary>Conta criada / membro em grupo privilegiado — Média.</summary>
    PrivilegedAccountChange,
    /// <summary>Rajada de falhas de logon — Média.</summary>
    LogonBruteForce,
    /// <summary>G5: leitura em massa por ator remoto (precursor de exfiltração / dupla extorsão) — Média.</summary>
    MassRead,
    /// <summary>
    /// Exclusão em massa — Média. No Windows real, apagar e renomear pela rede geram o mesmo registro (acesso de
    /// exclusão no nome antigo): cobre o apagador e a metade "renomeia" do ransomware que cifra no lugar.
    /// </summary>
    MassDelete,
    /// <summary>
    /// Algum arquivo com extensão do catálogo, abaixo do limiar de Alta — Média: registra, não contém. Fica no fim do
    /// enum de propósito: os valores dos membros anteriores não mudam.
    /// </summary>
    KnownExtensionSeen,
    // D6 — indícios que sozinhos não contêm ninguém; dois juntos, ou um com gravação em massa, sim.
    /// <summary>Cópias de sombra reduzidas, não zeradas — Média.</summary>
    VssReduction,
    /// <summary>Utilitário de snapshot usado sem comando destrutivo visível — Média.</summary>
    RecoveryToolUse,
    /// <summary>Canários apagados sem nenhum outro arquivo apagado (o que um espelhamento com purga faz) — Média.</summary>
    CanaryRemoved,
    /// <summary>Mesmo arquivo de nome genérico ("read_me", "how-to") em várias pastas — Média.</summary>
    NoteLikeFiles,
    /// <summary>Laboratório, sessão 3: arquivos que já existiam regravados em massa pelo mesmo ator — Alta.</summary>
    MassOverwrite
}

/// <summary>
/// Resultado da correlação: um ator (usuário+IP+share) associado a um comportamento suspeito,
/// com a confiança e as razões que o sustentam. É o que o servidor exibe e o que a escada de
/// resposta consome.
/// </summary>
/// <param name="Server">Servidor afetado.</param>
/// <param name="User">Conta atribuída ao comportamento.</param>
/// <param name="SourceIp">IP de origem — chave para conter criptografia remota via SMB.</param>
/// <param name="Share">Share sob ataque.</param>
/// <param name="Confidence">Confiança agregada.</param>
/// <param name="Reasons">Razões distintas que contribuíram.</param>
/// <param name="AffectedFiles">Quantidade de arquivos tocados na janela.</param>
/// <param name="FirstAt">Primeiro evento correlacionado (UTC).</param>
/// <param name="LastAt">Último evento correlacionado (UTC).</param>
/// <param name="Processes">G4b: processos locais (PID + imagem) vistos tocando os arquivos — alvo do degrau StopProcess.</param>
public sealed record Detection(
    string Server,
    string User,
    string SourceIp,
    string Share,
    Confidence Confidence,
    IReadOnlySet<DetectionReason> Reasons,
    int AffectedFiles,
    DateTime FirstAt,
    DateTime LastAt,
    IReadOnlyList<LocalProcess>? Processes = null,
    IReadOnlyList<string>? AffectedPaths = null)
{
    /// <summary>G5: teto de caminhos guardados por incidente (metadado para o restore).</summary>
    public const int MaxAffectedPaths = 500;
    public const string LocalOrigin = "local";
    public bool IsLocal => string.Equals(SourceIp, LocalOrigin, StringComparison.OrdinalIgnoreCase);
}

/// <summary>Processo local identificado pelo 4663.</summary>
public sealed record LocalProcess(int Pid, string Name);
