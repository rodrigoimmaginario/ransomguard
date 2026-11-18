namespace RansomGuard.Core.Score;

/// <summary>
/// Retrato de configuração (postura) de um servidor Windows, coletado pelo agente. Metadado e
/// flags apenas — nunca conteúdo. É a entrada do <see cref="RiskScoreEngine"/>.
///
/// Cada propriedade mapeia uma checagem calibrada por uma premissa de ataque conhecida.
///
/// Checagem que o agente **não conseguiu realizar** (sem permissão, cmdlet ausente, não é file
/// server) entra em <see cref="UnknownChecks"/> — nunca vira um valor chutado. Chutar "está ruim"
/// produz achado falso, e nota errada destrói a confiança na tela que é a porta de entrada
/// do produto; chutar "está bom" esconde risco. A saída honesta é dizer que não se sabe.
/// </summary>
public sealed record PostureSnapshot
{
    public required string Server { get; init; }

    /// <summary>
    /// Ids de regras (<see cref="ScoreRule.Id"/>) cuja checagem não pôde ser realizada. A engine as
    /// exclui do numerador e do denominador, e as devolve em <see cref="ServerScore.Unknown"/> para
    /// o painel mostrar o que ficou sem verificar.
    /// </summary>
    /// <remarks>Tipo concreto de propósito: o System.Text.Json não desserializa IReadOnlySet (visto no .NET 8), e este
    /// objeto atravessa o fio agente → painel (bug pego pelo IncidentTrailSimulator em 2026-10-03).</remarks>
    public HashSet<string> UnknownChecks { get; init; } = new();

    // ── Superfície SMB ────────────────────────────────────────────────────────────────────────
    /// <summary>SMBv1 habilitado (protocolo legado, vetor de relay/wormable).</summary>
    public bool SmbV1Enabled { get; init; }
    /// <summary>SMB signing exigido (Server 2025 liga por padrão; evita relay/tamper).</summary>
    public bool SmbSigningRequired { get; init; }
    /// <summary>NTLM irrestrito (permite pass-the-hash/relay; Server 2025 permite bloquear).</summary>
    public bool NtlmUnrestricted { get; init; }
    /// <summary>Rate limiter de autenticação SMB ativo (freia brute force; padrão no 2025).</summary>
    public bool SmbAuthRateLimiter { get; init; }
    /// <summary>Porta 445 exposta além do segmento de servidores.</summary>
    public bool Smb445ExposedBroadly { get; init; }

    // ── Exposição de shares ───────────────────────────────────────────────────────────────────
    /// <summary>Há share com escrita para Everyone/Domain Users (cripto remota a partir de 1 host).</summary>
    public bool SharesWritableByEveryone { get; init; }
    /// <summary>Permissões NTFS largas (herança aberta, grupos amplos com modify).</summary>
    public bool BroadNtfsPermissions { get; init; }

    // ── Resiliência (recuperação) ─────────────────────────────────────────────────────────────
    /// <summary>Shadow copies (VSS) habilitadas nos volumes de dados.</summary>
    public bool VssEnabled { get; init; }
    /// <summary>Serviço de backup presente e em execução.</summary>
    public bool BackupServiceRunning { get; init; }
    /// <summary>VSS/backup com proteção contra deleção por conta comprometida.</summary>
    public bool BackupsProtected { get; init; }

    // ── Detecção ──────────────────────────────────────────────────────────────────────────────
    /// <summary>FSRM instalado e com file screen do catálogo aplicado.</summary>
    public bool FsrmActive { get; init; }
    /// <summary>Auditoria de file share (evento 5145) habilitada.</summary>
    public bool ShareAuditingEnabled { get; init; }
    /// <summary>G2: tamanho máximo do Security log em bytes (null = não lido). 20 MB padrão estoura em minutos sob 5145.</summary>
    public long? SecurityLogMaxBytes { get; init; }
    /// <summary>Arquivos-canário plantados nos shares.</summary>
    public bool CanariesPlanted { get; init; }
    /// <summary>O agente RansomGuard está instalado e reportando neste servidor.</summary>
    public bool AgentInstalled { get; init; } = true;

    // ── Identidade ────────────────────────────────────────────────────────────────────────────
    /// <summary>Contas de serviço com privilégio excessivo (admin de domínio, p.ex.).</summary>
    public bool OverprivilegedServiceAccounts { get; init; }
    /// <summary>Excesso de administradores locais no servidor.</summary>
    public bool ExcessLocalAdmins { get; init; }

    // ── Higiene de SO ─────────────────────────────────────────────────────────────────────────
    /// <summary>SO fora de suporte (EOL) ou sem patches críticos recentes.</summary>
    public bool OsEndOfLifeOrUnpatched { get; init; }
    /// <summary>RDP exposto à rede ampla/internet.</summary>
    public bool RdpExposed { get; init; }
}
