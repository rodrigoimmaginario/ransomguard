namespace RansomGuard.Core.Score;

/// <summary>
/// Catálogo padrão de regras do Score de Risco (v1). Os pesos somam 100 para um servidor: um
/// servidor que viola tudo chega a 0; um que não viola nada, a 100. Cada regra cita a premissa
/// de ataque real que a justifica (rastreável à análise de mercado).
/// </summary>
public static class ScoreRules
{
    /// <summary>G2: mínimo recomendado do Security log com auditoria de file share ligada (256 MB).</summary>
    public const long SecurityLogMinimumBytes = 256L * 1024 * 1024;

    public static IReadOnlyList<ScoreRule> Default { get; } = new List<ScoreRule>
    {
        // ── Superfície SMB (peso total 24) ──────────────────────────────────────────────────
        new("smb-v1", ScoreCategory.SmbSurface, Severity.Critical, 8,
            "SMBv1 habilitado",
            "Protocolo legado wormable — vetor de relay e propagação (EternalBlue/WannaCry).",
            "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
            s => s.SmbV1Enabled),

        new("smb-signing", ScoreCategory.SmbSurface, Severity.High, 6,
            "SMB signing não exigido",
            "Sem signing, atacante faz relay e adultera tráfego SMB (padrão no Server 2025).",
            "GPO: Microsoft network server: Digitally sign communications (always) = Enabled",
            s => !s.SmbSigningRequired),

        new("ntlm", ScoreCategory.SmbSurface, Severity.High, 5,
            "NTLM irrestrito",
            "Permite pass-the-hash e relay; força para Kerberos reduz o vetor.",
            "GPO/Block NTLM (Lanman Workstation) com exceções mínimas necessárias.",
            s => s.NtlmUnrestricted),

        new("smb-ratelimit", ScoreCategory.SmbSurface, Severity.Low, 2,
            "Rate limiter de autenticação SMB ausente",
            "Sem freio, brute force de conta é rápido (padrão no Server 2025).",
            "Set-SmbServerConfiguration -InvalidAuthenticationDelayTimeInMs 2000",
            s => !s.SmbAuthRateLimiter),

        new("smb-445", ScoreCategory.SmbSurface, Severity.Medium, 3,
            "Porta 445 exposta amplamente",
            "445 acessível fora do segmento amplia superfície de brute force/relay.",
            "Firewall: restringir 445 ao segmento de servidores/administração.",
            s => s.Smb445ExposedBroadly),

        // ── Exposição de shares (peso total 18) ─────────────────────────────────────────────
        new("share-everyone", ScoreCategory.ShareExposure, Severity.Critical, 11,
            "Share com escrita para Everyone/Domain Users",
            "Uma única máquina comprometida criptografa o share remotamente via SMB.",
            "Restringir permissões de share/NTFS a grupos específicos (least privilege).",
            s => s.SharesWritableByEveryone),

        new("ntfs-broad", ScoreCategory.ShareExposure, Severity.Medium, 7,
            "Permissões NTFS largas",
            "Herança aberta e grupos amplos com modify aumentam o raio de criptografia.",
            "Revisar ACLs; remover Modify de grupos amplos; quebrar herança onde couber.",
            s => s.BroadNtfsPermissions),

        // ── Resiliência / recuperação (peso total 20) ───────────────────────────────────────
        new("vss", ScoreCategory.Resilience, Severity.High, 8,
            "Shadow copies (VSS) ausentes",
            "Sem VSS não há restauração rápida; deleção de VSS é passo universal do playbook.",
            "Habilitar VSS nos volumes de dados com agendamento e retenção adequados.",
            s => !s.VssEnabled),

        new("backup-running", ScoreCategory.Resilience, Severity.Critical, 8,
            "Serviço de backup parado/ausente",
            "Backup é a última linha de defesa; sem ele, criptografia é irreversível.",
            "Garantir backup em execução e testado (restore drill).",
            s => !s.BackupServiceRunning),

        new("backup-protected", ScoreCategory.Resilience, Severity.Medium, 4,
            "Backups/VSS sem proteção contra deleção",
            "Ransomware apaga backups alcançáveis antes de criptografar.",
            "Backup imutável/offline; conta de backup fora do alcance de contas comuns.",
            s => !s.BackupsProtected),

        // ── Detecção (peso total 20) ────────────────────────────────────────────────────────
        new("fsrm", ScoreCategory.Detection, Severity.Medium, 5,
            "FSRM não ativo",
            "Sem file screen do catálogo, extensões conhecidas não são bloqueadas.",
            "Instalar FSRM e aplicar o file screen do RansomGuard.",
            s => !s.FsrmActive),

        new("share-audit", ScoreCategory.Detection, Severity.Medium, 5,
            "Auditoria de file share desligada",
            "Sem evento 5145 não há atribuição por usuário+IP das escritas.",
            "auditpol: habilitar Detailed File Share (Success).",
            s => !s.ShareAuditingEnabled),

        new("seclog-size", ScoreCategory.Detection, Severity.Medium, 2,
            "Security log pequeno demais",
            "Com Detailed File Share ligado, 20 MB rodam em minutos: eventos do ataque são sobrescritos antes de serem lidos.",
            "wevtutil sl Security /ms:1073741824 (1 GB) — o agente corrige sozinho com AutoRepairVisibility.",
            s => s.SecurityLogMaxBytes is { } b && b < SecurityLogMinimumBytes),

        new("canaries", ScoreCategory.Detection, Severity.Medium, 3,
            "Canários não plantados",
            "Sem canários, variante desconhecida/cripto remota passa sem alarme cedo.",
            "Plantar arquivos-canário do RansomGuard nos shares.",
            s => !s.CanariesPlanted),

        new("agent", ScoreCategory.Detection, Severity.High, 5,
            "Sem agente RansomGuard",
            "Tempo de detecção > tempo de criptografia (domínio cai em <4h).",
            "Instalar o agente via GPO neste servidor.",
            s => !s.AgentInstalled),

        // ── Identidade (peso total 10) ──────────────────────────────────────────────────────
        new("svc-priv", ScoreCategory.Identity, Severity.High, 6,
            "Contas de serviço com privilégio excessivo",
            "Conta legítima comprometida é o vetor nº 1; privilégio largo amplia o dano.",
            "Reduzir privilégios; usar gMSA; separar contas por função.",
            s => s.OverprivilegedServiceAccounts),

        new("local-admins", ScoreCategory.Identity, Severity.Medium, 4,
            "Excesso de administradores locais",
            "Mais admins = mais alvos para escalada e movimento lateral.",
            "Reduzir admins locais ao mínimo; LAPS para senhas locais.",
            s => s.ExcessLocalAdmins),

        // ── Higiene de SO (peso total 8) ────────────────────────────────────────────────────
        new("os-eol", ScoreCategory.OsHygiene, Severity.High, 5,
            "SO fora de suporte ou sem patch",
            "Vetores de entrada conhecidos permanecem abertos sem correção.",
            "Atualizar/migrar o SO; aplicar patches críticos.",
            s => s.OsEndOfLifeOrUnpatched),

        new("rdp", ScoreCategory.OsHygiene, Severity.Medium, 3,
            "RDP exposto",
            "RDP acessível é porta clássica de entrada de ransomware.",
            "Fechar RDP externo; usar gateway/VPN + MFA.",
            s => s.RdpExposed),
    };

    /// <summary>Soma dos pesos — a nota máxima de um servidor (100 no catálogo padrão).</summary>
    public static int MaxScore(IReadOnlyList<ScoreRule> rules) => rules.Sum(r => r.Weight);
}
