using RansomGuard.Agent.Posture;
using RansomGuard.Core.Fsrm;
using RansomGuard.Core.Score;

namespace RansomGuard.Agent.Service.Windows;

/// <summary>
/// Coletor de postura real. Lê a configuração do Windows via PowerShell e devolve, além dos
/// valores, **o conjunto de checagens que não conseguiu realizar** — que a engine de Score exclui
/// da conta em vez de punir ou perdoar em silêncio.
///
/// Duas correções de honestidade em relação à versão anterior:
///
/// 1. **Nada de chutar "está ruim".** Antes, qualquer falha de leitura virava `false` (ou `true`
///    para os campos invertidos), acusando o admin de algo que ninguém verificou. Um servidor bem
///    configurado recebia achado crítico de "share aberto para Everyone" — e a nota, que é a porta
///    de entrada do produto, perdia a credibilidade no primeiro olhar de quem entende.
///
/// 2. **Nada de perdoar em silêncio.** Sete checagens do catálogo nunca foram implementadas
///    (NTLM, 445 exposta, NTFS largo, backup protegido, contas privilegiadas, admins locais,
///    SO fora de suporte). Como o valor padrão do registro é `false` = "não violado", elas davam
///    pontos de graça e **inflavam** a nota. Agora entram explicitamente como não verificadas.
/// </summary>
public sealed class WindowsPostureCollector : IPostureCollector
{
    private readonly ILogger<WindowsPostureCollector> _log;
    private readonly IReadOnlyCollection<string> _protectedPaths;

    private readonly Func<IReadOnlyList<string>>? _canaryNames;

    public WindowsPostureCollector(ILogger<WindowsPostureCollector> log,
        IReadOnlyCollection<string>? protectedPaths = null, Func<IReadOnlyList<string>>? canaryNames = null)
    {
        _log = log;
        _protectedPaths = protectedPaths ?? Array.Empty<string>();
        _canaryNames = canaryNames;
    }

    /// <summary>Checagens que este coletor ainda não sabe fazer — declaradas, não escondidas.</summary>
    private static readonly string[] NaoImplementadas =
    {
        "ntlm", "smb-445", "ntfs-broad", "backup-protected",
        "svc-priv", "local-admins", "os-eol"
    };

    public PostureSnapshot Collect(string server)
    {
        var desconhecidas = new HashSet<string>(NaoImplementadas);

        // Teste booleano; falha ou saída ininteligível vira "desconhecido".
        bool Q(string ruleId, string script, bool fallback = false)
        {
            try
            {
                var saida = PowerShellRunner.Run(script).Trim();
                if (saida.Equals("True", StringComparison.OrdinalIgnoreCase)) return true;
                if (saida.Equals("False", StringComparison.OrdinalIgnoreCase)) return false;
                desconhecidas.Add(ruleId);           // não veio True/False: não sabemos
                return fallback;
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "Checagem {Rule} não pôde ser realizada", ruleId);
                desconhecidas.Add(ruleId);
                return fallback;
            }
        }

        long? LogSize(string ruleId)
        {
            try
            {
                var n = SecurityLogReader.TryReadMaxBytes(NativeTool.Run("wevtutil.exe", "gl Security"));
                if (n is null) desconhecidas.Add(ruleId);
                return n;
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "Checagem {Rule} não pôde ser realizada", ruleId);
                desconhecidas.Add(ruleId);
                return null;
            }
        }

        // Comando cuja saída vai para o parser tri-estado correspondente.
        bool Texto(string ruleId, string script, Func<string?, bool?> parser, bool fallback = false)
        {
            try
            {
                var resultado = parser(PowerShellRunner.Run(script));
                if (resultado is bool valor) return valor;
                desconhecidas.Add(ruleId);
                return fallback;
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "Checagem {Rule} não pôde ser realizada", ruleId);
                desconhecidas.Add(ruleId);
                return fallback;
            }
        }

        // Política de auditoria pelo GUID (independe do idioma do Windows); "não sei" entra como não verificado.
        bool Auditoria(string ruleId, AuditSubcategory sub)
        {
            if (WindowsAudit.IsSuccessEnabled(sub) is bool ligada) return ligada;
            desconhecidas.Add(ruleId);
            return false;
        }

        var canarios = CanaryPresence.Evaluate(_protectedPaths, ListarArquivos, _canaryNames?.Invoke());
        if (canarios is null) desconhecidas.Add("canaries");

        return new PostureSnapshot
        {
            Server = server,
            AgentInstalled = true,

            SmbV1Enabled = Q("smb-v1", "(Get-SmbServerConfiguration).EnableSMB1Protocol"),
            SmbSigningRequired = Q("smb-signing", "(Get-SmbServerConfiguration).RequireSecuritySignature"),
            SmbAuthRateLimiter = Q("smb-ratelimit",
                "(Get-SmbServerConfiguration).InvalidAuthenticationDelayTimeInMs -gt 0"),

            VssEnabled = Q("vss", "[bool](Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue)"),
            BackupServiceRunning = Q("backup-running",
                "[bool](Get-Service -Name 'Windows Backup' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')"),

            // R7: mede o FILE SCREEN do produto aplicado, não a role instalada. Um servidor com FSRM
            // mas sem o nosso screen não está protegido — e a nota não pode fingir que está.
            FsrmActive = Texto("fsrm",
                "Get-FsrmFileScreen -ErrorAction SilentlyContinue | Format-List Path,Active,IncludeGroup | Out-String",
                FsrmScreenReader.TryRead),

            // Antes: fixo em true (acusava todo mundo). Agora lê a ACL de verdade.
            SharesWritableByEveryone = Texto("share-everyone",
                "Get-SmbShare -ErrorAction Stop | Get-SmbShareAccess -ErrorAction Stop | Format-Table -AutoSize | Out-String -Width 200",
                SharePermissionReader.TryRead),

            // Antes: fixo em false. É pré-requisito da detecção, não só um item de nota.
            // A subcategoria é **Detailed File Share** (evento 5145, um por arquivo). "File Share"
            // gera o 5140, um por conexão — cem mil arquivos cifrados numa sessão produzem um
            // único evento, inútil para detectar criptografia em massa.
            ShareAuditingEnabled = Auditoria("share-audit", AuditSubcategory.DetailedFileShare),

            // G2: tamanho do Security log — 20 MB padrão estoura em minutos com 5145 ligado.
            SecurityLogMaxBytes = LogSize("seclog-size"),

            // Antes: fixo em false — a nota nunca subia quando o produto plantava os canários.
            CanariesPlanted = canarios ?? false,

            RdpExposed = Q("rdp",
                "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections -eq 0"),

            UnknownChecks = desconhecidas
        };
    }

    private static IReadOnlyList<string> ListarArquivos(string path) =>
        Directory.EnumerateFiles(path).Select(Path.GetFileName).OfType<string>().ToList();
}
