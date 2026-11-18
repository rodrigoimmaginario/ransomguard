using System.Net;
using System.Text.RegularExpressions;

namespace RansomGuard.Core.Response;

/// <summary>
/// R3 — porteiro dos alvos de contenção. Os alvos (IP de origem, conta, share) vêm de metadado de
/// evento do Windows, e parte deles é influenciável por quem abriu a sessão SMB. Antes de qualquer
/// alvo compor um comando no servidor, ele precisa ter **forma segura**.
///
/// A regra é allowlist, não blocklist: em vez de tentar listar tudo o que é perigoso, só deixamos
/// passar o que casa exatamente com o formato esperado de cada passo. Assim, um valor com aspas,
/// metacaractere de shell, quebra de linha ou subexpressão simplesmente não casa e é recusado —
/// o executor nunca chega a interpolá-lo.
///
/// Lógica pura e determinística; o executor real do serviço a consulta como defesa em profundidade.
/// </summary>
public static class ResponseTarget
{
    // Conta: DOMÍNIO\sam ou sam simples. Letras/dígitos/._- e $ final (contas de máquina/serviço).
    private static readonly Regex AccountPattern =
        new(@"^(?:[A-Za-z0-9._-]{1,64}\\)?[A-Za-z0-9._-]{1,64}\$?$", RegexOptions.Compiled);

    // Share: UNC \\servidor\share ou nome simples. Permite espaço; proíbe metacaractere/controle.
    private static readonly Regex SharePattern =
        new(@"^(?:\\\\[A-Za-z0-9._-]{1,64}\\)?[A-Za-z0-9 ._$-]{1,128}$", RegexOptions.Compiled);

    /// <summary>Validação completa da ação (alvo e, quando o passo exige, conta).</summary>
    public static bool IsSafe(ResponseAction action) =>
        action.Step == ResponseStep.DenyUserOnShare
            ? IsSafe(action.Step, action.Target) && !string.IsNullOrWhiteSpace(action.Account)
              && !ContainsDangerousChar(action.Account) && AccountPattern.IsMatch(action.Account)
            : IsSafe(action.Step, action.Target);

    /// <summary>O alvo tem forma segura para este passo da escada?</summary>
    public static bool IsSafe(ResponseStep step, string? target)
    {
        if (string.IsNullOrWhiteSpace(target)) return false;
        if (ContainsDangerousChar(target)) return false;

        return step switch
        {
            ResponseStep.PreemptiveSnapshot => SharePattern.IsMatch(target),
            ResponseStep.StopProcess => IsSafeProcessTarget(target),
            ResponseStep.DenyUserOnShare => SharePattern.IsMatch(target),
            ResponseStep.KillSmbSession => IsIpOrHost(target),
            ResponseStep.BlockIp => IsIp(target),
            ResponseStep.DisableAdAccount => AccountPattern.IsMatch(target),
            ResponseStep.IsolateShare => SharePattern.IsMatch(target),
            _ => false
        };
    }

    /// <summary>
    /// Caracteres que jamais aparecem num alvo legítimo e quebrariam a composição do comando. O
    /// <c>$</c> fica fora desta lista porque contas de máquina/serviço terminam legitimamente em
    /// <c>$</c> (ex.: <c>svc_backup$</c>); o regex de conta o permite só como sufixo, e os padrões de
    /// IP/share não o aceitam — então ele nunca chega a compor uma subexpressão num alvo aceito.
    /// </summary>
    private static bool ContainsDangerousChar(string s)
    {
        foreach (var c in s)
        {
            if (char.IsControl(c)) return true;                       // \n \r \t etc.
            if (c is '\'' or '"' or '`' or ';' or '|' or '&'          // shell
                  or '<' or '>' or '(' or ')' or '{' or '}' or '*' or '?' or '%' or '^')
                return true;
        }
        return false;
    }

    private static bool IsIp(string s) => IPAddress.TryParse(s, out _);

    /// <summary>Processos que o produto NUNCA encerra, mesmo que apareçam tocando arquivos (sistema, segurança, backup nativo).</summary>
    public static readonly IReadOnlySet<string> ProtectedProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "System", "ntoskrnl.exe", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
        "MsMpEng.exe", "explorer.exe", "dfsrs.exe", "ntfrs.exe", "wbengine.exe", "vssvc.exe", "RansomGuard.Agent.Service.exe"
    };

    /// <summary>PID numérico, nunca 0/4 (Idle/System), nunca o próprio processo.</summary>
    private static bool IsSafeProcessTarget(string s) =>
        int.TryParse(s, out var pid) && pid > 4 && pid != Environment.ProcessId;

    public static bool IsProtectedProcess(string? imageName)
    {
        if (string.IsNullOrWhiteSpace(imageName)) return false;
        var name = imageName.Replace('/', '\\');
        var slash = name.LastIndexOf('\\');
        if (slash >= 0) name = name[(slash + 1)..];
        return ProtectedProcessNames.Contains(name) || name.Equals("System", StringComparison.OrdinalIgnoreCase);
    }

    // KillSmbSession casa por IP ou nome de máquina (o executor filtra por ClientComputerName).
    private static bool IsIpOrHost(string s) =>
        IsIp(s) || Regex.IsMatch(s, @"^[A-Za-z0-9._-]{1,64}$");
}
