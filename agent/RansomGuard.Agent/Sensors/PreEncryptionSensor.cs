using System.Text.RegularExpressions;
using System.Xml.Linq;
using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Sensors;

/// <summary>
/// G3 — sinais de pré-cifra: o que o operador de ransomware faz ANTES do primeiro arquivo. Traduz eventos do
/// Security log (4688 com linha de comando, 4697, 4720, 4728/4732/4756, 4625) e do System log (7045) em
/// <see cref="HostSignal"/>. Detecção por padrão de comando/evento, não por nome de malware: é o comportamento
/// (apagar cópias de sombra, impedir recuperação, instalar serviço, criar admin, adivinhar senha) que denuncia.
/// </summary>
public static class PreEncryptionEventParser
{
    // Comandos que destroem a capacidade de recuperação. Nenhum deles aparece na operação normal de um file server.
    private static readonly Regex RecoveryTampering = new(
        @"(vssadmin(\.exe)?\s+(delete\s+shadows|resize\s+shadowstorage))" +
        @"|(wmic(\.exe)?\s+.*shadowcopy\s+delete)" +
        @"|(wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup))" +
        @"|(bcdedit(\.exe)?\s+.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures))" +
        @"|(cipher(\.exe)?\s+/w)" +
        @"|(fsutil(\.exe)?\s+usn\s+deletejournal)" +
        @"|(win32_shadowcopy[\s\S]{0,120}(delete|remove))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // D6: utilitário de snapshot sem comando destrutivo visível. Scripts de backup o usam para CRIAR cópias de sombra;
    // o que ele faz está num arquivo de script, fora da linha de comando. Indício fraco, não comando contra a recuperação.
    private static readonly Regex RecoveryTool = new(@"\bdiskshadow(\.exe)?\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// D6: programas que executam o que vem na linha de comando. O texto de um comando destrutivo na linha de comando
    /// de QUALQUER outro programa (um editor abrindo um arquivo com esse nome, uma busca num log) não é o comando rodando.
    /// </summary>
    private static readonly HashSet<string> Interpreters = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
        "wmic.exe", "psexec.exe", "psexec64.exe", "psexesvc.exe", "schtasks.exe", "at.exe", "conhost.exe", "wsl.exe", "bash.exe",
        "vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "cipher.exe", "fsutil.exe", "diskshadow.exe"
    };

    private static bool RunsCommands(string image)
    {
        if (string.IsNullOrWhiteSpace(image)) return true;   // sem o nome do processo não dá para descartar
        var cut = image.LastIndexOfAny(new[] { '\\', '/' });
        return Interpreters.Contains(cut >= 0 ? image[(cut + 1)..] : image);
    }

    private static readonly string[] PrivilegedGroups =
        { "Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins", "Backup Operators", "Administradores", "Admins. do Domínio" };

    public static HostSignal? Parse(string? eventXml, DateTime? nowOverride = null)
    {
        if (string.IsNullOrWhiteSpace(eventXml)) return null;
        XElement root;
        try { root = XElement.Parse(eventXml); } catch (System.Xml.XmlException) { return null; }

        var id = root.Descendants().FirstOrDefault(e => e.Name.LocalName == "EventID")?.Value;
        var server = (root.Descendants().FirstOrDefault(e => e.Name.LocalName == "Computer")?.Value ?? "").Split('.')[0];
        var at = nowOverride ?? ParseTime(root);
        string Data(string name) => root.Descendants().FirstOrDefault(e => e.Name.LocalName == "Data"
            && string.Equals(e.Attribute("Name")?.Value, name, StringComparison.OrdinalIgnoreCase))?.Value ?? "";
        string Who() => $"{Data("SubjectDomainName")}\\{Data("SubjectUserName")}".Trim('\\');

        switch (id)
        {
            case "4688":
            {
                var cmd = Data("CommandLine");
                var proc = Data("NewProcessName");
                var text = string.IsNullOrWhiteSpace(cmd) ? proc : cmd;
                if (!RunsCommands(proc)) return null;
                if (RecoveryTampering.IsMatch(text))
                    return new HostSignal(at, HostSignalKind.RecoveryTampering, server, $"Comando contra a recuperação por {Who()}: {Truncate(text)}");
                if (RecoveryTool.IsMatch(text))
                    return new HostSignal(at, HostSignalKind.RecoveryToolUsed, server, $"Utilitário de snapshot executado por {Who()}: {Truncate(text)}");
                return null;
            }
            case "4697":
                if (IsOwnService(Data("ServiceName"), Data("ServiceFileName"))) return null;
                return new HostSignal(at, HostSignalKind.ServiceInstalled, server, $"Serviço '{Data("ServiceName")}' instalado por {Who()}: {Truncate(Data("ServiceFileName"))}");
            case "7045":   // System log: Service Control Manager
                if (IsOwnService(Data("ServiceName"), Data("ImagePath"))) return null;
                return new HostSignal(at, HostSignalKind.ServiceInstalled, server, $"Serviço '{Data("ServiceName")}' instalado: {Truncate(Data("ImagePath"))}");
            case "4720":
                return new HostSignal(at, HostSignalKind.PrivilegedAccountChange, server, $"Conta '{Data("TargetUserName")}' criada por {Who()}");
            case "4728" or "4732" or "4756":
            {
                var group = Data("TargetUserName");
                if (!PrivilegedGroups.Any(g => group.Equals(g, StringComparison.OrdinalIgnoreCase))) return null;
                return new HostSignal(at, HostSignalKind.PrivilegedAccountChange, server, $"'{Data("MemberName")}' adicionado ao grupo '{group}' por {Who()}");
            }
            case "4625":
            {
                var ip = Data("IpAddress");
                var user = Data("TargetUserName");
                return new HostSignal(at, HostSignalKind.LogonFailure, server, $"{ip}|{user}");   // bruto: o agregador decide
            }
            default:
                return null;
        }
    }

    /// <summary>
    /// L10 (laboratório, sessão 2): instalar ou atualizar o próprio agente gerava "serviço novo instalado". Só é do produto
    /// o serviço com o nome dele E o executável dele na pasta do produto — nome igual em outro lugar continua sinal.
    /// </summary>
    private static bool IsOwnService(string name, string image)
    {
        var n = name.Replace(" ", "");
        if (!n.Equals("RansomGuardAgent", StringComparison.OrdinalIgnoreCase) && !n.Equals("RansomGuardPanel", StringComparison.OrdinalIgnoreCase)) return false;
        var path = image.Trim().Trim('"');
        return path.Contains(@"\Program Files\RansomGuard\", StringComparison.OrdinalIgnoreCase)
               && (path.EndsWith(@"\RansomGuard.Agent.Service.exe", StringComparison.OrdinalIgnoreCase) || path.EndsWith(@"\RansomGuard.Server.exe", StringComparison.OrdinalIgnoreCase));
    }

    private static string Truncate(string s) => s.Length <= 160 ? s : s[..157] + "...";

    private static DateTime ParseTime(XElement root)
    {
        var tc = root.Descendants().FirstOrDefault(e => e.Name.LocalName == "TimeCreated")?.Attribute("SystemTime")?.Value;
        return DateTime.TryParse(tc, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var t)
            ? t : DateTime.UtcNow;
    }
}

/// <summary>
/// Agrega falhas de logon (4625) por IP de origem: uma rajada vira UM sinal de força bruta (com cooldown), não
/// cem. Falha isolada é ruído (senha errada) e nunca sai daqui.
/// </summary>
public sealed class LogonFailureAggregator(int threshold = 20, TimeSpan? window = null, TimeSpan? cooldown = null)
{
    private readonly TimeSpan _window = window ?? TimeSpan.FromMinutes(5);
    private readonly TimeSpan _cooldown = cooldown ?? TimeSpan.FromMinutes(15);
    private readonly Dictionary<string, List<DateTime>> _failures = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _lastSignal = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Consome sinais brutos <see cref="HostSignalKind.LogonFailure"/> e devolve os sinais finais (força bruta) + os demais intactos.</summary>
    public IReadOnlyList<HostSignal> Aggregate(IEnumerable<HostSignal> raw)
    {
        var output = new List<HostSignal>();
        foreach (var s in raw)
        {
            if (s.Kind != HostSignalKind.LogonFailure) { output.Add(s); continue; }
            var ip = s.Detail.Split('|')[0];
            if (string.IsNullOrWhiteSpace(ip) || ip == "-") continue;
            if (!_failures.TryGetValue(ip, out var list)) { list = new List<DateTime>(); _failures[ip] = list; }
            list.Add(s.At);
            list.RemoveAll(t => s.At - t > _window);
            if (list.Count < threshold) continue;
            if (_lastSignal.TryGetValue(ip, out var last) && s.At - last < _cooldown) continue;
            _lastSignal[ip] = s.At;
            output.Add(new HostSignal(s.At, HostSignalKind.LogonBruteForce, s.Server, $"{list.Count} falhas de logon em {_window.TotalMinutes:0} min a partir de {ip}"));
        }
        return output;
    }
}
