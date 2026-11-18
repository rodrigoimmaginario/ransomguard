using System.Globalization;
using System.Xml.Linq;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Fsrm;

namespace RansomGuard.Agent.Sensors;

/// <summary>
/// Traduz um evento do Security log do Windows para o <see cref="FileEvent"/> que o
/// <c>DetectionEngine</c> consome. É o ponto em que o produto deixa de ser cego.
///
/// Só dois eventos interessam:
/// <list type="bullet">
///   <item><b>5145</b> — acesso a share. O bom: traz <b>IP de origem</b>, share e alvo. É o evento
///   que enxerga a criptografia remota, o ponto cego do EDR.</item>
///   <item><b>4663</b> — acesso a objeto. Traz o caminho completo, mas <b>não traz IP</b> — daí o
///   <see cref="SessionCorrelator"/>.</item>
/// </list>
///
/// Puro: entra XML, sai evento. Assim a tradução fica coberta por teste sem precisar de um file
/// server, e o serviço Windows só se preocupa em ler o log.
/// </summary>
public static class SecurityEventParser
{
    /// <summary>Origem usada quando o evento não revela IP (acesso local, ou 4663 sem correlação).</summary>
    public const string LocalOrigin = "local";

    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    // Códigos de acesso do Windows (%%NNNN). Errar aqui faz leitura virar escrita — e leitura em
    // massa é backup rodando, não ataque.
    private const string WriteData = "%%4417";
    private const string AppendData = "%%4418";
    private const string Delete = "%%1537";
    // %%4422 = DeleteChild. (%%4420 é WriteEA: vem em toda abertura para gravação — confundi-los fazia cada
    // arquivo aberto para escrita aparecer como exclusão. Corrigido com evento real: Fixtures/real.)
    private const string DeleteChild = "%%4422";

    /// <summary>Shares de infraestrutura do Windows: ruído constante, nada a ver com dados de usuário.</summary>
    private static readonly string[] IgnoredShares = { "IPC$" };

    /// <summary>
    /// Endereços de loopback. O Windows registra acesso feito **na própria máquina** através do
    /// caminho de rede (\\localhost\share, ou um app que usa UNC local) com o IP de loopback.
    ///
    /// Tratar isso como origem remota seria perigoso: a escada de contenção bloquearia o loopback
    /// no firewall do servidor, o que quebra o próprio servidor — e derrubaria a sessão SMB de
    /// quem está trabalhando localmente. Loopback é **local**, e para origem local a resposta certa
    /// é a conta, não o endereço.
    /// </summary>
    private static readonly string[] Loopback = { "::1", "127.0.0.1", "0:0:0:0:0:0:0:1" };

    /// <summary><c>null</c> quando o XML não é um evento relevante ou está malformado.</summary>
    public static FileEvent? Parse(string? eventXml) => ParseDetailed(eventXml)?.Event;

    /// <summary>
    /// D1 — o evento mais o que o <see cref="ShareMap"/> precisa para dar a ele um share canônico: o nome do share
    /// (só o 5145 traz) e o caminho local completo do arquivo (5145: caminho local do share + alvo relativo;
    /// 4663: o próprio nome do objeto).
    /// </summary>
    public static ParsedFileEvent? ParseDetailed(string? eventXml)
    {
        if (string.IsNullOrWhiteSpace(eventXml)) return null;

        XElement root;
        try { root = XElement.Parse(eventXml); }
        catch (System.Xml.XmlException) { return null; }   // evento truncado não derruba o coletor

        var id = Value(root, "EventID") ?? root.Descendants().FirstOrDefault(e => e.Name.LocalName == "EventID")?.Value;
        return id switch
        {
            "5145" => ParseShareAccess(root),
            "4663" => ParseObjectAccess(root),
            _ => null
        };
    }

    /// <summary>RecordId do evento — é o que o cursor persiste para não reprocessar nem perder.</summary>
    public static long RecordIdOf(string? eventXml)
    {
        if (string.IsNullOrWhiteSpace(eventXml)) return 0;
        try
        {
            var v = XElement.Parse(eventXml).Descendants()
                .FirstOrDefault(e => e.Name.LocalName == "EventRecordID")?.Value;
            return long.TryParse(v, out var id) ? id : 0;
        }
        catch (System.Xml.XmlException) { return 0; }
    }

    private static ParsedFileEvent? ParseShareAccess(XElement root)
    {
        var share = NormalizeShare(Data(root, "ShareName"));
        if (share.Length == 0 || IgnoredShares.Contains(share, StringComparer.OrdinalIgnoreCase)) return null;

        var target = Data(root, "RelativeTargetName");
        if (string.IsNullOrWhiteSpace(target)) return null;

        var e = Build(root, share, target, NormalizeOrigin(Data(root, "IpAddress")));
        return new ParsedFileEvent(e, share, CombineLocal(Data(root, "ShareLocalPath"), target));
    }

    /// <summary><c>\??\D:\Shares\Fin</c> + <c>2024\a.docx</c> → <c>D:\Shares\Fin\2024\a.docx</c>. Sem caminho local: desconhecido.</summary>
    private static string? CombineLocal(string shareLocalPath, string relativeTarget)
    {
        var root = shareLocalPath.Trim();
        if (root.StartsWith(@"\??\", StringComparison.Ordinal)) root = root[4..];
        root = root.TrimEnd('\\');
        if (root.Length == 0) return null;
        return root + "\\" + relativeTarget.TrimStart('\\');
    }

    private static ParsedFileEvent? ParseObjectAccess(XElement root)
    {
        var objectName = Data(root, "ObjectName");
        if (string.IsNullOrWhiteSpace(objectName)) return null;

        // O 4663 traz o caminho local completo (D:\Shares\Financeiro\arquivo.docx). Usamos a pasta
        // imediatamente acima como "share" — o correlator refina com a sessão real.
        var file = System.IO.Path.GetFileName(objectName);
        if (file.Length == 0) return null;
        var folder = System.IO.Path.GetFileName(System.IO.Path.GetDirectoryName(objectName) ?? "");

        // G4b: o 4663 identifica o processo local (PID em hexa, ex.: 0x1a2c) — alvo do degrau StopProcess.
        var pidText = Data(root, "ProcessId");
        int? pid = pidText.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? (int.TryParse(pidText[2..], System.Globalization.NumberStyles.HexNumber, null, out var hex) ? hex : null)
            : (int.TryParse(pidText, out var dec) ? dec : null);
        var process = Data(root, "ProcessName");
        // L11 (laboratório, sessão 2): PID 4 é o próprio Windows servindo SMB — o acesso veio pela rede. Não há processo
        // local a encerrar; o coletor atribui a origem pelo acesso de rede do mesmo usuário ou pela sessão.
        if (pid is <= 4) { pid = null; process = ""; }
        var e = Build(root, folder, file, LocalOrigin) with { ProcessId = pid, ProcessName = string.IsNullOrWhiteSpace(process) ? null : process };
        return new ParsedFileEvent(e, null, objectName.Trim());
    }

    private static FileEvent Build(XElement root, string share, string target, string ip)
    {
        var user = ComposeUser(Data(root, "SubjectDomainName"), Data(root, "SubjectUserName"));
        var access = Data(root, "AccessList");
        var name = System.IO.Path.GetFileName(target);
        var ext = System.IO.Path.GetExtension(name);

        return new FileEvent(
            At: TimeOf(root),
            User: user,
            SourceIp: ip,
            Share: share,
            Op: OperationOf(access),
            Path: target,
            NewExtension: string.IsNullOrEmpty(ext) ? null : ext,
            IsCanary: CanaryPlan.IsCanary(name));
    }

    /// <summary>
    /// Precedência: apagar &gt; escrever &gt; ler. Um evento que apaga e escreve é reescrita
    /// destrutiva; classificar como leitura esconderia o ataque.
    /// </summary>
    private static FileOp OperationOf(string accessList)
    {
        if (accessList.Contains(Delete) || accessList.Contains(DeleteChild)) return FileOp.Delete;
        if (accessList.Contains(WriteData) || accessList.Contains(AppendData)) return FileOp.Write;
        return FileOp.Read;
    }

    /// <summary>
    /// Endereço vazio, "-" ou loopback viram <see cref="LocalOrigin"/>. Confirmado em máquina real:
    /// acessar <c>\\localhost\share</c> registra o 5145 com <c>::1</c>. Se isso passasse como IP
    /// remoto, a contenção bloquearia o loopback no firewall e quebraria o próprio servidor.
    /// </summary>
    public static string NormalizeOrigin(string? ip)
    {
        var v = (ip ?? "").Trim();
        if (v.Length == 0 || v == "-") return LocalOrigin;
        return Loopback.Contains(v, StringComparer.OrdinalIgnoreCase) ? LocalOrigin : v;
    }

    /// <summary><c>\\*\Financeiro</c> → <c>Financeiro</c>.</summary>
    private static string NormalizeShare(string raw)
    {
        var s = raw.Trim();
        var i = s.LastIndexOf('\\');
        return i >= 0 ? s[(i + 1)..] : s;
    }

    /// <summary>Sem domínio não se inventa a barra — <c>SYSTEM</c>, não <c>\SYSTEM</c>.</summary>
    private static string ComposeUser(string domain, string user) =>
        string.IsNullOrWhiteSpace(domain) ? user : $"{domain}\\{user}";

    private static DateTime TimeOf(XElement root)
    {
        var raw = root.Descendants().FirstOrDefault(e => e.Name.LocalName == "TimeCreated")
                      ?.Attribute("SystemTime")?.Value;
        return DateTime.TryParse(raw, CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t)
            ? t
            : DateTime.UtcNow;
    }

    private static string Value(XElement root, string localName) =>
        root.Descendants().FirstOrDefault(e => e.Name.LocalName == localName)?.Value ?? "";

    /// <summary>Lê <c>&lt;Data Name='X'&gt;valor&lt;/Data&gt;</c> do bloco EventData.</summary>
    private static string Data(XElement root, string name) =>
        root.Descendants().FirstOrDefault(e =>
            e.Name.LocalName == "Data" &&
            string.Equals(e.Attribute("Name")?.Value, name, StringComparison.Ordinal))?.Value ?? "";
}

/// <summary>Evento traduzido + os dados brutos que identificam o share (ver <see cref="ShareMap"/>).</summary>
/// <param name="Event">O evento como o <see cref="SecurityEventParser.Parse"/> sempre devolveu.</param>
/// <param name="ShareName">Nome do share no evento (5145); <c>null</c> no 4663.</param>
/// <param name="LocalFullPath">Caminho local completo do arquivo, quando o evento permite reconstruí-lo.</param>
public sealed record ParsedFileEvent(FileEvent Event, string? ShareName, string? LocalFullPath);

/// <summary>Uma sessão SMB aberta no servidor: quem, de onde.</summary>
/// <param name="User">Conta (DOMÍNIO\usuario).</param>
/// <param name="SourceIp">IP do cliente.</param>
/// <param name="Share">Share acessado, quando conhecido.</param>
public sealed record SmbSession(string User, string SourceIp, string Share = "");

/// <summary>
/// Dá origem aos eventos que não a revelam. Sem isto, toda criptografia remota apareceria como
/// "local" — e a escada de contenção não teria sessão nem IP em que bater, justamente no caso que
/// o produto existe para resolver.
/// </summary>
public static class SessionCorrelator
{
    /// <summary>
    /// Atribui um IP ao evento a partir das sessões abertas. Casa por **usuário**, preferindo a
    /// sessão do mesmo share. Sem correspondência, o evento continua local — atribuir ao usuário
    /// errado seria pior que não atribuir: a contenção derrubaria um inocente.
    /// </summary>
    public static FileEvent Attribute(FileEvent e, IReadOnlyCollection<SmbSession> sessions)
    {
        if (e.SourceIp != SecurityEventParser.LocalOrigin) return e;

        var doUsuario = sessions
            .Where(s => string.Equals(s.User, e.User, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (doUsuario.Count == 0) return e;

        var escolhida = doUsuario.FirstOrDefault(s =>
            string.Equals(s.Share, e.Share, StringComparison.OrdinalIgnoreCase)) ?? doUsuario[0];

        return e with { SourceIp = escolhida.SourceIp };
    }

    /// <summary>Comando que lista as sessões no formato que <see cref="ParseSessionLines"/> lê: <c>cliente|usuário|aberturas</c>.</summary>
    public const string SessionLinesCommand =
        "Get-SmbSession -ErrorAction SilentlyContinue | ForEach-Object { '{0}|{1}|{2}' -f $_.ClientComputerName, $_.ClientUserName, $_.NumOpens }";

    /// <summary>
    /// Lê as sessões no formato <c>cliente|usuário|aberturas</c>, uma por linha. O nome do cliente vem do Windows como
    /// <c>\\10.0.9.66</c> ou <c>[fe80::…]</c>; vira o mesmo texto que o evento de share traz como origem (loopback = local).
    /// </summary>
    public static IReadOnlyList<SmbSession> ParseSessionLines(string? output)
    {
        var sessions = new List<SmbSession>();
        foreach (var raw in (output ?? "").Split('\n'))
        {
            var cols = raw.Trim().Split('|');
            if (cols.Length != 3 || !long.TryParse(cols[2].Trim(), out _)) continue;
            var client = NormalizeClient(cols[0]);
            var user = cols[1].Trim();
            if (client.Length == 0 || user.Length == 0) continue;
            sessions.Add(new SmbSession(User: user, SourceIp: SecurityEventParser.NormalizeOrigin(client)));
        }
        return sessions;
    }

    /// <summary><c>\\10.0.9.66</c> → <c>10.0.9.66</c>; <c>[fe80::1]</c> → <c>fe80::1</c>.</summary>
    public static string NormalizeClient(string? client)
    {
        var v = (client ?? "").Trim().TrimStart('\\');
        if (v.Length >= 2 && v[0] == '[' && v[^1] == ']') v = v[1..^1];
        return v;
    }

    /// <summary>Lê a tabela do <c>Get-SmbSession</c>. Linha sem as colunas esperadas é descartada.</summary>
    public static IReadOnlyList<SmbSession> ParseSessions(string? output)
    {
        var sessions = new List<SmbSession>();
        if (string.IsNullOrWhiteSpace(output)) return sessions;

        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("----") || line.StartsWith("SessionId")) continue;

            var cols = line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (cols.Length < 4) continue;

            // SessionId ClientComputerName ClientUserName NumOpens — a última coluna é numérica,
            // e é isso que separa uma linha de dados de uma mensagem de erro do PowerShell.
            if (!long.TryParse(cols[^1], out _)) continue;

            sessions.Add(new SmbSession(User: cols[2], SourceIp: cols[1]));
        }
        return sessions;
    }
}
