using RansomGuard.Core.Fsrm;

namespace RansomGuard.Agent.Posture;

/// <summary>
/// Lê, da saída do <c>Get-SmbShareAccess</c>, se existe algum share com **escrita para grupo
/// amplo** — a premissa de ataque nº 1 do produto: uma única máquina comprometida criptografa o
/// share inteiro pela rede.
///
/// Todos os métodos são puros (texto → resposta), então a regra fica coberta por teste sem precisar
/// de um file server. O serviço Windows só invoca o PowerShell e passa o texto adiante.
/// </summary>
public static class SharePermissionReader
{
    /// <summary>Grupos que representam "qualquer pessoa da rede", incluindo o Windows em português.</summary>
    private static readonly string[] BroadAccounts =
    {
        "everyone", "todos",
        "authenticated users", "usuários autenticados", "usuarios autenticados",
        "builtin\\users", "usuários", "usuarios",
        "domain users", "usuários do domínio", "usuarios do dominio"
    };

    /// <summary>Direitos que permitem criptografar (ler não basta para o atacante).</summary>
    private static readonly string[] WriteRights = { "full", "change", "modify", "write", "alterar", "modificar" };

    /// <summary>
    /// Resposta com tri-estado: <c>null</c> = não deu para ler (vira "desconhecido" na postura, e o
    /// Score não pontua). Nunca chutamos: chutar "aberto" acusa o admin sem prova.
    /// </summary>
    public static bool? TryRead(string? powerShellOutput)
    {
        if (string.IsNullOrWhiteSpace(powerShellOutput)) return null;
        if (!ParseRows(powerShellOutput).Any()) return null;
        return HasBroadWriteAccess(powerShellOutput);
    }

    public static bool HasBroadWriteAccess(string powerShellOutput) =>
        ParseRows(powerShellOutput).Any(r =>
            !IsAdministrativeShare(r.Share) &&
            r.Allow &&
            IsBroadAccount(r.Account) &&
            GrantsWrite(r.Right));

    /// <summary>
    /// Shares administrativos (<c>C$</c>, <c>ADMIN$</c>, <c>IPC$</c>) só são acessíveis a
    /// administradores e existem em todo Windows. Contá-los faria qualquer servidor nascer com um
    /// achado crítico falso.
    /// </summary>
    private static bool IsAdministrativeShare(string share) => share.EndsWith('$');

    private static bool IsBroadAccount(string account) =>
        BroadAccounts.Any(b => account.Equals(b, StringComparison.OrdinalIgnoreCase)
                            || account.EndsWith("\\" + b, StringComparison.OrdinalIgnoreCase));

    private static bool GrantsWrite(string right) =>
        WriteRights.Any(w => right.Contains(w, StringComparison.OrdinalIgnoreCase));

    private readonly record struct Row(string Share, string Account, bool Allow, string Right);

    /// <summary>
    /// Valores válidos de <c>AccessControlType</c>. É o que distingue uma linha de dados de uma
    /// mensagem de erro do PowerShell — sem isso, "Get-SmbShare : O termo não é reconhecido" tem
    /// colunas suficientes e passaria por um registro, fazendo o agente afirmar sobre um comando
    /// que sequer executou.
    /// </summary>
    private static readonly string[] AccessTypes = { "allow", "deny", "permitir", "negar" };

    /// <summary>
    /// Quebra a tabela do PowerShell em colunas. Formato esperado (Format-Table):
    /// <c>Name  ScopeName  AccountName  AccessControlType  AccessRight</c>. Linhas de cabeçalho,
    /// separador e mensagens de erro são descartadas por não terem colunas suficientes.
    /// </summary>
    private static IEnumerable<Row> ParseRows(string output)
    {
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("----") || line.StartsWith("Name ")) continue;

            var cols = line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (cols.Length < 5) continue;

            // A conta pode conter espaço ("Authenticated Users"): as duas últimas colunas são
            // sempre AccessControlType e AccessRight; a primeira é o nome do share.
            var share = cols[0];
            var right = cols[^1];
            var type = cols[^2];
            if (!AccessTypes.Contains(type, StringComparer.OrdinalIgnoreCase)) continue;

            var account = string.Join(' ', cols[2..^2]);
            if (account.Length == 0) continue;

            var allow = type.Equals("allow", StringComparison.OrdinalIgnoreCase)
                     || type.Equals("permitir", StringComparison.OrdinalIgnoreCase);
            yield return new Row(share, account, allow, right);
        }
    }
}

/// <summary>
/// Uma subcategoria de auditoria do Windows, com os nomes em inglês e português e o comando que a
/// liga. Existe como tipo — em vez de string solta — porque a distinção entre elas é sutil e já
/// causou um diagnóstico errado.
/// </summary>
/// <param name="English">Nome exato em inglês, como o auditpol imprime.</param>
/// <param name="Portuguese">Nome exato em português.</param>
/// <param name="Event">Evento que ela habilita (para a mensagem ao admin).</param>
/// <param name="Guid">GUID da subcategoria — o mesmo em qualquer idioma do Windows; é por ele que o produto consulta e liga.</param>
public sealed record AuditSubcategory(string English, string Portuguese, string Event, string Guid)
{
    /// <summary>
    /// Gera o <b>5145</b>: um evento por <b>arquivo</b> acessado num share, com IP de origem. É o
    /// que permite ver criptografia em massa vinda pela rede — o ponto cego do EDR.
    /// </summary>
    public static readonly AuditSubcategory DetailedFileShare =
        new("Detailed File Share", "Compartilhamento de Arquivos Detalhado", "5145", "{0CCE9244-69AE-11D9-BED3-505054503030}");

    /// <summary>
    /// Gera o <b>5140</b>: um evento por <b>conexão</b> ao share. Não serve para detectar
    /// criptografia em massa — cem mil arquivos cifrados numa sessão produzem um único 5140.
    /// </summary>
    public static readonly AuditSubcategory FileShare =
        new("File Share", "Compartilhamento de Arquivos", "5140", "{0CCE9224-69AE-11D9-BED3-505054503030}");

    /// <summary>Gera o <b>4663</b>, mas só em pastas com SACL configurada.</summary>
    public static readonly AuditSubcategory FileSystem =
        new("File System", "Sistema de Arquivos", "4663", "{0CCE921D-69AE-11D9-BED3-505054503030}");

    /// <summary>Gera o <b>4688</b>: criação de processo.</summary>
    public static readonly AuditSubcategory ProcessCreation =
        new("Process Creation", "Criação de Processo", "4688", "{0CCE922B-69AE-11D9-BED3-505054503030}");

    /// <summary>Argumentos do <c>auditpol.exe</c> para ligar a auditoria de sucesso.</summary>
    public string EnableArguments => $"/set /subcategory:{Guid} /success:enable";

    /// <summary>O comando por extenso, para mostrar ao administrador (o nome só serve de legenda).</summary>
    public string EnableCommand => $"auditpol {EnableArguments}";
}

/// <summary>
/// Lê a saída do <c>auditpol /get</c>. Sem auditoria o Windows não emite 5145/4663 e o produto fica
/// cego, por mais correto que o resto esteja — por isso esta checagem é ao mesmo tempo um item do
/// Score e um pré-requisito da detecção.
///
/// O casamento é pelo nome <b>completo</b> da subcategoria, e não por "contém": "File Share" é
/// prefixo de "Detailed File Share" (e o mesmo vale em português). Casar frouxo faz o produto
/// responder "auditoria ligada" enquanto o evento de que ele depende segue desligado — que foi
/// exatamente o que aconteceu na primeira validação em máquina real.
/// </summary>
public static class AuditPolicyReader
{
    /// <summary>Palavras que indicam auditoria de SUCESSO ligada (PT e EN).</summary>
    private static readonly string[] SuccessWords = { "success", "êxito", "exito" };

    /// <returns>
    /// <c>true</c>/<c>false</c> quando a subcategoria aparece na saída; <c>null</c> quando não deu
    /// para ler (auditpol ausente, sem permissão) ou a subcategoria não está na saída.
    /// </returns>
    public static bool? TryRead(string? auditpolOutput, AuditSubcategory subcategory)
    {
        if (string.IsNullOrWhiteSpace(auditpolOutput)) return null;

        foreach (var raw in auditpolOutput.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;

            // A linha é "<Subcategoria><espaços><Configuração>". Duas ou mais colunas separadas
            // por 2+ espaços é o que o auditpol produz.
            var cols = line.Split("  ", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (cols.Length < 2) continue;

            var nome = cols[0];
            if (!Matches(nome, subcategory)) continue;

            var setting = cols[^1];
            if (IsHeader(setting)) continue;

            // "Success", "Success and Failure" e "Êxito e Falha" contam; "Failure" e "No Auditing" não.
            return SuccessWords.Any(w => setting.Contains(w, StringComparison.OrdinalIgnoreCase));
        }
        return null;
    }

    /// <summary>
    /// Interpreta o valor que a API de auditoria do Windows devolve para uma subcategoria: bit 1 = sucesso, bit 2 =
    /// falha. Só o sucesso interessa — é o acesso bem-sucedido que o produto precisa ver.
    /// </summary>
    public static bool IsSuccess(uint auditingInformation) => (auditingInformation & 1) == 1;

    /// <summary>Igualdade exata — nunca "contém", pelo motivo explicado na classe.</summary>
    private static bool Matches(string nome, AuditSubcategory s) =>
        nome.Equals(s.English, StringComparison.OrdinalIgnoreCase) ||
        nome.Equals(s.Portuguese, StringComparison.OrdinalIgnoreCase);

    private static bool IsHeader(string setting) =>
        setting.Equals("Setting", StringComparison.OrdinalIgnoreCase) ||
        setting.StartsWith("Configura", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Confere se os arquivos-canário estão realmente plantados nas pastas protegidas. Antes desta
/// fatia o valor era fixo em <c>false</c>, então o Score acusava "sem canários" mesmo depois de o
/// produto plantá-los — e o admin não via a nota subir ao fazer a coisa certa.
/// </summary>
public static class CanaryPresence
{
    /// <param name="protectedPaths">Pastas configuradas para proteção.</param>
    /// <param name="listFiles">Lista os nomes de arquivo de uma pasta (injetado para teste).</param>
    /// <returns><c>null</c> quando não há pasta configurada ou a listagem falhou.</returns>
    public static bool? Evaluate(
        IReadOnlyCollection<string> protectedPaths,
        Func<string, IReadOnlyList<string>> listFiles,
        IReadOnlyList<string>? names = null)
    {
        // Sem pasta protegida não há o que afirmar — nem que tem, nem que falta.
        if (protectedPaths.Count == 0) return null;

        try
        {
            foreach (var path in protectedPaths)
            {
                var presentes = listFiles(path);
                var esperados = names is { Count: > 0 } ? names : CanaryPlan.NamesFor(path);   // B4: nomes desta instalação
                // Uma pasta descoberta já basta: o buraco está aberto ali.
                if (!esperados.All(e => presentes.Any(p => p.Equals(e, StringComparison.OrdinalIgnoreCase))))
                    return false;
            }
            return true;
        }
        catch (Exception)
        {
            // Sem permissão ou pasta inacessível: desconhecido, não "está ruim".
            return null;
        }
    }
}

/// <summary>G2 — lê o tamanho máximo do Security log na saída de <c>wevtutil gl Security</c> (linha <c>maxSize: N</c>).</summary>
public static class SecurityLogReader
{
    public static long? TryReadMaxBytes(string? wevtutilOutput)
    {
        if (string.IsNullOrWhiteSpace(wevtutilOutput)) return null;
        foreach (var raw in wevtutilOutput.Split('\n'))
        {
            var line = raw.Trim();
            if (!line.StartsWith("maxSize:", StringComparison.OrdinalIgnoreCase)) continue;
            return long.TryParse(line["maxSize:".Length..].Trim(), out var n) ? n : null;
        }
        return null;
    }
}

/// <summary>G3 — a auditoria 'Process Creation' precisa de duas coisas: a subcategoria ligada e a linha de comando incluída
/// (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1).</summary>
public static class ProcessAuditReader
{
    public static readonly AuditSubcategory ProcessCreation = AuditSubcategory.ProcessCreation;
    /// <summary>Liga a inclusão da linha de comando no 4688 (a subcategoria em si é ligada pelo GUID, fora do PowerShell).</summary>
    public const string EnableCommandLineScript = "New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Force | Out-Null; "
        + "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord";

    /// <summary>true só se a subcategoria está ligada E a linha de comando está incluída; null quando não dá para saber.</summary>
    public static bool? TryRead(string? auditpolOutput, string? includeCmdLineValue)
    {
        var sub = AuditPolicyReader.TryRead(auditpolOutput, ProcessCreation);
        if (sub is null) return null;
        if (sub == false) return false;
        return int.TryParse((includeCmdLineValue ?? "").Trim(), out var v) ? v == 1 : null;
    }
}
