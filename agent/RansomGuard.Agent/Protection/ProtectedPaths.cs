namespace RansomGuard.Agent.Protection;

/// <summary>Um caminho recusado e o motivo, para o admin corrigir a configuração.</summary>
public sealed record RejectedPath(string Path, string Reason);

/// <summary>Resultado da leitura da configuração de pastas protegidas.</summary>
public sealed record ProtectedPathSet(IReadOnlyList<string> Accepted, IReadOnlyList<RejectedPath> Rejected);

/// <summary>
/// Decide **onde** o produto pode agir. F12 é a primeira fatia em que o RansomGuard escreve no
/// ambiente do cliente (planta canários, aplica file screen), então esta é a porta que impede que
/// um erro de digitação numa GPO vire incidente no parque inteiro.
///
/// Lógica pura: entra a string de configuração, sai a lista do que foi aceito e do que foi recusado
/// com o motivo. Nada é silenciosamente descartado — o admin precisa ver o que ignoramos.
/// </summary>
public static class ProtectedPaths
{
    /// <summary>
    /// Pastas do sistema. Plantar canário ou aplicar file screen aqui é dano, não proteção: atinge
    /// arquivos do Windows e de todos os aplicativos de uma vez.
    /// </summary>
    private static readonly string[] SystemFolders =
    {
        @"\windows", @"\program files", @"\program files (x86)", @"\programdata",
        @"\arquivos de programas"   // Windows antigo em português
    };

    public static ProtectedPathSet Parse(string? configured)
    {
        var accepted = new List<string>();
        var rejected = new List<RejectedPath>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in (configured ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var path = raw.TrimEnd('\\', '/');
            if (path.Length == 0) continue;

            var reason = Reject(path);
            if (reason is not null)
            {
                rejected.Add(new RejectedPath(raw, reason));
                continue;
            }

            // Duplicata silenciosa faria o produto plantar e reportar o mesmo lugar duas vezes.
            if (seen.Add(Normalize(path))) accepted.Add(path);
        }

        return new ProtectedPathSet(accepted, rejected);
    }

    /// <summary><c>null</c> = caminho aceito.</summary>
    private static string? Reject(string path)
    {
        // Um caminho de rede aponta para outro servidor. Quem protege aquele servidor é o agente
        // instalado nele — agir à distância esconderia de quem é a responsabilidade.
        if (path.StartsWith(@"\\") || path.StartsWith("//"))
            return "Caminho de rede: instale o agente no servidor de destino; quem protege aquele " +
                   "servidor é o agente dele.";

        if (!IsAbsolute(path))
            return "Caminho relativo: informe o caminho completo (ex.: D:\\Shares\\Financeiro).";

        // "C:" e "C:\" — a raiz inteira do volume.
        if (IsVolumeRoot(path))
            return "Raiz de volume: proteger o disco inteiro atingiria o sistema. Aponte a pasta " +
                   "de dados compartilhada.";

        var lower = path.ToLowerInvariant();
        var semDrive = lower.Length >= 2 && lower[1] == ':' ? lower[2..] : lower;
        if (SystemFolders.Any(f => semDrive == f || semDrive.StartsWith(f + "\\")))
            return "Pasta de sistema: plantar canário ou aplicar file screen aqui seria dano, não " +
                   "proteção.";

        return null;
    }

    private static bool IsAbsolute(string path) =>
        path.Length >= 2 && char.IsLetter(path[0]) && path[1] == ':';

    private static bool IsVolumeRoot(string path) =>
        path.Length == 2 && path[1] == ':';

    private static string Normalize(string path) => path.ToLowerInvariant().TrimEnd('\\', '/');
}

/// <summary>Quanto da defesa está realmente de pé neste servidor.</summary>
public enum ProtectionMode
{
    /// <summary>Nada preparado: sem pastas configuradas ou sem canário plantado.</summary>
    None,
    /// <summary>Canários plantados; sem FSRM (Windows client ou servidor sem a role).</summary>
    CanaryOnly,
    /// <summary>Canários + FSRM auditando (padrão): registra a violação, não bloqueia.</summary>
    CanaryAndAudit,
    /// <summary>Canários + FSRM bloqueando a gravação — escolha explícita do admin.</summary>
    CanaryAndBlock
}

/// <param name="Mode">Modo efetivo.</param>
/// <param name="Explanation">O que está e o que não está ativo, em português, para o painel.</param>
public sealed record ProtectionStatusResult(ProtectionMode Mode, string Explanation);

/// <summary>
/// Traduz o estado real das defesas em algo que o admin possa ler. Reportar "protegido" quando só
/// metade está de pé é o mesmo pecado da nota mentirosa: parece completo sem ser. Aqui o produto
/// **arredonda para baixo** e explica o que falta.
/// </summary>
public static class ProtectionStatus
{
    public static ProtectionStatusResult Evaluate(
        int protectedPaths, int canariesPlanted, bool fsrmAvailable, bool fsrmActive)
    {
        if (protectedPaths == 0)
            return new(ProtectionMode.None,
                "Nenhuma pasta protegida configurada — o produto não sabe onde plantar canário nem " +
                "o que vigiar de perto. Defina as pastas na instalação (PROTECTEDPATHS) ou no registro.");

        if (canariesPlanted == 0)
            return new(ProtectionMode.None,
                "Pastas configuradas, mas nenhum canário plantado. O canário é o sinal de maior " +
                "confiança do produto: sem ele, a detecção depende só de volume e ritmo.");

        if (!fsrmAvailable)
            return new(ProtectionMode.CanaryOnly,
                $"{canariesPlanted} canário(s) em {protectedPaths} pasta(s). O FSRM não está " +
                "disponível neste servidor (Windows client ou role de File Server ausente), então " +
                "extensões conhecidas de ransomware não são bloqueadas — a detecção segue por " +
                "canário, volume e ritmo.");

        return fsrmActive
            ? new(ProtectionMode.CanaryAndBlock,
                $"{canariesPlanted} canário(s) em {protectedPaths} pasta(s) e FSRM **bloqueando** " +
                "extensões do catálogo.")
            : new(ProtectionMode.CanaryAndAudit,
                $"{canariesPlanted} canário(s) em {protectedPaths} pasta(s) e FSRM em **auditoria** " +
                "(registra a violação sem bloquear). Ative o bloqueio quando estiver confiante.");
    }
}
