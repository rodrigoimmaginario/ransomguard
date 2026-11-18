using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Sensors;

/// <summary>Um share de disco publicado pelo servidor: nome e pasta local.</summary>
public sealed record ShareEntry(string Name, string LocalPath);

/// <summary>
/// D1 — dá a cada evento de arquivo UM nome de share, na forma que o motor, a escada de resposta e
/// a configuração de shares-isca usam: <c>\\SERVIDOR\Share</c>.
///
/// O Windows descreve o mesmo arquivo de três jeitos: pelo nome do share (5145), pelo caminho local
/// (4663) e pelo share administrativo quando quem acessa é admin (<c>C$</c>). Tratar cada um como um
/// "share" diferente espalha a contagem de um ataque por vários atores e entrega à contenção um nome
/// que não existe. Aqui todos convergem: o caminho local completo é casado com o share publicado
/// mais específico que o contém.
///
/// Lógica pura; a tabela de shares vem do serviço (registro do LanmanServer).
/// </summary>
public sealed class ShareMap
{
    private readonly string _server;
    private readonly List<ShareEntry> _shares;   // do caminho mais longo para o mais curto

    public ShareMap(string server, IEnumerable<ShareEntry> shares)
    {
        _server = server.Trim().TrimStart('\\');
        _shares = shares
            .Select(s => new ShareEntry(s.Name.Trim(), TrimPath(s.LocalPath)))
            .Where(s => s.Name.Length > 0 && s.LocalPath.Length > 0)
            .OrderByDescending(s => s.LocalPath.Length)
            .ToList();
    }

    public string Server => _server;
    public IReadOnlyList<ShareEntry> Shares => _shares;

    public string Unc(string shareName) => $@"\\{_server}\{shareName}";

    /// <summary>Devolve o evento com <c>Share</c> canônico e <c>Path</c> relativo à raiz desse share.</summary>
    public FileEvent Canonicalize(ParsedFileEvent parsed)
    {
        var e = parsed.Event;

        if (!string.IsNullOrWhiteSpace(parsed.LocalFullPath))
        {
            var full = parsed.LocalFullPath!.Trim();
            foreach (var share in _shares)
                if (TryRelative(share.LocalPath, full, out var relative))
                    return e with { Share = Unc(share.Name), Path = relative };
        }

        // Tabela indisponível ou share não listado (ex.: administrativo sem share publicado por cima): o nome basta.
        if (!string.IsNullOrWhiteSpace(parsed.ShareName))
            return e with { Share = Unc(parsed.ShareName!.Trim()) };

        // Objeto local fora de qualquer share: a pasta completa é a identidade (só o último nome colidiria
        // entre pastas diferentes). A contenção por share não se aplica a ela, e o porteiro de alvos a recusa.
        if (!string.IsNullOrWhiteSpace(parsed.LocalFullPath))
        {
            var full = parsed.LocalFullPath!.Trim();
            var slash = full.LastIndexOf('\\');
            if (slash > 0) return e with { Share = full[..slash], Path = full[(slash + 1)..] };
        }
        return e;
    }

    /// <summary>
    /// Aceita o que o admin digitar para um share (UNC com qualquer nome de servidor, ou só o nome) e
    /// devolve a forma canônica deste servidor. Vazio → <c>null</c>.
    /// </summary>
    public string? NormalizeConfigured(string? configured)
    {
        var v = (configured ?? "").Trim().TrimEnd('\\');
        if (v.Length == 0) return null;
        var name = v;
        if (v.StartsWith(@"\\", StringComparison.Ordinal))
        {
            var parts = v.TrimStart('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) return null;
            name = parts[1];
        }
        return Unc(name);
    }

    /// <summary>
    /// Lê os shares de disco de <c>HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares</c>: cada valor é um
    /// REG_MULTI_SZ com linhas <c>Chave=valor</c>. Sem processo auxiliar, sem depender do idioma do Windows.
    /// </summary>
    public static IReadOnlyList<ShareEntry> ParseLanmanShares(IEnumerable<KeyValuePair<string, string[]>> registryValues)
    {
        var list = new List<ShareEntry>();
        foreach (var (name, lines) in registryValues)
        {
            string? path = null; var type = "0";
            foreach (var line in lines ?? Array.Empty<string>())
            {
                var eq = line.IndexOf('=');
                if (eq <= 0) continue;
                var key = line[..eq].Trim();
                var value = line[(eq + 1)..].Trim();
                if (key.Equals("Path", StringComparison.OrdinalIgnoreCase)) path = value;
                else if (key.Equals("Type", StringComparison.OrdinalIgnoreCase)) type = value;
            }
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(path) || type != "0") continue;   // 0 = disco
            list.Add(new ShareEntry(name.Trim(), path!));
        }
        return list;
    }

    private static string TrimPath(string path) => path.Trim().TrimEnd('\\');

    /// <summary>O arquivo está sob a raiz? Só em fronteira de pasta: <c>D:\Fin</c> não contém <c>D:\Financeiro\x</c>.</summary>
    private static bool TryRelative(string root, string full, out string relative)
    {
        relative = "";
        if (full.Length <= root.Length + 1) return false;
        if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase) || full[root.Length] != '\\') return false;
        relative = full[(root.Length + 1)..];
        return relative.Length > 0;
    }
}
