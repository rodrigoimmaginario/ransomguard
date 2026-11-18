namespace RansomGuard.Core.Fsrm;

/// <summary>
/// Define os arquivos-canário plantados num share. Nomes escolhidos para ordenar no início e no
/// fim de uma listagem (é por onde o ransomware costuma varrer), aumentando a chance de o canário
/// ser tocado cedo. Lógica pura: decide os nomes; o plantio real e a SACL ficam no serviço/spike.
/// </summary>
public static class CanaryPlan
{
    /// <summary>Prefixos que garantem posições extremas na ordenação alfabética do diretório.</summary>
    /// <remarks>
    /// G1: na ordenação do NTFS (case-insensitive por code unit), "!" (0x21) vem antes de dígitos e letras — é o
    /// primeiro arquivo que uma varredura alfabética encontra; "~" (0x7E) é o último printável ASCII — depois de "_" e
    /// de qualquer letra. Três âncoras: início absoluto, logo após as letras, fim absoluto. (Canários "zzz_" de versões
    /// anteriores continuam reconhecidos pela marca e são removidos normalmente.)
    /// </remarks>
    public static readonly IReadOnlyList<string> Anchors = new[] { "!0_", "_aaa", "~zz_" };

    /// <summary>Extensões que imitam documentos reais para não denunciar o canário.</summary>
    public static readonly IReadOnlyList<string> Extensions = new[] { ".docx", ".xlsx", ".pdf" };

    /// <summary>Gera os nomes de canário para um share (determinístico).</summary>
    public static IReadOnlyList<string> NamesFor(string share)
    {
        var names = new List<string>();
        foreach (var anchor in Anchors)
            foreach (var ext in Extensions)
                names.Add($"{anchor}_ransomguard_canary{ext}");
        return names;
    }

    /// <summary>Marca dos canários de versões anteriores. Nome fixo e autoidentificado: ainda reconhecido, não mais plantado.</summary>
    public const string LegacyMarker = "_ransomguard_canary";

    // B4: nomes desta instalação (do manifesto local). Só cresce — reconhecer um nome a mais nunca faz mal, e os
    // analisadores de evento, que são estáticos, consultam daqui.
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> Known = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Passa a reconhecer estes nomes de arquivo como canários desta instalação.</summary>
    public static void Recognize(IEnumerable<string> names)
    {
        foreach (var name in names)
            if (!string.IsNullOrWhiteSpace(name)) Known.TryAdd(name.Trim(), 0);
    }

    /// <summary>true se o nome é de um canário de versão anterior (os que o plantio com nomes novos retira).</summary>
    public static bool IsLegacy(string path) =>
        System.IO.Path.GetFileName(path).Contains(LegacyMarker, StringComparison.OrdinalIgnoreCase);

    /// <summary>true se o caminho corresponde a um canário plantado (usado pelo coletor de eventos).</summary>
    public static bool IsCanary(string path)
    {
        // O nome vem de eventos do Windows, com "\" — não depende do separador do sistema em que o código roda.
        var cut = path.LastIndexOfAny(new[] { '\\', '/' });
        var file = cut >= 0 ? path[(cut + 1)..] : path;
        return file.Contains(LegacyMarker, StringComparison.OrdinalIgnoreCase) || Known.ContainsKey(file);
    }
}
