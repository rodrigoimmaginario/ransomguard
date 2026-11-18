namespace RansomGuard.Core.Detection;

/// <summary>Uma troca de extensão observada: o arquivo original e a extensão com que ele reapareceu.</summary>
public readonly record struct ExtensionChange(string File, string NewExtension);

/// <summary>
/// D2 — trocas de extensão OBSERVADAS num conjunto de eventos de um mesmo ator.
///
/// O que o Windows entrega de verdade (visto na CI, Windows Server 2025): cada gravação traz o nome do arquivo
/// gravado; renomear e apagar trazem só o nome ANTIGO. Nenhum evento diz "de .xlsx para .locked". Por isso a troca
/// só existe quando as duas pontas aparecem:
/// <list type="bullet">
///   <item>um arquivo gravado cujo nome é o de outro, apagado ou renomeado pelo mesmo ator, com a extensão
///   acrescentada (<c>rel.xlsx</c> → <c>rel.xlsx.locked</c>) ou substituída (<c>rel.xlsx</c> → <c>rel.locked</c>),
///   na mesma pasta;</item>
///   <item>ou um evento que já traz o nome antigo e a extensão nova (fontes que conhecem o destino).</item>
/// </list>
/// Limite conhecido: quem cifra no lugar e só renomeia deixa apenas a ponta antiga — não é visto aqui; é pego por
/// volume, pelo canário e, quando a extensão é conhecida, pelo file screen.
/// </summary>
public static class ExtensionChanges
{
    public static IReadOnlyList<ExtensionChange> Observed(IEnumerable<FileEvent> events)
    {
        var list = events as IReadOnlyCollection<FileEvent> ?? events.ToList();
        var comparer = StringComparer.OrdinalIgnoreCase;

        // Nomes antigos que o ator apagou ou renomeou — por caminho inteiro e por "pasta + nome sem extensão".
        var removed = new HashSet<string>(comparer);
        var removedByStem = new Dictionary<string, string>(comparer);
        foreach (var e in list)
        {
            if (e.Op is not (FileOp.Delete or FileOp.Rename)) continue;
            removed.Add(e.Path);
            var ext = Path.GetExtension(e.Path);
            if (ext.Length > 1) removedByStem.TryAdd(e.Path[..^ext.Length], e.Path);
        }

        var seen = new HashSet<string>(comparer);
        var changes = new List<ExtensionChange>();
        void Add(string file, string newExtension)
        {
            if (seen.Add(file)) changes.Add(new ExtensionChange(file, newExtension));
        }

        foreach (var e in list)
        {
            if (e.Op is not (FileOp.Write or FileOp.Rename) || e.NewExtension is not { Length: > 1 } declared) continue;
            var own = Path.GetExtension(e.Path);

            // O evento traz o nome antigo e a extensão nova.
            if (!comparer.Equals(own, declared)) { Add(e.Path, declared); continue; }
            if (e.Op != FileOp.Write) continue;

            // Extensão acrescentada: "rel.xlsx.locked" gravado e "rel.xlsx" apagado.
            var withoutExt = e.Path[..^own.Length];
            if (removed.Contains(withoutExt) && Path.GetExtension(withoutExt).Length > 1) { Add(withoutExt, own); continue; }

            // Extensão substituída: "rel.locked" gravado e "rel.xlsx" apagado, mesma pasta e mesmo nome.
            if (removedByStem.TryGetValue(withoutExt, out var original) && !comparer.Equals(original, e.Path))
                Add(original, own);
        }
        return changes;
    }
}

/// <summary>
/// Extensões de trabalho legítimo. Nunca entram sozinhas num file screen: bloquear <c>.dwg</c> ou <c>.sql</c> num
/// servidor de arquivos é o produto virando o incidente. A lista é ampla de propósito — o custo de deixar de
/// aprender uma extensão é pequeno (o catálogo assinado e os outros sinais continuam valendo); o de bloquear trabalho
/// é alto.
/// </summary>
public static class LegitExtensions
{
    private static readonly HashSet<string> Known = new(StringComparer.OrdinalIgnoreCase)
    {
        // Escritório e texto
        ".doc", ".docx", ".docm", ".dot", ".dotx", ".xls", ".xlsx", ".xlsm", ".xlsb", ".xlt", ".xltx", ".ppt", ".pptx", ".pptm", ".pps", ".ppsx",
        ".odt", ".ods", ".odp", ".rtf", ".txt", ".csv", ".tsv", ".pdf", ".xps", ".md", ".one", ".vsd", ".vsdx", ".mpp", ".pub", ".msg", ".eml",
        ".pst", ".ost", ".pages", ".numbers", ".key", ".epub",
        // Imagem, desenho e editoração
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".svg", ".ico", ".heic", ".raw", ".cr2", ".nef", ".dng",
        ".psd", ".psb", ".ai", ".eps", ".indd", ".idml", ".cdr", ".xcf", ".sketch", ".fig",
        // CAD, engenharia e 3D
        ".dwg", ".dxf", ".dwt", ".dgn", ".rvt", ".rfa", ".ifc", ".skp", ".stl", ".step", ".stp", ".iges", ".igs", ".sldprt", ".sldasm", ".slddrw",
        ".ipt", ".iam", ".3ds", ".max", ".blend", ".obj", ".fbx", ".nwd", ".pln",
        // Áudio e vídeo
        ".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a", ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".webm", ".m4v", ".mpg", ".mpeg",
        // Dados e bancos
        ".sql", ".mdf", ".ndf", ".ldf", ".bak", ".trn", ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".dbf", ".fdb", ".gdb", ".dmp", ".parquet",
        ".json", ".xml", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".config", ".log", ".dat", ".bin",
        // Compactados, imagens de disco e máquinas virtuais
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".ova", ".ovf", ".qcow2", ".wim",
        // Código e web
        ".cs", ".vb", ".java", ".py", ".js", ".ts", ".jsx", ".tsx", ".html", ".htm", ".css", ".php", ".rb", ".go", ".rs", ".c", ".h", ".cpp", ".hpp",
        ".ps1", ".psm1", ".bat", ".cmd", ".sh", ".sln", ".csproj", ".resx",
        // Sistema, temporários e instaladores
        ".tmp", ".temp", ".old", ".bkp", ".lnk", ".url", ".exe", ".dll", ".msi", ".msp", ".sys", ".inf", ".cat", ".ttf", ".otf", ".pfx", ".cer", ".crt",
        // Fiscal e contábil (uso comum em servidores de arquivos no Brasil)
        ".ofx", ".rem", ".ret", ".sped", ".p7s"
    };

    public static bool Contains(string? extension) => !string.IsNullOrEmpty(extension) && Known.Contains(extension);
}
