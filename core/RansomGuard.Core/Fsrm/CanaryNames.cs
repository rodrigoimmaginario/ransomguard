using System.Security.Cryptography;
using System.Text;

namespace RansomGuard.Core.Fsrm;

/// <summary>
/// B4 — nomes de canário por instalação. Derivados de uma semente que só existe no servidor monitorado, com cara
/// de documento de trabalho e sem nada que identifique o produto.
///
/// Limite honesto: o gerador é público. Quem escreve ransomware pode reconhecer o FORMATO destes nomes e pular
/// tudo o que se pareça com eles — ao custo de deixar de cifrar arquivos reais com nome parecido. Nomes que só o
/// administrador conhece (<see cref="Parse"/>, opção <c>Agent:CanaryNames</c>) não têm esse limite.
/// </summary>
public static class CanaryNames
{
    /// <summary>
    /// Primeiro caractere de cada nome: "!" ordena antes de dígitos e letras, "~" depois de tudo, "_" logo após as
    /// letras maiúsculas — uma varredura alfabética encontra um canário cedo, no meio e no fim. ("~" seguido de letra,
    /// nunca "~$", que é o prefixo dos temporários do Office e costuma ser pulado.)
    /// </summary>
    private static readonly char[] Anchors = { '!', '_', '~' };

    private static readonly string[] Subjects =
    {
        "Orcamento", "Relatorio", "Planilha", "Contrato", "Cadastro", "Inventario", "Balancete", "Proposta", "Cronograma",
        "Indice", "Controle", "Resumo", "Ata", "Parecer", "Fechamento", "Conciliacao", "Folha", "Projecao", "Laudo",
        "Memorial", "Levantamento", "Demonstrativo", "Quadro", "Acompanhamento"
    };

    private static readonly string[] Qualifiers =
    {
        "consolidado", "revisado", "final", "anual", "geral", "aprovado", "preliminar", "atualizado", "mensal",
        "diretoria", "auditoria", "fiscal"
    };

    /// <summary>Nove nomes (três posições de ordenação × três extensões), sempre os mesmos para a mesma semente.</summary>
    public static IReadOnlyList<string> Generate(byte[] seed)
    {
        if (seed.Length < 16) throw new ArgumentException("A semente dos nomes precisa de pelo menos 16 bytes.", nameof(seed));
        var names = new List<string>();
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var slot = 0;
        foreach (var anchor in Anchors)
            foreach (var ext in CanaryPlan.Extensions)
            {
                for (var attempt = 0; ; attempt++)
                {
                    var b = HMACSHA256.HashData(seed, Encoding.UTF8.GetBytes($"canary-name/{slot}/{attempt}"));
                    var name = $"{anchor}{Subjects[b[0] % Subjects.Length]} {2015 + b[1] % 10} - {Qualifiers[b[2] % Qualifiers.Length]} "
                               + $"{(char)('A' + b[3] % 26)}{(char)('A' + b[4] % 26)} v{1 + b[5] % 9}{ext}";
                    if (!used.Add(name)) continue;
                    names.Add(name);
                    break;
                }
                slot++;
            }
        return names;
    }

    /// <summary>
    /// Conteúdo de um canário desta instalação: bytes que só a semente reproduz, com o início que o tipo de arquivo
    /// teria. Duas funções: o arquivo não traz texto que identifique o produto (o texto fixo das versões anteriores
    /// seria reconhecido por qualquer um que lesse o código), e é pelo conteúdo — não pelo nome — que o produto
    /// reconhece o que é dele na hora de apagar. Um arquivo do cliente com o mesmo nome nunca confere.
    /// O arquivo não abre no programa do tipo; é isca, não documento.
    /// </summary>
    public static byte[] ContentFor(byte[] seed, string name)
    {
        var id = Encoding.UTF8.GetBytes("canary-content/" + name.ToUpperInvariant());
        var first = HMACSHA256.HashData(seed, id);
        var length = 12_000 + (first[0] << 8 | first[1]) % 48_000;            // 12 a 60 KB: tamanho de documento pequeno
        var content = new byte[length];
        var offset = 0;
        for (var counter = 0; offset < length; counter++)
        {
            var block = HMACSHA256.HashData(seed, id.Concat(BitConverter.GetBytes(counter)).ToArray());
            var take = Math.Min(block.Length, length - offset);
            Array.Copy(block, 0, content, offset, take);
            offset += take;
        }
        var magic = Path.GetExtension(name).ToLowerInvariant() switch
        {
            ".pdf" => "%PDF-1.7\n"u8.ToArray(),
            ".docx" or ".xlsx" or ".pptx" or ".zip" => new byte[] { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00 },
            _ => Array.Empty<byte>()
        };
        Array.Copy(magic, content, magic.Length);
        return content;
    }

    /// <summary>Lista informada pelo administrador (separada por ponto e vírgula): só nomes de arquivo válidos, sem repetição.</summary>
    public static IReadOnlyList<string> Parse(string? configured)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        return (configured ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(n => IsValidFileName(n) && seen.Add(n)).ToList();
    }

    private static readonly char[] Forbidden = { '\\', '/', ':', '*', '?', '"', '<', '>', '|' };
    private static readonly HashSet<string> Reserved = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    /// <summary>Um nome de arquivo — sem pasta, sem caractere proibido no Windows, sem nome reservado.</summary>
    public static bool IsValidFileName(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > 120) return false;
        if (name.IndexOfAny(Forbidden) >= 0 || name.Any(char.IsControl)) return false;
        if (name[^1] is ' ' or '.') return false;
        var stem = name.Split('.')[0];
        return stem.Length > 0 && !Reserved.Contains(stem.Trim());
    }
}
