using RansomGuard.Core.Fsrm;

namespace RansomGuard.Agent.Protection;

/// <summary>Resultado do plantio numa pasta.</summary>
/// <param name="Path">Pasta.</param>
/// <param name="Planted">Canários criados agora.</param>
/// <param name="AlreadyPresent">Canários que já existiam (idempotência).</param>
/// <param name="Error">Motivo da falha, quando a pasta inteira não pôde ser tratada.</param>
/// <param name="Unaudited">Canários sem regra de auditoria (D4): um processo LOCAL que os toque não gera evento.</param>
public sealed record CanaryResult(string Path, int Planted, int AlreadyPresent, string? Error = null, int Unaudited = 0)
{
    public bool Ok => Error is null;
    public int Total => Planted + AlreadyPresent;
    /// <summary>B4: nomes de canário ocupados por um arquivo que NÃO é do produto (não foi sobrescrito nem conta como canário).</summary>
    public int Collisions { get; init; }
}

/// <summary>
/// B4 — os canários de uma instalação: os nomes e o conteúdo que cada um deve ter. O conteúdo é o que prova que um
/// arquivo é do produto; o nome sozinho não autoriza apagar nada.
/// </summary>
public sealed record CanarySet(IReadOnlyList<string> Names, Func<string, byte[]> ContentFor);

/// <summary>
/// Operações de arquivo que o plantio precisa. Abstraído para a decisão ficar testável sem disco —
/// e para o teste de integração real exercitar a implementação verdadeira.
/// </summary>
public interface ICanaryFileSystem
{
    bool DirectoryExists(string path);
    IReadOnlyList<string> ListFiles(string path);
    /// <summary>G1: subpastas imediatas (caminho completo). Padrão vazio mantém implementações antigas válidas.</summary>
    IReadOnlyList<string> ListDirectories(string path) => Array.Empty<string>();
    void WriteCanary(string fullPath, string content);
    /// <summary>B4: grava o canário com conteúdo binário. Padrão delega ao texto (implementações antigas e testes).</summary>
    void WriteCanary(string fullPath, byte[] content) => WriteCanary(fullPath, System.Text.Encoding.Latin1.GetString(content));
    /// <summary>B4: o arquivo tem exatamente este conteúdo? Padrão "não sei dizer" = falso: na dúvida, não é do produto.</summary>
    bool ContentEquals(string fullPath, byte[] expected) => false;
    void Delete(string fullPath);
    /// <summary>
    /// D4: garante a regra de auditoria (SACL) no canário, sem regravar o conteúdo. É ela que faz o Windows registrar o
    /// evento de objeto (4663, com o processo) quando alguém mexe no arquivo a partir do próprio servidor — o evento de
    /// share só cobre o acesso pela rede. Padrão sem efeito mantém implementações antigas e os testes válidos.
    /// </summary>
    void EnsureAudited(string fullPath) { }
}

/// <summary>
/// Planta e remove os arquivos-canário. É a primeira coisa que o produto **escreve** no ambiente do
/// cliente, então três propriedades são inegociáveis:
///
/// <list type="number">
///   <item><b>Idempotente</b> — rodar N vezes deixa o mesmo resultado. O agente roda em ciclo; um
///   plantio que reescrevesse o arquivo a cada volta mudaria o timestamp sem parar e poluiria o
///   backup incremental do cliente.</item>
///   <item><b>Reversível</b> — a remoção apaga <b>somente</b> arquivos com a marca do produto.
///   Nunca varre a pasta.</item>
///   <item><b>Isolado por pasta</b> — uma pasta sem permissão não impede as outras. Meia proteção
///   é melhor que nenhuma, desde que o admin saiba qual metade.</item>
/// </list>
/// </summary>
public sealed class CanaryPlanter
{
    private readonly ICanaryFileSystem _fs;
    private readonly CanarySet? _set;

    /// <param name="set">
    /// B4: canários desta instalação (nomes e conteúdo). Sem eles (testes, chamadas antigas) valem os nomes fixos e o
    /// texto das versões anteriores. Com eles, o plantio também retira os canários antigos que encontrar.
    /// </param>
    public CanaryPlanter(ICanaryFileSystem fs, CanarySet? set = null)
    {
        _fs = fs;
        _set = set is { Names.Count: > 0 } ? set : null;
        if (_set is not null) CanaryPlan.Recognize(_set.Names);
    }

    /// <summary>
    /// O arquivo é do produto? Canário de versão anterior traz a marca no nome (nenhum arquivo de cliente a tem). Os
    /// desta instalação só são reconhecidos pelo conteúdo: um arquivo do cliente que tenha o mesmo nome não confere.
    /// </summary>
    private bool IsOurs(string folder, string name)
    {
        if (CanaryPlan.IsLegacy(name)) return true;
        return _set is not null && CanaryPlan.IsCanary(name) && _fs.ContentEquals(Path.Combine(folder, name), _set.ContentFor(name));
    }

    /// <summary>
    /// Conteúdo do canário: inerte e autoexplicativo. Um admin que topar com o arquivo entende o
    /// que é sem precisar procurar. Nunca macro, nunca executável — o produto não pode introduzir
    /// no ambiente do cliente exatamente o tipo de arquivo de que ele se defende.
    /// </summary>
    public const string Content =
        "Arquivo-canário do RansomGuard.\r\n" +
        "\r\n" +
        "Serve de isca: ninguém tem motivo legítimo para abrir ou alterar este arquivo, então\r\n" +
        "qualquer acesso a ele é um sinal forte de que algo está varrendo esta pasta.\r\n" +
        "\r\n" +
        "Pode ser apagado sem risco — o agente replanta no próximo ciclo.\r\n";

    /// <summary>Profundidade de subpastas que também recebem canários (G1: canários densos).</summary>
    public const int SubdirectoryDepth = 2;
    /// <summary>Teto de subpastas por raiz — um share com 50 mil pastas não vira 300 mil canários.</summary>
    public const int MaxSubdirectoriesPerRoot = 200;

    /// <summary>
    /// Expande cada raiz com suas subpastas até <see cref="SubdirectoryDepth"/> (limitado por raiz). Ransomware varre
    /// diretório a diretório: um canário por pasta é tocado nos primeiros arquivos, não depois de milhares.
    /// </summary>
    public IReadOnlyList<string> ExpandWithSubdirectories(IEnumerable<string> roots) => Expand(roots, MaxSubdirectoriesPerRoot);

    /// <summary>
    /// As mesmas pastas, sem o teto: é o alcance da REMOÇÃO. Pastas criadas ou apagadas depois do plantio mudam quais
    /// cabem no teto, e reverter não pode deixar canário para trás por causa disso.
    /// </summary>
    public IReadOnlyList<string> ExpandForRemoval(IEnumerable<string> roots) => Expand(roots, int.MaxValue);

    private IReadOnlyList<string> Expand(IEnumerable<string> roots, int maxSubdirectoriesPerRoot)
    {
        var all = new List<string>();
        foreach (var root in roots)
        {
            all.Add(root);
            var budget = maxSubdirectoriesPerRoot;
            var frontier = new List<(string Path, int Depth)> { (root, 0) };
            while (frontier.Count > 0 && budget > 0)
            {
                var (dir, depth) = frontier[0]; frontier.RemoveAt(0);
                if (depth >= SubdirectoryDepth) continue;
                IReadOnlyList<string> subs;
                try { subs = _fs.DirectoryExists(dir) ? _fs.ListDirectories(dir) : Array.Empty<string>(); }
                catch (Exception) { continue; }    // pasta sem permissão não impede as outras
                foreach (var sub in subs)
                {
                    if (budget-- <= 0) break;
                    all.Add(sub);
                    frontier.Add((sub, depth + 1));
                }
            }
        }
        return all;
    }

    /// <summary>Planta os canários em cada pasta e nas subpastas (G1). Nunca lança: erros viram resultado.</summary>
    public IReadOnlyList<CanaryResult> Plant(IEnumerable<string> paths)
    {
        var results = new List<CanaryResult>();

        foreach (var path in ExpandWithSubdirectories(paths))
        {
            try
            {
                if (!_fs.DirectoryExists(path))
                {
                    results.Add(new CanaryResult(path, 0, 0, "Pasta não encontrada."));
                    continue;
                }

                var existentes = _fs.ListFiles(path);
                int plantados = 0, jaExistiam = 0, semAuditoria = 0, colisoes = 0;

                // B4: com canários próprios, saem da pasta os de versão anterior (nome fixo, que qualquer um reconhece)
                // e os de nomes que o administrador trocou — só os que são comprovadamente do produto.
                if (_set is not null)
                    foreach (var antigo in existentes.Where(f => CanaryPlan.IsCanary(f) && !_set.Names.Contains(f, StringComparer.OrdinalIgnoreCase)).ToList())
                    {
                        try { if (IsOurs(path, antigo)) _fs.Delete(Path.Combine(path, antigo)); }
                        catch (Exception) { /* fica; segue valendo como canário */ }
                    }

                foreach (var nome in _set?.Names ?? CanaryPlan.NamesFor(path))
                {
                    var completo = Path.Combine(path, nome);
                    // Idempotência: existir já basta. Não reescrevemos — mudar o timestamp a cada
                    // ciclo poluiria o backup incremental do cliente.
                    if (existentes.Any(f => f.Equals(nome, StringComparison.OrdinalIgnoreCase)))
                    {
                        // B4: o nome já existe, mas o arquivo é do cliente — não é canário, não é sobrescrito.
                        if (_set is not null && !_fs.ContentEquals(completo, _set.ContentFor(nome))) { colisoes++; continue; }
                        jaExistiam++;
                    }
                    else
                    {
                        if (_set is not null) _fs.WriteCanary(completo, _set.ContentFor(nome));
                        else _fs.WriteCanary(completo, Content);
                        plantados++;
                    }

                    // A auditoria é conferida também nos que já existiam (plantados por versão anterior, ou com a
                    // regra removida). Falhar aqui não desfaz o plantio: o canário segue valendo para acesso pela rede.
                    try { _fs.EnsureAudited(completo); }
                    catch (Exception) { semAuditoria++; }
                }

                results.Add(new CanaryResult(path, plantados, jaExistiam, Unaudited: semAuditoria) { Collisions = colisoes });
            }
            catch (Exception ex)
            {
                // Uma pasta problemática não pode impedir as demais.
                results.Add(new CanaryResult(path, 0, 0, ex.Message));
            }
        }

        return results;
    }

    /// <summary>
    /// Remove os canários das pastas e das subpastas em que o plantio entra. Apaga **somente** arquivos com a marca
    /// do produto — a pasta é do cliente, e uma remoção que varresse o diretório seria destruição de dados.
    /// </summary>
    public IReadOnlyList<CanaryResult> Remove(IEnumerable<string> paths)
    {
        var results = new List<CanaryResult>();

        foreach (var path in ExpandForRemoval(paths))
        {
            try
            {
                if (!_fs.DirectoryExists(path))
                {
                    results.Add(new CanaryResult(path, 0, 0, "Pasta não encontrada."));
                    continue;
                }

                var removidos = 0;
                // Snapshot antes de apagar: enumerar a listagem enquanto se apaga dentro dela
                // remove só parte dos arquivos (e num disco real pode lançar no meio do caminho).
                foreach (var nome in _fs.ListFiles(path).ToList())
                {
                    if (!IsOurs(path, nome)) continue;   // do cliente (mesmo com nome de canário): não se toca
                    _fs.Delete(Path.Combine(path, nome));
                    removidos++;
                }

                results.Add(new CanaryResult(path, removidos, 0));
            }
            catch (Exception ex)
            {
                results.Add(new CanaryResult(path, 0, 0, ex.Message));
            }
        }

        return results;
    }

    /// <summary>Total de canários presentes (plantados agora ou já existentes) nas pastas OK.</summary>
    public static int CountPlanted(IEnumerable<CanaryResult> results) =>
        results.Where(r => r.Ok).Sum(r => r.Total);
}
