using System.Security.Cryptography;
using System.Text.Json;
using RansomGuard.Core.Fsrm;
using RansomGuard.Core.Security;

namespace RansomGuard.Agent.Service.Windows;

/// <summary>
/// B4 — manifesto local dos canários: os nomes desta instalação e as pastas em que já foram plantados. Fica na pasta
/// de dados do agente (restrita), protegido — um processo de usuário comum não descobre por ele quais arquivos evitar.
///
/// É também o que permite DESFAZER: com nomes que não se identificam, só o manifesto sabe dizer quais arquivos são
/// do produto. Por isso guarda os nomes aposentados (trocados pelo administrador) e as pastas já usadas, mesmo que
/// tenham saído da configuração.
/// </summary>
public sealed class CanaryManifest
{
    public const string FileName = "canary-manifest.json";
    private const string Purpose = "RansomGuard.Agent.Canary.v1";

    private sealed record Stored(string Seed, List<string> Names, List<string> Retired, List<string> Roots);

    private readonly string _path;
    private readonly ILogger _log;
    private Stored _state;

    private CanaryManifest(string path, Stored state, ILogger log) { _path = path; _state = state; _log = log; }

    /// <summary>Nomes que o plantio usa nesta instalação.</summary>
    public IReadOnlyList<string> Names => _state.Names;
    /// <summary>Nomes e conteúdo dos canários desta instalação — o que o plantio usa e o que a remoção confere.</summary>
    public RansomGuard.Agent.Protection.CanarySet Set
    {
        get
        {
            var seed = Convert.FromBase64String(_state.Seed);
            var cache = new System.Collections.Concurrent.ConcurrentDictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            return new RansomGuard.Agent.Protection.CanarySet(_state.Names, name => cache.GetOrAdd(name, n => CanaryNames.ContentFor(seed, n)));
        }
    }
    /// <summary>Pastas em que o produto já plantou (inclui as que saíram da configuração).</summary>
    public IReadOnlyCollection<string> Roots => _state.Roots;

    /// <summary>
    /// Abre o manifesto ou cria um. <paramref name="configuredNames"/> (opção <c>Agent:CanaryNames</c>) vale no lugar
    /// dos nomes gerados quando traz pelo menos três nomes válidos; os nomes anteriores passam a "aposentados" e são
    /// retirados das pastas no próximo plantio.
    /// </summary>
    public static CanaryManifest Load(string dataDirectory, string? configuredNames, ILogger log)
    {
        var path = Path.Combine(dataDirectory, FileName);
        Stored? stored = null;
        try
        {
            if (ProtectedFile.ReadAndSeal(path, Purpose) is { } json) stored = JsonSerializer.Deserialize<Stored>(json);
        }
        catch (Exception ex) when (ex is InvalidDataException or JsonException)
        {
            var aside = path + ".ilegivel-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            try { File.Move(path, aside, overwrite: true); } catch (Exception) { }
            log.LogError(ex, "O manifesto de canários não abre ({Path}). Novos nomes serão gerados; canários plantados com os nomes anteriores deixam de ser reconhecidos e precisam ser removidos à mão.", aside);
        }

        var seed = stored?.Seed is { Length: > 0 } s ? s : Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var custom = CanaryNames.Parse(configuredNames);
        if (configuredNames is { Length: > 0 } && custom.Count < 3)
            log.LogWarning("Agent:CanaryNames precisa de pelo menos três nomes de arquivo válidos; seguem os nomes gerados para esta instalação.");
        var names = custom.Count >= 3 ? custom.ToList() : CanaryNames.Generate(Convert.FromBase64String(seed)).ToList();

        var retired = new HashSet<string>(stored?.Retired ?? new List<string>(), StringComparer.OrdinalIgnoreCase);
        foreach (var old in stored?.Names ?? new List<string>())
            if (!names.Contains(old, StringComparer.OrdinalIgnoreCase)) retired.Add(old);
        retired.ExceptWith(names);

        var manifest = new CanaryManifest(path, new Stored(seed, names, retired.ToList(), stored?.Roots ?? new List<string>()), log);
        if (stored is null || !names.SequenceEqual(stored.Names) || retired.Count != (stored.Retired?.Count ?? 0)) manifest.Save();
        CanaryPlan.Recognize(names.Concat(retired));
        return manifest;
    }

    /// <summary>
    /// Só reconhece os nomes de um manifesto que já existe, sem criar nada — para os modos de linha de comando
    /// (ensaio, diagnóstico), que não devem escrever na pasta de dados.
    /// </summary>
    public static IReadOnlyList<string> RecognizeExisting(string dataDirectory)
    {
        try
        {
            if (ProtectedFile.Read(Path.Combine(dataDirectory, FileName), Purpose) is { } json
                && JsonSerializer.Deserialize<Stored>(json) is { } stored)
            {
                CanaryPlan.Recognize(stored.Names.Concat(stored.Retired ?? new List<string>()));
                return stored.Names;
            }
        }
        catch (Exception) { /* sem manifesto legível: valem só os nomes antigos */ }
        return Array.Empty<string>();
    }

    /// <summary>Registra as pastas em que o plantio entrou (só grava quando há pasta nova).</summary>
    public void RememberRoots(IEnumerable<string> roots)
    {
        var known = new HashSet<string>(_state.Roots, StringComparer.OrdinalIgnoreCase);
        var added = roots.Where(r => !string.IsNullOrWhiteSpace(r) && known.Add(r)).ToList();
        if (added.Count == 0) return;
        _state = _state with { Roots = known.ToList() };
        Save();
    }

    private void Save()
    {
        try { ProtectedFile.Write(_path, JsonSerializer.Serialize(_state), Purpose); }
        catch (Exception ex) { _log.LogError(ex, "Não foi possível gravar o manifesto de canários em {Path}.", _path); }
    }
}
