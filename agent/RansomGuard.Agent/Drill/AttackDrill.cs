using RansomGuard.Agent.Protection;
using RansomGuard.Core.Fsrm;

namespace RansomGuard.Agent.Drill;

/// <summary>O que o ensaio deve provocar.</summary>
public enum DrillScenario
{
    /// <summary>Reescreve arquivos com extensão do catálogo — volume + troca de extensão.</summary>
    MassRewrite,
    /// <summary>Renomeia arquivos em massa — o padrão mais comum de ransomware.</summary>
    MassRename,
    /// <summary>Toca os arquivos-canário — o sinal de maior confiança do produto.</summary>
    Canary,
    /// <summary>Cria o bilhete de resgate — padrão que o FSRM bloqueia.</summary>
    RansomNote,
    /// <summary>Os quatro, na ordem de um ataque real.</summary>
    Full,
    // M3 — comportamentos da matriz de casos de uso do laboratório.
    /// <summary>Grava o "cifrado" ao lado e apaga o original — a troca de extensão fica visível nas duas pontas.</summary>
    CopyEncryptDelete,
    /// <summary>Regrava no lugar, sem mudar nome nem extensão — só volume e ritmo denunciam.</summary>
    InPlace,
    /// <summary>Só apaga (apagador).</summary>
    Wiper,
    /// <summary>Só lê, em massa — o que precede a exfiltração.</summary>
    MassRead
}

/// <summary>Opções de um plano de ensaio.</summary>
/// <param name="Count">Quantos arquivos o ataque alcança.</param>
/// <param name="Extension">Extensão que os arquivos "cifrados" recebem. O padrão está no catálogo; outra simula família desconhecida.</param>
/// <param name="SkipHidden">Pula arquivos ocultos e de sistema — o ataque que evita canários pelos atributos.</param>
public sealed record DrillOptions(int Count = 150, string Extension = AttackDrill.EncryptedExtension, bool SkipHidden = false);

/// <summary>
/// Ritmo do ataque: pausa fixa entre arquivos (lento e constante) e/ou pausa longa a cada rajada. A decisão é pura;
/// quem dorme é a linha de comando.
/// </summary>
public sealed record DrillPacing(int IntervalMs = 0, int Burst = 0, int PauseMs = 0)
{
    public static readonly DrillPacing None = new();

    /// <summary>Quanto esperar depois da ação de índice <paramref name="index"/> (base zero).</summary>
    public int DelayAfter(int index) => Burst > 0 && (index + 1) % Burst == 0 ? PauseMs : IntervalMs;
}

/// <summary>
/// O que aconteceu numa execução — é o registro do atacante, e é dele que saem "quantos arquivos foram tocados antes
/// de o servidor fechar a porta" e os instantes para medir detecção e contenção.
/// </summary>
public sealed record DrillRunResult(
    int Planned, int Done, int Failed, int? FirstFailureIndex, DateTime StartedUtc, DateTime? FirstFailureAtUtc, DateTime EndedUtc,
    bool StoppedEarly, string? Error);

/// <summary>Uma ação que o ensaio pretende executar. Descrita antes de acontecer.</summary>
/// <param name="Kind">Natureza da ação.</param>
/// <param name="Target">Arquivo alvo (nome, não caminho completo).</param>
/// <param name="NewName">Nome resultante, quando há renomeação.</param>
public sealed record DrillAction(string Kind, string Target, string? NewName = null);

/// <summary>Por que o ensaio se recusou a rodar.</summary>
public sealed record DrillRefusal(string Reason);

/// <summary>
/// Ensaio de ataque controlado: provoca o comportamento que o produto deve detectar, para provar a
/// cadeia <c>ataque → evento → detecção</c> num ambiente real.
///
/// <b>Este utilitário imita ransomware.</b> Se puder ser apontado para dados de produção por engano,
/// ele é o incidente. Daí as travas, que são a parte séria desta classe:
///
/// <list type="number">
///   <item><b>Só opera em pasta que o próprio ensaio criou</b>, identificada pelo marcador
///   <see cref="MarkerFile"/>. Pasta sem marcador é recusada, sempre.</item>
///   <item><b>Recusa caminhos perigosos</b> reusando o <see cref="ProtectedPaths"/> do F12 — mesma
///   lista, um só lugar para manter.</item>
///   <item><b>Nunca criptografa.</b> Renomeia e reescreve com conteúdo inerte. Não existe chave nem
///   cifra: nada aqui pode ficar irrecuperável.</item>
///   <item><b>Só age com confirmação explícita.</b> Sem ela, apenas descreve o plano.</item>
///   <item><b>É reversível</b> — apaga só o que criou.</item>
/// </list>
/// </summary>
public sealed class AttackDrill
{
    /// <summary>Marcador que autoriza o ensaio numa pasta. Sem ele, nada acontece.</summary>
    public const string MarkerFile = "_RANSOMGUARD_TESTE_.txt";

    public const string MarkerContent =
        "Pasta de ENSAIO do RansomGuard.\r\n" +
        "\r\n" +
        "Criada pelo utilitário de ataque controlado. Tudo aqui é descartável: os arquivos são\r\n" +
        "gerados pelo próprio ensaio e podem ser apagados a qualquer momento.\r\n" +
        "\r\n" +
        "O ensaio SÓ opera em pastas que contenham este arquivo. Não mova este marcador para\r\n" +
        "uma pasta com dados reais.\r\n";

    /// <summary>Extensão usada na reescrita. Está no catálogo semente, então o FSRM a reconhece.</summary>
    public const string EncryptedExtension = ".locked";

    /// <summary>Nome do bilhete de resgate. Casa com o padrão `HOW_TO_DECRYPT*` do catálogo.</summary>
    public const string RansomNoteName = "HOW_TO_DECRYPT_YOUR_FILES.txt";

    /// <summary>Conteúdo do bilhete — inerte e claramente identificado como ensaio.</summary>
    public const string RansomNoteContent =
        "*** ENSAIO DO RANSOMGUARD — NAO E UM ATAQUE REAL ***\r\n" +
        "\r\n" +
        "Este arquivo imita um bilhete de resgate para exercitar a deteccao do produto.\r\n" +
        "Nenhum arquivo foi criptografado. Nada aqui e recuperavel porque nada foi perdido.\r\n";

    private readonly IDrillFileSystem _fs;

    public AttackDrill(IDrillFileSystem fs) => _fs = fs;

    /// <summary>Falhas seguidas depois das quais o ataque desiste: o servidor está negando (a contenção chegou).</summary>
    public const int MaxConsecutiveFailures = 10;

    private const string InertContent = "conteudo substituido pelo ensaio do RansomGuard";

    private static readonly HashSet<string> NeverProduced = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".com", ".msi", ".lnk", ".hta", ".sys" };

    /// <summary>
    /// Extensão que o ensaio aceita dar a um arquivo: ponto + até dez letras ou dígitos, e nunca a de algo que o
    /// Windows executaria — o ensaio não deixa no share um arquivo que alguém possa abrir e rodar.
    /// </summary>
    public static bool IsSafeExtension(string? extension) =>
        extension is { Length: >= 2 and <= 11 } && extension[0] == '.'
        && extension.Skip(1).All(c => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9')
        && !NeverProduced.Contains(extension);

    /// <summary>
    /// A pasta está autorizada a receber o ensaio? <c>null</c> = autorizada; caso contrário, o
    /// motivo da recusa, em português, para o operador entender e corrigir.
    /// </summary>
    public DrillRefusal? CheckTarget(string path)
    {
        // Trava 2: a mesma lista de caminhos perigosos do F12 — raiz de volume, pasta de sistema,
        // caminho de rede, relativo.
        var parsed = ProtectedPaths.Parse(path);
        if (parsed.Rejected.Count > 0)
            return new DrillRefusal(parsed.Rejected[0].Reason);

        if (!_fs.DirectoryExists(path))
            return new DrillRefusal("A pasta não existe. Use --preparar-pasta para criá-la.");

        // Trava 1: a mais importante. Sem o marcador, o ensaio não toca em nada.
        if (!_fs.FileExists(Path.Combine(path, MarkerFile)))
            return new DrillRefusal(
                $"Pasta sem o marcador {MarkerFile}. O ensaio só opera em pasta criada por ele " +
                "mesmo — é o que impede apontá-lo para dados reais por engano.");

        return null;
    }

    /// <summary>
    /// Cria a pasta de ensaio com o marcador e arquivos descartáveis. É o único ponto em que uma
    /// pasta passa a ser elegível ao ataque.
    /// </summary>
    public DrillRefusal? PrepareFolder(string path, int fileCount = 200, int subfolders = 0)
    {
        var parsed = ProtectedPaths.Parse(path);
        if (parsed.Rejected.Count > 0) return new DrillRefusal(parsed.Rejected[0].Reason);

        // Uma pasta que já tem conteúdo pode ser do cliente. Só aceitamos vazia ou já marcada.
        if (_fs.DirectoryExists(path) &&
            _fs.ListFiles(path).Count > 0 &&
            !_fs.FileExists(Path.Combine(path, MarkerFile)))
        {
            return new DrillRefusal(
                "A pasta já tem arquivos e não é uma pasta de ensaio. Escolha uma pasta vazia ou " +
                "nova — o ensaio nunca reaproveita pasta com conteúdo desconhecido.");
        }

        _fs.CreateDirectory(path);
        _fs.WriteFile(Path.Combine(path, MarkerFile), MarkerContent);

        for (var i = 1; i <= fileCount; i++)
            _fs.WriteFile(Path.Combine(path, $"documento_{i:D4}.docx"),
                $"Arquivo descartável de ensaio nº {i}.");

        // M3: subpastas, para os casos em que o ataque (e a nota de resgate) se espalha por diretórios.
        for (var s = 1; s <= subfolders; s++)
        {
            var sub = Path.Combine(path, $"pasta_{s:D2}");
            _fs.CreateDirectory(sub);
            for (var i = 1; i <= fileCount; i++)
                _fs.WriteFile(Path.Combine(sub, $"documento_{i:D4}.docx"), $"Arquivo descartável de ensaio nº {i} da pasta {s}.");
        }

        return null;
    }

    /// <summary>Arquivos de ensaio da pasta e das subpastas imediatas, como caminhos relativos, em ordem alfabética.</summary>
    private List<string> Targets(string path, DrillOptions options)
    {
        var all = _fs.ListFiles(path).ToList();
        foreach (var sub in _fs.ListDirectories(path))
            all.AddRange(_fs.ListFiles(sub).Select(f => Path.Combine(Path.GetFileName(sub), f)));
        return all
            .Where(f => !Path.GetFileName(f).Equals(MarkerFile, StringComparison.OrdinalIgnoreCase))
            .Where(f => !Path.GetFileName(f).Equals(RansomNoteName, StringComparison.OrdinalIgnoreCase))
            .Where(f => !f.EndsWith(options.Extension, StringComparison.OrdinalIgnoreCase))
            .Where(f => !options.SkipHidden || !_fs.IsHiddenOrSystem(Path.Combine(path, f)))
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .Take(options.Count)
            .ToList();
    }

    /// <summary>Plano de um dos comportamentos, com opções (extensão, quantidade, pular ocultos). Não executa nada.</summary>
    public IReadOnlyList<DrillAction> Plan(string path, DrillScenario scenario, DrillOptions options)
    {
        if (!IsSafeExtension(options.Extension))
            throw new ArgumentException($"Extensão não aceita pelo ensaio: {options.Extension}", nameof(options));

        // Os quatro comportamentos originais, com a extensão padrão e sem subpastas, seguem pelo plano de sempre.
        if (scenario is DrillScenario.Canary or DrillScenario.Full)
            return Plan(path, scenario, options.Count);

        var targets = Targets(path, options);
        var actions = new List<DrillAction>();
        switch (scenario)
        {
            case DrillScenario.MassRewrite:
                actions.AddRange(targets.Select(f => new DrillAction("reescrita", f, f + options.Extension)));
                break;
            case DrillScenario.MassRename:
                actions.AddRange(targets.Select(f => new DrillAction("renomeação", f, Path.ChangeExtension(f, options.Extension))));
                break;
            case DrillScenario.CopyEncryptDelete:
                foreach (var f in targets)
                {
                    actions.Add(new DrillAction("cópia cifrada", f, f + options.Extension));
                    actions.Add(new DrillAction("exclusão", f));
                }
                break;
            case DrillScenario.InPlace:
                actions.AddRange(targets.Select(f => new DrillAction("regravação", f)));
                break;
            case DrillScenario.Wiper:
                actions.AddRange(targets.Select(f => new DrillAction("exclusão", f)));
                break;
            case DrillScenario.MassRead:
                actions.AddRange(targets.Select(f => new DrillAction("leitura", f)));
                break;
            case DrillScenario.RansomNote:
                // A mesma nota na pasta e em cada subpasta — é o que caracteriza uma nota de resgate.
                actions.Add(new DrillAction("bilhete de resgate", RansomNoteName));
                actions.AddRange(_fs.ListDirectories(path).OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
                    .Select(d => new DrillAction("bilhete de resgate", Path.Combine(Path.GetFileName(d), RansomNoteName))));
                break;
        }
        return actions;
    }

    /// <summary>
    /// Executa o plano tolerando recusa do servidor: cada falha é contada, e depois de
    /// <see cref="MaxConsecutiveFailures"/> seguidas o ataque para. Devolve o registro com contagens e instantes.
    /// Mesma pré-condição de <see cref="Execute"/>: pasta conferida e confirmação dada.
    /// </summary>
    public DrillRunResult Run(string path, IReadOnlyList<DrillAction> plan, DrillPacing? pacing = null,
        Action<int>? sleep = null, Func<DateTime>? clock = null)
    {
        pacing ??= DrillPacing.None;
        clock ??= () => DateTime.UtcNow;
        var started = clock();
        int done = 0, failed = 0, consecutive = 0;
        int? firstFailure = null;
        DateTime? firstFailureAt = null;
        string? error = null;
        var stopped = false;

        for (var i = 0; i < plan.Count; i++)
        {
            try
            {
                if (Apply(path, plan[i])) done++;
                consecutive = 0;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                failed++;
                consecutive++;
                error ??= ex.Message;
                if (firstFailure is null) { firstFailure = i; firstFailureAt = clock(); }
                if (consecutive >= MaxConsecutiveFailures) { stopped = true; break; }
            }

            var delay = pacing.DelayAfter(i);
            if (delay > 0 && i < plan.Count - 1) (sleep ?? (ms => Thread.Sleep(ms)))(delay);
        }

        return new DrillRunResult(plan.Count, done, failed, firstFailure, started, firstFailureAt, clock(), stopped, error);
    }

    /// <summary>Uma ação. Nenhuma cifra: o que se grava é sempre texto inerte.</summary>
    private bool Apply(string path, DrillAction action)
    {
        var source = Path.Combine(path, action.Target);
        switch (action.Kind)
        {
            case "reescrita":
                _fs.WriteFile(source, InertContent);
                _fs.Move(source, Path.Combine(path, action.NewName!));
                return true;
            case "renomeação":
                _fs.Move(source, Path.Combine(path, action.NewName!));
                return true;
            case "cópia cifrada":
                _fs.WriteFile(Path.Combine(path, action.NewName!), InertContent);
                return true;
            case "regravação":
                _fs.WriteFile(source, InertContent);
                return true;
            case "exclusão":
                _fs.DeleteFile(source);
                return true;
            case "leitura":
                _fs.ReadFile(source);
                return true;
            case "canário":
                _fs.Touch(source);
                return true;
            case "bilhete de resgate":
                _fs.WriteFile(source, RansomNoteContent);
                return true;
            default:
                return false;
        }
    }

    /// <summary>
    /// Descreve o que o ensaio faria, **sem executar**. É o que o operador vê antes de confirmar.
    /// </summary>
    public IReadOnlyList<DrillAction> Plan(string path, DrillScenario scenario, int count = 150)
    {
        var alvos = _fs.ListFiles(path)
            .Where(f => !f.Equals(MarkerFile, StringComparison.OrdinalIgnoreCase))
            .Where(f => !CanaryPlan.IsCanary(f))
            .Where(f => !f.EndsWith(EncryptedExtension, StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .Take(count)
            .ToList();

        var canarios = _fs.ListFiles(path).Where(CanaryPlan.IsCanary).ToList();
        var acoes = new List<DrillAction>();

        void Reescrita() => acoes.AddRange(alvos.Select(f =>
            new DrillAction("reescrita", f, f + EncryptedExtension)));

        void Renomeacao() => acoes.AddRange(alvos.Select(f =>
            new DrillAction("renomeação", f, Path.GetFileNameWithoutExtension(f) + EncryptedExtension)));

        void Canario() => acoes.AddRange(canarios.Select(c => new DrillAction("canário", c)));

        void Bilhete() => acoes.Add(new DrillAction("bilhete de resgate", RansomNoteName));

        switch (scenario)
        {
            case DrillScenario.MassRewrite: Reescrita(); break;
            case DrillScenario.MassRename: Renomeacao(); break;
            case DrillScenario.Canary: Canario(); break;
            case DrillScenario.RansomNote: Bilhete(); break;
            case DrillScenario.Full:
                // Ordem de um ataque real: varre (toca o canário), cifra, deixa o bilhete.
                Canario();
                Reescrita();
                Bilhete();
                break;
        }

        return acoes;
    }

    /// <summary>
    /// Executa o plano. Só chame depois de <see cref="CheckTarget"/> devolver <c>null</c> e de o
    /// operador ter confirmado — a CLI é quem garante isso.
    /// </summary>
    public int Execute(string path, IReadOnlyList<DrillAction> plan)
    {
        var feitas = 0;

        foreach (var acao in plan)
        {
            var origem = Path.Combine(path, acao.Target);

            switch (acao.Kind)
            {
                case "reescrita":
                    // Reescreve com conteúdo INERTE e renomeia. Nenhuma cifra: o "ataque" é
                    // observável pelo produto, mas nada fica irrecuperável.
                    _fs.WriteFile(origem, "conteudo substituido pelo ensaio do RansomGuard");
                    _fs.Move(origem, Path.Combine(path, acao.NewName!));
                    break;

                case "renomeação":
                    _fs.Move(origem, Path.Combine(path, acao.NewName!));
                    break;

                case "canário":
                    // Tocar já basta: o produto detecta o ACESSO, não a alteração.
                    _fs.Touch(origem);
                    break;

                case "bilhete de resgate":
                    _fs.WriteFile(origem, RansomNoteContent);
                    break;

                default:
                    continue;
            }
            feitas++;
        }

        return feitas;
    }

    /// <summary>
    /// Apaga a pasta de ensaio inteira — e **só** se ela tiver o marcador. É a mesma trava da
    /// execução: sem marcador, não se apaga nada.
    /// </summary>
    public DrillRefusal? Clean(string path)
    {
        var recusa = CheckTarget(path);
        if (recusa is not null) return recusa;

        _fs.DeleteDirectory(path);
        return null;
    }
}

/// <summary>Operações de disco do ensaio. Abstraído para as travas serem testáveis sem disco.</summary>
public interface IDrillFileSystem
{
    bool DirectoryExists(string path);
    bool FileExists(string path);
    IReadOnlyList<string> ListFiles(string path);
    void CreateDirectory(string path);
    void WriteFile(string fullPath, string content);
    void Move(string from, string to);
    void Touch(string fullPath);
    void DeleteDirectory(string path);

    // M3 — operações dos comportamentos novos. Padrões seguros mantêm as implementações anteriores válidas.
    /// <summary>Subpastas imediatas (caminho completo).</summary>
    IReadOnlyList<string> ListDirectories(string path) => Array.Empty<string>();
    void DeleteFile(string fullPath) => throw new NotSupportedException();
    /// <summary>Lê o arquivo inteiro e descarta — o acesso é o que importa.</summary>
    void ReadFile(string fullPath) => throw new NotSupportedException();
    bool IsHiddenOrSystem(string fullPath) => false;
}
