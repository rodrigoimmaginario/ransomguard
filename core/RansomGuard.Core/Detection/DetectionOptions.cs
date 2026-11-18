namespace RansomGuard.Core.Detection;

/// <summary>
/// Parâmetros do motor de detecção. Na v1 têm defaults sensatos; na fatia 3 passam a vir do
/// catálogo assinado (chave offline), permitindo ajustar sensibilidade sem relançar o agente.
/// Também são a base do guard-rail de falso positivo: allowlist de contas de serviço/IPs.
/// </summary>
public sealed class DetectionOptions
{
    /// <summary>Janela de correlação: eventos do mesmo ator dentro dela formam um incidente.</summary>
    public TimeSpan Window { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Nº de arquivos escritos/renomeados que caracteriza operação "em massa".</summary>
    public int MassThreshold { get; init; } = 40;

    /// <summary>Nº de arquivos distintos apagados (ou renomeados) num lote que caracteriza exclusão em massa.</summary>
    public int MassDeleteThreshold { get; init; } = 100;

    /// <summary>O mesmo, acumulado na janela de 60 s entre lotes (apagar devagar não escapa do limiar do lote).</summary>
    public int RollingDeleteThreshold { get; init; } = 300;

    /// <summary>
    /// Contas cujo I/O em massa é legítimo (backup, antivírus, robocopy). Nunca geram detecção
    /// por volume; ainda assim disparam se tocarem um canário (nenhum processo legítimo toca).
    /// </summary>
    public IReadOnlySet<string> AllowlistedUsers { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>IPs de origem confiáveis (ex.: servidor de backup) — mesma regra da allowlist.</summary>
    public IReadOnlySet<string> AllowlistedIps { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    // ── G1 — detecção em profundidade ────────────────────────────────────────────────────────

    /// <summary>Padrões (curinga *) de nomes de nota de resgate. Genéricos demais (readme.txt) ficam de fora de propósito.</summary>
    public IReadOnlyList<string> NoteNamePatterns { get; init; } = new[]
    {
        "*decrypt*", "*restore*file*", "*recover*file*", "*recover-files*", "*how_to*", "*how-to*", "*howto*",
        "*readme*restore*", "*read_me*", "*read-me*", "!!!*", "*ransom*", "*unlock*files*", "*your_files*", "*files_encrypted*",
        "*_readme.txt", "*#*recover*", "*instructions*.hta"
    };
    /// <summary>
    /// D6 — dos padrões acima, os que só uma nota de resgate teria (falam em restaurar/recuperar/decifrar ARQUIVOS, em
    /// resgate, em "seus arquivos"). O mesmo nome destes em várias pastas é Alta por si. Os demais ("read_me",
    /// "how-to", "decrypt" solto, "!!!") aparecem em documentação e instaladores: repetidos, são só um indício.
    /// </summary>
    public IReadOnlyList<string> StrongNoteNamePatterns { get; init; } = new[]
    {
        "*restore*file*", "*recover*file*", "*recover-files*", "*decrypt*file*", "*readme*restore*", "*ransom*",
        "*unlock*files*", "*your_files*", "*your files*", "*files_encrypted*", "*files*encrypted*", "*#*recover*", "*instructions*.hta"
    };
    /// <summary>Diretórios distintos com nota para caracterizar o incidente.</summary>
    public int MinNoteDirectories { get; init; } = 3;

    /// <summary>Extensões conhecidas (catálogo assinado) — provedor para refletir atualizações sem recriar o motor.</summary>
    public Func<IReadOnlySet<string>>? KnownExtensionsProvider { get; init; }
    /// <summary>G7: catálogo ativo (notas de resgate extras + afinação de limiares), consultado a cada análise.</summary>
    public Func<Fsrm.RansomwareCatalog?>? CatalogProvider { get; init; }

    /// <summary>Limiares efetivos: os do catálogo ativo (quando definidos) sobre os padrões.</summary>
    public (int Mass, int Rolling, int Slow, int Read, int KnownExt, int NoteDirs, IReadOnlyList<string> NotePatterns) Effective()
    {
        var c = CatalogProvider?.Invoke();
        var t = c?.Tuning;
        var notes = c?.NotePatterns is { Count: > 0 } extra ? NoteNamePatterns.Concat(extra).Distinct(StringComparer.OrdinalIgnoreCase).ToList() : NoteNamePatterns;
        return (t?.MassThreshold ?? MassThreshold, t?.RollingWindowThreshold ?? RollingWindowThreshold, t?.SlowThreshold ?? SlowThreshold,
                t?.ReadThreshold ?? ReadThreshold, t?.KnownExtensionThreshold ?? KnownExtensionThreshold, t?.MinNoteDirectories ?? MinNoteDirectories, notes);
    }
    /// <summary>Arquivos renomeados para extensão conhecida que bastam para Alta.</summary>
    public int KnownExtensionThreshold { get; init; } = 5;

    /// <summary>Shares-isca (UNC): ninguém legítimo os usa; qualquer acesso é Alta.</summary>
    public IReadOnlySet<string> DecoyShares { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// G1/G6: limiar da janela de 60 s acumulada ENTRE ciclos. É maior que <see cref="MassThreshold"/> (que vale para um
    /// lote de 5 s) porque 40 gravações por minuto numa pasta é tráfego normal de aplicativo; 2 por segundo sustentados
    /// por um minuto não é.
    /// </summary>
    public int RollingWindowThreshold { get; init; } = 120;

    /// <summary>Janela longa para low-and-slow e seu limiar.</summary>
    public TimeSpan SlowWindow { get; init; } = TimeSpan.FromMinutes(30);
    public int SlowThreshold { get; init; } = 300;   // 10 por minuto sustentados por 30 min: 1 arquivo a cada 6 s
    /// <summary>Intervalo mínimo entre duas emissões de "escrita sustentada" para o mesmo ator.</summary>
    public TimeSpan SustainedCooldown { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>Anomalia de ritmo: último minuto ≥ fator × média por minuto do ator (24 h), com mínimo de arquivos e histórico.</summary>
    /// <summary>G5: leituras na janela que caracterizam leitura em massa (exfiltração) por ator remoto não allowlisted.</summary>
    public int ReadThreshold { get; init; } = 2_000;   // busca em share lê centenas; cópia integral lê milhares

    public double AnomalyFactor { get; init; } = 8;
    public int AnomalyMinFiles { get; init; } = 10;
    public TimeSpan AnomalyMinHistory { get; init; } = TimeSpan.FromMinutes(60);
}
