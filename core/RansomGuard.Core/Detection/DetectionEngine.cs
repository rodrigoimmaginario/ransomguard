namespace RansomGuard.Core.Detection;

/// <summary>
/// Correlaciona eventos de arquivo e sinais de host por ator (usuário+IP+share) numa janela de
/// tempo e decide se há um incidente de ransomware, com que confiança e por quê.
///
/// Regras de confiança (semente da fatia 0, calibrável pelo catálogo na fatia 3):
///  - Canário tocado           → High (nenhum processo legítimo mexe num canário).
///  - VSS deletado / tamper     → High (passo de playbook, não acontece em operação normal).
///  - Escrita/renomeação em massa OU troca de extensão em massa → Medium.
///  - Ator na allowlist         → nunca gera detecção por volume (guard-rail de falso positivo),
///    mas ainda dispara High se tocar canário.
///
/// Lógica pura e determinística: sem I/O, sem relógio próprio (usa o carimbo dos eventos), para
/// ser 100% testável e dirigível pelos simuladores.
/// </summary>
public sealed class DetectionEngine
{
    private readonly DetectionOptions _options;
    private readonly ActorActivityTracker? _tracker;
    private readonly ActorActivityTracker? _deleteTracker;
    private readonly ActorActivityTracker? _overwriteTracker;
    private readonly ActorActivityTracker? _readTracker;

    /// <param name="tracker">G1: memória entre ciclos (janela de 60 s real, low-and-slow, linha de base). Null = só o lote.</param>
    public DetectionEngine(DetectionOptions? options = null, ActorActivityTracker? tracker = null)
    {
        _options = options ?? new DetectionOptions();
        _tracker = tracker;
        // Exclusões têm memória própria: somá-las às gravações faria um "salvar" comum (gravar + renomear) contar duas vezes.
        _deleteTracker = tracker is null ? null : new ActorActivityTracker(TimeSpan.FromMinutes(10), op => op == FileOp.Delete);
        // Laboratório, sessão 3: regravações de arquivos existentes também têm memória própria (o ataque em rajadas fica
        // abaixo do limiar em cada lote, mas não na janela de um minuto).
        _overwriteTracker = tracker is null ? null : new ActorActivityTracker(TimeSpan.FromMinutes(10), op => op == FileOp.Write);
        // Laboratório, sessão 4: a leitura em massa também precisa da janela de um minuto (2600 arquivos em 28 s passavam).
        _readTracker = tracker is null ? null : new ActorActivityTracker(TimeSpan.FromMinutes(10), op => op == FileOp.Read);
    }

    /// <summary>
    /// Analisa um lote de eventos/sinais e retorna as detecções, uma por ator (usuário+IP+share).
    /// O servidor de cada detecção vem do share ou dos sinais de host correlacionados.
    /// </summary>
    public IReadOnlyList<Detection> Analyze(
        IEnumerable<FileEvent> events,
        IEnumerable<HostSignal>? hostSignals = null)
    {
        var eventList = events as IReadOnlyList<FileEvent> ?? events.ToList();
        _tracker?.Record(eventList);
        _deleteTracker?.Record(eventList);
        _overwriteTracker?.Record(eventList.Where(e => e.Overwrite));
        _readTracker?.Record(eventList.Where(e => e.SourceIp != Detection.LocalOrigin));
        var known = _options.KnownExtensionsProvider?.Invoke();
        var fx = _options.Effective();   // G7: limiares/notas do catálogo ativo
        var byActor = eventList
            .GroupBy(e => new ActorKey(e.User, e.SourceIp, e.Share));

        var signals = (hostSignals ?? Enumerable.Empty<HostSignal>()).ToList();
        var results = new List<Detection>();

        // R6: rastreia quais sinais foram consumidos por algum grupo de evento. Os que sobrarem
        // (deleção de VSS/tamper sem eventos correlacionados) viram detecção de nível servidor —
        // o produto não pode ficar cego no primeiro passo do playbook (apagar shadow copies / matar
        // o agente antes de cifrar).
        var consumed = new HashSet<HostSignal>();

        foreach (var group in byActor)
        {
            var actor = group.Key;
            var allowlisted = _options.AllowlistedUsers.Contains(actor.User)
                              || _options.AllowlistedIps.Contains(actor.SourceIp);

            var reasons = new HashSet<DetectionReason>();

            var canaryHits = group.Where(e => e.IsCanary
                && e.Op is FileOp.Write or FileOp.Rename or FileOp.Delete).ToList();
            if (canaryHits.Count > 0)
            {
                // D6: quem SÓ apaga canários e não apaga mais nenhum arquivo está fazendo o que um espelhamento com purga
                // faz (apaga o que não existe na origem). Indício, não certeza: Média. Gravar ou renomear um canário,
                // ou apagar canário junto com arquivo do cliente, continua Alta.
                var onlyDeleted = canaryHits.All(e => e.Op == FileOp.Delete);
                var deletedOthers = group.Any(e => !e.IsCanary && e.Op is FileOp.Delete or FileOp.Rename);
                reasons.Add(onlyDeleted && !deletedOthers ? DetectionReason.CanaryRemoved : DetectionReason.CanaryTouched);
            }

            // G1 — sinais de Alta que valem MESMO para ator na allowlist (uma conta de backup comprometida
            // escreve nota de resgate ou .lockbit como qualquer outra):
            if (_options.DecoyShares.Contains(actor.Share))
                reasons.Add(DetectionReason.DecoyShareTouched);
            // D6: nota de resgate é o MESMO arquivo deixado em várias pastas. Três documentos diferentes que casam
            // com padrões genéricos não são isso; e nome genérico repetido é indício (Média), não certeza.
            var strongNotes = _options.StrongNoteNamePatterns.Concat(fx.NotePatterns.Except(_options.NoteNamePatterns, StringComparer.OrdinalIgnoreCase)).ToList();
            var anyNote = fx.NotePatterns.Concat(strongNotes).ToList();
            foreach (var sameName in group.Where(e => e.Op == FileOp.Write && RansomNoteNames.Matches(e.Path, anyNote))
                         .GroupBy(e => RansomNoteNames.FileOf(e.Path), StringComparer.OrdinalIgnoreCase))
            {
                if (sameName.Select(e => RansomNoteNames.DirectoryOf(e.Path)).Distinct(StringComparer.OrdinalIgnoreCase).Count() < fx.NoteDirs) continue;
                reasons.Add(RansomNoteNames.Matches(sameName.Key, strongNotes) ? DetectionReason.RansomNote : DetectionReason.NoteLikeFiles);
            }
            if (known is { Count: > 0 })
            {
                var knownFlips = Files(group.Where(e => e.NewExtension is not null && e.Op is FileOp.Write or FileOp.Rename && known.Contains(e.NewExtension!)));
                if (knownFlips >= fx.KnownExt)
                    reasons.Add(DetectionReason.KnownRansomExtension);
                // Abaixo do limiar não contém ninguém, mas um arquivo com extensão do catálogo (é o que o file screen
                // registra) não passa em silêncio: vira incidente de Média.
                else if (knownFlips > 0)
                    reasons.Add(DetectionReason.KnownExtensionSeen);
            }

            // Operações em massa só contam para atores fora da allowlist (guard-rail).
            if (!allowlisted)
            {
                // Conta ARQUIVOS, não eventos: no Windows real, criar um único arquivo pela rede gera duas checagens de
                // gravação (abrir para escrita + gravar). Contar eventos dobraria o volume de qualquer usuário legítimo.
                var writes = Files(group.Where(e => e.Op == FileOp.Write));
                var renames = Files(group.Where(e => e.Op == FileOp.Rename));
                // D2: troca de extensão é troca OBSERVADA (as duas pontas), não "arquivo gravado que tem extensão" —
                // o coletor real preenche a extensão de todo arquivo, e isso fazia toda gravação em massa virar "troca".
                var flips = ExtensionChanges.Observed(group).Count;

                if (writes >= fx.Mass)
                    reasons.Add(DetectionReason.MassRewrite);
                // Laboratório, sessão 3: o que separa o ransomware que regrava no lugar (e que, pulando arquivos ocultos,
                // nunca toca um canário) de quem copia arquivos novos para o share é regravar arquivos que JÁ EXISTIAM.
                var overwrites = Files(group.Where(e => e.Overwrite && e.Op == FileOp.Write));
                if (overwrites >= fx.Mass
                    || (_overwriteTracker is not null && overwrites > 0
                        && _overwriteTracker.CountInWindow(actor, group.Max(e => e.At), _options.Window) >= fx.Mass))
                    reasons.Add(DetectionReason.MassOverwrite);
                if (renames >= fx.Mass)
                    reasons.Add(DetectionReason.MassRename);
                if (flips >= fx.Mass)
                    reasons.Add(DetectionReason.ExtensionFlip);
                // Apagar e renomear chegam do Windows como o mesmo acesso de exclusão no nome antigo.
                var deletes = Files(group.Where(e => e.Op == FileOp.Delete));
                if (deletes >= _options.MassDeleteThreshold
                    || (_deleteTracker is not null && deletes > 0
                        && _deleteTracker.CountInWindow(actor, group.Max(e => e.At), _options.Window) >= _options.RollingDeleteThreshold))
                    reasons.Add(DetectionReason.MassDelete);
                // G5: ler centenas de arquivos de um share por sessão remota é o que precede a exfiltração.
                if (!string.Equals(actor.SourceIp, Detection.LocalOrigin, StringComparison.OrdinalIgnoreCase))
                {
                    var reads = group.Where(e => e.Op == FileOp.Read).Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
                    if (reads >= fx.Read
                        || (_readTracker is not null && reads > 0 && _readTracker.CountInWindow(actor, group.Max(e => e.At), _options.Window) >= fx.Read))
                        reasons.Add(DetectionReason.MassRead);
                }

                // G1 — memória entre ciclos: a janela de 60 s atravessa lotes de 5 s; low-and-slow na janela
                // longa (com cooldown para não re-emitir a cada ciclo); anomalia contra a própria linha de base.
                if (_tracker is not null)
                {
                    var until = group.Max(e => e.At);
                    if (_tracker.CountInWindow(actor, until, _options.Window) >= fx.Rolling)
                        reasons.Add(DetectionReason.MassRewrite);
                    if (_tracker.CountInWindow(actor, until, _options.SlowWindow) >= fx.Slow
                        && _tracker.TryMarkSustained(actor, until, _options.SustainedCooldown))
                        reasons.Add(DetectionReason.SustainedRewrite);
                    var lastMinute = _tracker.CountInWindow(actor, until, TimeSpan.FromMinutes(1));
                    var baseline = _tracker.BaselinePerMinute(actor, until, _options.AnomalyMinHistory);
                    if (baseline is { } avg && lastMinute >= _options.AnomalyMinFiles
                        && lastMinute >= _options.AnomalyFactor * Math.Max(avg, 1.0 / 60))
                        reasons.Add(DetectionReason.RateAnomaly);
                }
            }

            // Sinais de host correlacionados pela janela de tempo do ator — só para quem JÁ tem razão própria. Um sinal
            // do servidor reforça o suspeito; não transforma em suspeito quem só estava trabalhando naquele minuto.
            var first = group.Min(e => e.At);
            var last = group.Max(e => e.At);
            var windowStart = first - _options.Window;
            var windowEnd = last + _options.Window;
            var server = ServerOf(actor.Share);

            if (reasons.Count == 0)
                continue;   // sem comportamento suspeito próprio: os sinais do servidor ficam para o incidente do servidor

            foreach (var s in signals.Where(s =>
                         string.Equals(s.Server, server, StringComparison.OrdinalIgnoreCase)
                         && s.At >= windowStart && s.At <= windowEnd))
            {
                consumed.Add(s);
                if (ReasonOf(s.Kind) is { } r) reasons.Add(r);
            }

            var confidence = Score(reasons);
            var processes = group.Where(e => e.ProcessId is > 0)
                .GroupBy(e => e.ProcessId!.Value)
                .Select(g => new LocalProcess(g.Key, g.Select(e => e.ProcessName).FirstOrDefault(n => !string.IsNullOrEmpty(n)) ?? ""))
                .ToList();
            results.Add(new Detection(
                Server: server,
                User: actor.User,
                SourceIp: actor.SourceIp,
                Share: actor.Share,
                Confidence: confidence,
                Reasons: reasons,
                AffectedFiles: AffectedFilesOf(group),
                FirstAt: first,
                LastAt: last,
                Processes: processes.Count > 0 ? processes : null,
                AffectedPaths: group.Where(e => e.Op is FileOp.Write or FileOp.Rename or FileOp.Delete)
                    .Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).Take(Detection.MaxAffectedPaths).ToList()));
        }

        // R6: sinais isolados (não consumidos por nenhum grupo), agrupados por servidor, viram uma
        // detecção de nível servidor. Sem ator: não há usuário/IP/share, e a resposta certa para
        // origem desconhecida é alertar/conter pela conta local, não bloquear um IP que não existe.
        foreach (var byServer in signals.Where(s => !consumed.Contains(s))
                     .GroupBy(s => s.Server, StringComparer.OrdinalIgnoreCase))
        {
            var reasons = new HashSet<DetectionReason>(byServer.Select(s => ReasonOf(s.Kind)).OfType<DetectionReason>());
            if (reasons.Count == 0) continue;   // só sinais informativos (ex.: visibilidade reparada) não viram detecção
            var first = byServer.Min(s => s.At);
            var last = byServer.Max(s => s.At);
            results.Add(new Detection(
                Server: byServer.Key,
                User: "",
                SourceIp: "",
                Share: "",
                Confidence: Score(reasons),
                Reasons: reasons,
                AffectedFiles: 0,
                FirstAt: first,
                LastAt: last));
        }

        return results;
    }

    /// <summary>Arquivos distintos (por caminho, sem distinção de caixa) num conjunto de eventos.</summary>
    private static int Files(IEnumerable<FileEvent> events) =>
        events.Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();

    /// <summary>
    /// Arquivos afetados = caminhos distintos gravados, renomeados ou apagados. Só quando não houve nenhum (ex.:
    /// leitura em massa) conta os caminhos lidos. Eventos de leitura de pasta que acompanham cada gravação não inflam o número.
    /// </summary>
    private static int AffectedFilesOf(IEnumerable<FileEvent> group)
    {
        var list = group as IReadOnlyCollection<FileEvent> ?? group.ToList();
        var changed = Files(list.Where(e => e.Op is FileOp.Write or FileOp.Rename or FileOp.Delete));
        return changed > 0 ? changed : Files(list);
    }

    private static DetectionReason? ReasonOf(HostSignalKind kind) => kind switch
    {
        HostSignalKind.VssDeleted => DetectionReason.VssDeletion,
        HostSignalKind.AgentTamper => DetectionReason.AgentTamper,
        HostSignalKind.BackupServiceStopped => DetectionReason.VssDeletion,
        HostSignalKind.AuditPolicyChanged or HostSignalKind.SecurityLogCleared
            or HostSignalKind.AuditDisabled => DetectionReason.VisibilityTamper,
        // D6: canário replantado, cópias reduzidas e utilitário de snapshot são indícios — Média sozinhos.
        HostSignalKind.CanaryMissing => DetectionReason.CanaryRemoved,
        HostSignalKind.VssReduced => DetectionReason.VssReduction,
        HostSignalKind.RecoveryToolUsed => DetectionReason.RecoveryToolUse,
        HostSignalKind.VisibilityRepaired => null,
        HostSignalKind.RecoveryTampering => DetectionReason.RecoveryTampering,
        HostSignalKind.ServiceInstalled => DetectionReason.ServiceInstalled,
        HostSignalKind.PrivilegedAccountChange => DetectionReason.PrivilegedAccountChange,
        HostSignalKind.LogonBruteForce => DetectionReason.LogonBruteForce,
        HostSignalKind.LogonFailure => null,   // bruto: só o agregador decide
        _ => DetectionReason.MassRewrite
    };

    private static Confidence Score(IReadOnlySet<DetectionReason> reasons)
    {
        if (reasons.Contains(DetectionReason.CanaryTouched)
            || reasons.Contains(DetectionReason.VssDeletion)
            || reasons.Contains(DetectionReason.AgentTamper)
            || reasons.Contains(DetectionReason.RansomNote)
            || reasons.Contains(DetectionReason.KnownRansomExtension)
            || reasons.Contains(DetectionReason.DecoyShareTouched)
            || reasons.Contains(DetectionReason.VisibilityTamper)
            || reasons.Contains(DetectionReason.RecoveryTampering)
            || reasons.Contains(DetectionReason.MassOverwrite))
            return Confidence.High;

        // G3: dois sinais de pré-cifra distintos no mesmo servidor/janela (ex.: força bruta + serviço novo, ou
        // admin novo + serviço novo) são o playbook em andamento — Alta mesmo sem nenhum arquivo tocado.
        // D6: os indícios fracos entram na mesma conta — nenhum contém sozinho, dois distintos sim.
        var preEncryption = new[]
        {
            DetectionReason.ServiceInstalled, DetectionReason.PrivilegedAccountChange, DetectionReason.LogonBruteForce,
            DetectionReason.VssReduction, DetectionReason.RecoveryToolUse, DetectionReason.CanaryRemoved
        };
        if (preEncryption.Count(reasons.Contains) >= 2)
            return Confidence.High;

        // D6: cópias de sombra diminuindo, ou o mesmo arquivo de nome suspeito espalhado, ENQUANTO o mesmo ator
        // regrava, renomeia ou apaga em massa — os dois juntos são o ataque; cada um sozinho é rotina.
        var destructive = new[]
        {
            DetectionReason.MassRewrite, DetectionReason.MassRename, DetectionReason.MassDelete, DetectionReason.ExtensionFlip,
            DetectionReason.SustainedRewrite, DetectionReason.RateAnomaly, DetectionReason.KnownExtensionSeen
        };
        if ((reasons.Contains(DetectionReason.VssReduction) || reasons.Contains(DetectionReason.NoteLikeFiles)) && reasons.Overlaps(destructive))
            return Confidence.High;

        var massReasons = new[]
        {
            DetectionReason.MassRewrite, DetectionReason.MassRename, DetectionReason.ExtensionFlip, DetectionReason.KnownExtensionSeen,
            DetectionReason.SustainedRewrite, DetectionReason.RateAnomaly, DetectionReason.MassRead, DetectionReason.MassDelete,
            DetectionReason.ServiceInstalled, DetectionReason.PrivilegedAccountChange, DetectionReason.LogonBruteForce,
            DetectionReason.VssReduction, DetectionReason.RecoveryToolUse, DetectionReason.CanaryRemoved, DetectionReason.NoteLikeFiles
        };
        if (reasons.Overlaps(massReasons))
            return Confidence.Medium;

        return Confidence.Low;
    }

    /// <summary>Deriva o nome do servidor de um caminho UNC (\\SERVER\Share) — metadado.</summary>
    private static string ServerOf(string share)
    {
        var trimmed = share.TrimStart('\\');
        var slash = trimmed.IndexOf('\\');
        return slash > 0 ? trimmed[..slash] : trimmed;
    }

}
