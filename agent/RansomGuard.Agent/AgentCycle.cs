using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;
using DetectionModel = RansomGuard.Core.Detection.Detection;

namespace RansomGuard.Agent;

/// <summary>
/// Resposta do painel a um lote. Só documentos assinados pela chave da instalação do painel têm efeito no agente:
/// a política de resposta e os comandos. Não há licença: quem liga a contenção é o administrador, pela política.
/// </summary>
/// <param name="Policy">F33: política de resposta assinada (ou null = mantém a vigente).</param>
/// <param name="Commands">F33: comandos assinados (reversões pedidas no painel).</param>
public sealed record BatchResponse(Core.Auth.SignedAssertion? Policy = null, Core.Auth.SignedAssertion? Commands = null);

/// <summary>Onde o agente guarda a última política assinada aceita (sobrevive a reinício).</summary>
public interface IPolicyStore
{
    Core.Auth.SignedAssertion? Load();
    void Save(Core.Auth.SignedAssertion policy);
}

/// <summary>
/// B5 — onde o agente lembra quais IPs da blocklist de rede ele bloqueou no firewall. Sem essa memória, um IP que
/// saísse da lista com o serviço parado ficaria bloqueado para sempre.
/// </summary>
public interface IAppliedBlocklistStore
{
    IReadOnlyCollection<string> Load();
    void Save(IReadOnlyCollection<string> ips);
}

/// <summary>Para onde o agente envia o lote coletado (o backend). Abstração testável.</summary>
public interface IBatchSink
{
    /// <returns>A resposta do painel, ou <c>null</c> se não deu para contatá-lo.</returns>
    Task<BatchResponse?> SendAsync(AgentBatch batch, CancellationToken ct = default);
}

/// <summary>Lote enviado pelo agente ao servidor (mesma forma consumida pela ingestão da fatia 2).</summary>
/// <param name="Incidents">F32: o que o agente detectou, decidiu e executou neste ciclo (verdade única). <c>null</c> só em
/// agentes antigos; o painel então re-analisa os eventos como fallback, marcando a origem.</param>
public sealed record AgentBatch(
    string Server,
    DateTime At,
    Core.Score.PostureSnapshot? Posture,
    IReadOnlyList<FileEvent> Events,
    IReadOnlyList<HostSignal> HostSignals,
    IReadOnlyList<Core.Incidents.AgentIncident>? Incidents = null,
    IReadOnlyList<Core.Policy.CommandOutcome>? CommandResults = null);

/// <summary>Resultado de um ciclo (para observabilidade/testes).</summary>
public sealed record CycleResult(
    int Events, int Detections, int LocalContainments, bool PostureSent);

/// <summary>
/// O loop de um ciclo do agente: coleta postura + eventos + sinais, roda a detecção (Core), decide a
/// resposta local (ResponseLadder) e executa a contenção conforme a política, e envia o lote ao
/// servidor. Lógica pura orquestrando o Core — testável com coletores/efetores/sink fake; os reais
/// entram no serviço Windows (fora da `.sln`).
/// </summary>
public sealed class AgentCycle
{
    private readonly string _server;
    private readonly IPostureCollector _posture;
    private readonly IFileEventCollector _events;
    private readonly IHostSignalCollector _signals;
    private readonly IBatchSink _sink;
    private readonly DetectionEngine _detect;
    private readonly ResponseLadder _ladder;
    private ResponsePolicy _policy;
    private readonly IPolicyStore? _policyStore;
    private bool _storedPolicyLoaded;
    private readonly HashSet<string> _executedCommands = new(StringComparer.Ordinal);
    private readonly HashSet<string> _appliedBlocklist = new(StringComparer.OrdinalIgnoreCase);
    private readonly IAppliedBlocklistStore? _blocklistStore;
    private readonly Queue.IBatchQueue? _queue;
    /// <summary>D2: quantas trocas observadas para a MESMA extensão fazem dela um padrão (uma troca isolada não ensina).</summary>
    public const int MinChangesToLearn = 5;
    /// <summary>D2: teto do que um agente acrescenta sozinho ao file screen, entre uma reinicialização e outra.</summary>
    public const int MaxLearnedExtensions = 16;
    // L3: ciclos seguidos do mesmo ataque são o mesmo incidente para o painel.
    private readonly Core.Incidents.IncidentEpisodes _episodes = new();
    private readonly HashSet<string> _learnedExtensions = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>G7: extensões observadas em incidentes de ALTA que não estão no catálogo — entram no file screen local na hora.</summary>
    public IReadOnlyCollection<string> LearnedExtensions => _learnedExtensions;
    /// <summary>F34: lotes aguardando o painel voltar (diagnóstico).</summary>
    public int QueuedBatches => _queue?.Count ?? 0;
    /// <summary>F34: lotes descartados por teto de quantidade/idade desde o início (diagnóstico).</summary>
    public int DroppedBatches { get; private set; }
    /// <summary>G4b: IPs atualmente bloqueados por política de rede (diagnóstico).</summary>
    public IReadOnlyCollection<string> AppliedBlocklist => _appliedBlocklist;
    private readonly List<Core.Policy.CommandOutcome> _pendingResults = new();

    /// <summary>Política vigente (registro/appsettings até o painel publicar uma assinada — F33).</summary>
    public ResponsePolicy Policy => _policy;
    public Core.Policy.PolicyOutcome? LastPolicyOutcome { get; private set; }
    public Core.Policy.PolicyOutcome? LastCommandsOutcome { get; private set; }
    private readonly IResponseExecutor _executor;
    private readonly Auth.PanelTrust? _trust;

    public AgentCycle(
        string server,
        IPostureCollector posture, IFileEventCollector events, IHostSignalCollector signals,
        IBatchSink sink, ResponseLadder ladder, ResponsePolicy policy, IResponseExecutor executor,
        DetectionOptions? detectionOptions = null,
        Auth.PanelTrust? trust = null, IPolicyStore? policyStore = null,
        ActorActivityTracker? tracker = null, Queue.IBatchQueue? queue = null,
        IAppliedBlocklistStore? blocklistStore = null)
    {
        _queue = queue;
        _blocklistStore = blocklistStore;
        try
        {
            foreach (var ip in blocklistStore?.Load() ?? Array.Empty<string>())
                if (ResponseTarget.IsSafe(ResponseStep.BlockIp, ip)) _appliedBlocklist.Add(ip);
        }
        catch (Exception) { /* memória ilegível: recomeça vazia; as regras existentes são idempotentes ao reaplicar */ }
        _trust = trust;
        _policyStore = policyStore;
        _server = server;
        _posture = posture;
        _events = events;
        _signals = signals;
        _sink = sink;
        _ladder = ladder;
        _policy = policy;
        _executor = executor;
        // G1: com tracker, a janela de 60 s atravessa ciclos e low-and-slow/anomalia passam a existir.
        _detect = new DetectionEngine(detectionOptions, tracker ?? new ActorActivityTracker());
    }

    /// <summary>
    /// E7 — idade máxima do último evento de um incidente para que ele ainda dispare ações. O agente normalmente lê
    /// o evento segundos depois; só passa disso quando esteve parado. Bloquear um IP ou negar uma conta por atividade
    /// de horas atrás não interrompe ataque nenhum e pode atingir quem herdou aquele endereço.
    /// </summary>
    public static readonly TimeSpan MaxActionAge = TimeSpan.FromMinutes(15);

    private static string Age(TimeSpan age) =>
        age.TotalHours >= 1 ? $"{(int)age.TotalHours} h {age.Minutes} min" : $"{(int)age.TotalMinutes} min";

    /// <summary>Executa um ciclo. <paramref name="collectPosture"/>: false para ciclos rápidos só de eventos.</summary>
    public async Task<CycleResult> RunOnceAsync(DateTime now, bool collectPosture = true, CancellationToken ct = default)
    {
        // F33: ao subir, reaplica a última política assinada aceita (verificada de novo contra a chave fixada).
        if (!_storedPolicyLoaded && _policyStore is not null && _trust is { HasKey: true })
        {
            _storedPolicyLoaded = true;
            var stored = _trust.EvaluatePolicy(_policyStore.Load(), _server, now);
            if (stored.Outcome == Core.Policy.PolicyOutcome.Valid) _policy = stored.Policy!.ToResponsePolicy();
        }

        var posture = collectPosture ? _posture.Collect(_server) : null;
        var events = _events.Drain();
        var signals = _signals.Drain();

        // R6: analisa quando há eventos OU sinais de host. Uma deleção de VSS / tamper do agente sem
        // evento de arquivo no ciclo ainda é incidente — é o primeiro passo do playbook.
        var detections = events.Count > 0 || signals.Count > 0
            ? _detect.Analyze(events, signals)
            : Array.Empty<DetectionModel>();

        var containments = 0;
        var incidents = new List<Core.Incidents.AgentIncident>(detections.Count);
        foreach (var d in detections)
        {
            var decision = _ladder.Decide(d, _policy);
            // E7: evento antigo (agente parado e retomando o log) é registrado e alertado, não contido.
            if (decision.Actions.Count > 0 && now - d.LastAt > MaxActionAge)
                decision = ResponseDecision.AlertOnly(
                    $"Evento antigo ({Age(now - d.LastAt)} atrás, lido ao retomar o log) — registrado e alertado, sem contenção: " +
                    "agir agora atingiria quem já não está atacando.");
            var runner = new ResponseRunner(_executor);
            // R4: conta a contenção REAL (o que o executor confirmou), não a decidida.
            containments += await runner.RunAsync(decision, now, ct: ct);
            // F32: detecção + decisão + trilha de execução viajam juntas para o painel.
            incidents.Add(Core.Incidents.AgentIncident.From(d, decision, runner.Audit, _policy.Mode, _episodes.IdFor(d)));
            // G7: a extensão que um incidente de ALTA usou vira file screen dinâmico neste servidor (sem esperar o catálogo).
            // D2: só o que foi visto como TROCA (original apagado + cifrado gravado), repetida, para uma extensão que não
            // é de trabalho, e até um teto. O que o ator apenas gravou durante o incidente não ensina nada.
            if (d.Confidence == Confidence.High)
                foreach (var ext in LearnableExtensions(events.Where(e => e.User.Equals(d.User, StringComparison.OrdinalIgnoreCase)
                                                                       && e.SourceIp.Equals(d.SourceIp, StringComparison.OrdinalIgnoreCase))))
                    if (_learnedExtensions.Count < MaxLearnedExtensions)
                        _learnedExtensions.Add(ext);
        }

        // F34: antes do lote atual, reentrega o que ficou na fila (em ordem, aos poucos). Se o painel ainda está fora,
        // para na primeira falha — o lote atual também vai para a fila.
        // Sessão 5 do laboratório: com o painel fora, cada tentativa pode prender o ciclo por segundos (conexão sem
        // resposta). Depois de uma falha, não toca a rede até passar a espera — o lote vai direto para a fila.
        var tryPanel = now >= _panelRetryAt;
        var panelReachable = tryPanel && await FlushQueueAsync(now, ct);

        var results = _pendingResults.ToList();
        var current = new AgentBatch(_server, now, posture, events, signals, incidents, results);
        var response = panelReachable ? await _sink.SendAsync(current, ct) : null;
        if (tryPanel) NotePanelContact(now, reached: response is not null);
        if (response is not null) _pendingResults.RemoveAll(results.Contains);   // entregue: não repete
        else if (_queue is not null && Queue.BatchQueuePolicy.WorthQueuing(current))
        {
            _queue.Enqueue(current);
            _pendingResults.RemoveAll(results.Contains);   // viajam dentro do lote enfileirado
            DroppedBatches += _queue.Prune(now, Queue.BatchQueuePolicy.MaxQueuedBatches, Queue.BatchQueuePolicy.MaxAge);
        }

        // F33: política assinada pelo painel substitui a do registro; comandos (reversões) são executados uma vez.
        // Só o que passa na verificação (assinatura da chave fixada, servidor, anti-rollback) tem efeito: um painel
        // falso na rede não muda o modo nem dispara comando.
        if (_trust is not null && response is not null)
        {
            if (response.Policy is not null)
            {
                var pr = _trust.EvaluatePolicy(response.Policy, _server, now);
                LastPolicyOutcome = pr.Outcome;
                if (pr.Outcome == Core.Policy.PolicyOutcome.Valid)
                {
                    _policy = pr.Policy!.ToResponsePolicy();
                    _policyStore?.Save(response.Policy);
                    await ApplyNetworkBlocklistAsync(pr.Policy.NetworkBlocklist, now, ct);
                }
            }
            if (response.Commands is not null)
            {
                var cr = _trust.EvaluateCommands(response.Commands, _server, now);
                LastCommandsOutcome = cr.Outcome;
                if (cr.Outcome == Core.Policy.PolicyOutcome.Valid)
                    await ExecuteCommandsAsync(cr.Envelope!, now, ct);
            }
        }

        return new CycleResult(events.Count, detections.Count, containments, posture is not null);
    }

    /// <summary>
    /// G4b: converge o firewall local para a blocklist assinada — bloqueia o que entrou, libera o que saiu. Só IPs
    /// válidos (ResponseTarget) chegam ao executor; o modo não importa: bloquear um IP já condenado em outro
    /// servidor é higiene de rede, não contenção local.
    /// </summary>
    /// <summary>Reentrega lotes da fila; devolve false se o painel continua inacessível.</summary>
    /// <summary>
    /// Extensões que os eventos de um ator autorizam a aprender: destino de pelo menos <see cref="MinChangesToLearn"/>
    /// trocas observadas, com nome bem formado e fora das extensões de trabalho (bloquear .dwg ou .sql no file
    /// screen seria o próprio incidente). As mais frequentes primeiro.
    /// </summary>
    private static IEnumerable<string> LearnableExtensions(IEnumerable<FileEvent> actorEvents) =>
        ExtensionChanges.Observed(actorEvents)
            .GroupBy(c => c.NewExtension, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() >= MinChangesToLearn)
            .OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.Key.ToLowerInvariant())
            .Where(ext => ext.Length is > 1 and <= 16 && ext.StartsWith('.')
                          && ext.Skip(1).All(ch => char.IsLetterOrDigit(ch) || ch is '_' or '-')
                          && !LegitExtensions.Contains(ext));

    /// <summary>Primeira espera depois de uma falha de envio; dobra a cada falha seguida, até <see cref="PanelRetryMax"/>.</summary>
    public static readonly TimeSpan PanelRetryMin = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan PanelRetryMax = TimeSpan.FromMinutes(2);
    private DateTime _panelRetryAt = DateTime.MinValue;
    private TimeSpan _panelRetryDelay = TimeSpan.Zero;

    private void NotePanelContact(DateTime now, bool reached)
    {
        if (reached) { _panelRetryDelay = TimeSpan.Zero; _panelRetryAt = DateTime.MinValue; return; }
        _panelRetryDelay = _panelRetryDelay == TimeSpan.Zero ? PanelRetryMin
            : TimeSpan.FromTicks(Math.Min(_panelRetryDelay.Ticks * 2, PanelRetryMax.Ticks));
        _panelRetryAt = now + _panelRetryDelay;
    }

    private async Task<bool> FlushQueueAsync(DateTime now, CancellationToken ct)
    {
        if (_queue is null || _queue.Count == 0) return true;
        DroppedBatches += _queue.Prune(now, Queue.BatchQueuePolicy.MaxQueuedBatches, Queue.BatchQueuePolicy.MaxAge);
        foreach (var queued in _queue.Peek(Queue.BatchQueuePolicy.FlushPerCycle))
        {
            var r = await _sink.SendAsync(queued, ct);
            if (r is null) return false;
            _queue.DequeueOldest();
            // A resposta a um lote antigo não é aplicada: a política e os comandos vêm na resposta do lote atual.
        }
        return true;
    }

    /// <summary>
    /// Laboratório, sessão 4: regra removida por fora (administrador, ou invasor com direito de administrador) não era
    /// recolocada — o agente achava que o IP seguia bloqueado. A cada intervalo, a blocklist inteira é reafirmada.
    /// </summary>
    public static readonly TimeSpan BlocklistReassertEvery = TimeSpan.FromMinutes(10);
    private DateTime _lastBlocklistAssert = DateTime.MinValue;

    private async Task ApplyNetworkBlocklistAsync(IReadOnlyList<string> blocklist, DateTime now, CancellationToken ct)
    {
        var wanted = new HashSet<string>(blocklist.Where(ip => ResponseTarget.IsSafe(ResponseStep.BlockIp, ip)), StringComparer.OrdinalIgnoreCase);
        var reassert = now - _lastBlocklistAssert >= BlocklistReassertEvery;
        if (reassert) _lastBlocklistAssert = now;
        foreach (var ip in wanted.Where(ip => reassert || !_appliedBlocklist.Contains(ip)).ToList())
        {
            var outcome = await _executor.ExecuteAsync(new ResponseAction(ResponseStep.BlockIp, _server, ip, "blocklist de rede (política do painel)"), ct);
            if (outcome.Status == ResponseStatus.Executed) _appliedBlocklist.Add(ip);
        }
        foreach (var ip in _appliedBlocklist.Where(ip => !wanted.Contains(ip)).ToList())
        {
            var outcome = await _executor.RevertAsync(new ResponseAction(ResponseStep.BlockIp, _server, ip, "removido da blocklist de rede"), ct);
            if (outcome.Status != ResponseStatus.Failed) _appliedBlocklist.Remove(ip);
        }
        try { _blocklistStore?.Save(_appliedBlocklist.ToList()); }
        catch (Exception) { /* segue em memória; na próxima política tenta gravar de novo */ }
    }

    private async Task ExecuteCommandsAsync(Core.Policy.CommandEnvelope env, DateTime now, CancellationToken ct)
    {
        foreach (var cmd in env.Commands)
        {
            if (!_executedCommands.Add(cmd.Id)) continue;                 // idempotente: o painel pode reenviar
            var action = cmd.Kind == Core.Policy.AgentCommand.Revert ? cmd.ToAction(_server) : null;
            if (action is null || !ResponseTarget.IsSafe(action))
            {
                _pendingResults.Add(new(cmd.Id, "Skipped", "comando desconhecido ou alvo inseguro", now));
                continue;
            }
            var outcome = await _executor.RevertAsync(action, ct);
            _pendingResults.Add(new(cmd.Id, outcome.Status.ToString(), outcome.Detail, now));
        }
    }
}
