using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Sensors;

/// <summary>Um registro de um log de eventos do Windows: o id que o cursor persiste e o XML do evento.</summary>
public readonly record struct SecurityLogRecord(long RecordId, string Xml);

/// <summary>
/// Um log de eventos visto pelo coletor (o Security log; o log de Aplicativo para o FSRM). A implementação real
/// (serviço Windows) filtra no servidor de eventos; aqui só importa o contrato, para a lógica de retomada ser
/// testável sem Windows.
/// </summary>
public interface ISecurityLogSource
{
    /// <summary>Maior RecordId presente no log (qualquer evento), ou <c>null</c> se o log está vazio. Custo constante.</summary>
    long? NewestRecordId();

    /// <summary>Eventos de interesse com RecordId maior que <paramref name="recordId"/>, em ordem crescente, no máximo <paramref name="max"/>.</summary>
    IEnumerable<SecurityLogRecord> ReadAfter(long recordId, int max);
}

/// <summary>O que aconteceu na última drenagem — para log e diagnóstico do serviço.</summary>
/// <param name="Baselined">Primeira execução: a posição foi fixada no evento mais novo, sem ler histórico.</param>
/// <param name="Truncated">Havia mais eventos do que cabe num ciclo; o restante vem no próximo.</param>
/// <param name="Read">Registros lidos dos logs neste ciclo.</param>
public sealed record DrainInfo(bool Baselined, bool Truncated, int Read);

/// <summary>
/// A1 — leitura incremental dos logs de eventos.
///
/// Três regras que a versão anterior não cumpria:
/// <list type="number">
///   <item><b>Só o que é novo.</b> A consulta parte do cursor; o log não é relido a cada ciclo.</item>
///   <item><b>Sem passado.</b> Sem posição salva (agente recém-instalado), parte do evento mais novo: o histórico
///   de um log de 1 GB não é ataque em andamento, e reprocessá-lo atrasaria em minutos a visão do presente.</item>
///   <item><b>Sem perda no teto.</b> Numa tempestade, entrega <see cref="MaxPerCycle"/> eventos e retoma exatamente
///   no seguinte.</item>
/// </list>
/// E3 — além do Security log, lê (quando configurado) os eventos do file screen do FSRM, com cursor próprio: é a
/// única fonte que mostra o nome de destino de uma renomeação.
///
/// Erros da fonte sobem para o chamador (o serviço conta falhas seguidas e as transforma em sinal).
/// </summary>
public sealed class SecurityLogCollector : IFileEventCollector
{
    public const int MaxPerCycle = 5_000;

    private readonly ISecurityLogSource _source;
    private readonly EventCursor _cursor;
    private readonly ISecurityLogSource? _fsrmSource;
    private readonly EventCursor? _fsrmCursor;
    private readonly Func<ShareMap> _shares;
    private readonly Func<IReadOnlyList<SmbSession>> _sessions;
    private readonly HostSignalBuffer? _signals;
    private readonly Action<HostSignal>? _onSignal;

    public DrainInfo LastDrain { get; private set; } = new(false, false, 0);

    /// <param name="sessions">Sessões SMB abertas; consultadas só quando há evento sem origem (o 5145 já traz o IP).</param>
    /// <param name="onSignal">Chamado para cada sinal de host extraído do log (o serviço registra em log).</param>
    /// <param name="fsrmSource">Log onde o FSRM grava as violações do file screen (Aplicativo). <c>null</c> = não lê.</param>
    /// <param name="fsrmCursor">Cursor próprio desse log.</param>
    private readonly Func<string, DateTime?>? _creationTimeOf;

    public SecurityLogCollector(ISecurityLogSource source, EventCursor cursor, Func<ShareMap> shares,
        Func<IReadOnlyList<SmbSession>> sessions, HostSignalBuffer? signals = null, Action<HostSignal>? onSignal = null,
        ISecurityLogSource? fsrmSource = null, EventCursor? fsrmCursor = null, Func<string, DateTime?>? creationTimeOf = null)
    {
        _creationTimeOf = creationTimeOf;
        _source = source;
        _cursor = cursor;
        _shares = shares;
        _sessions = sessions;
        _signals = signals;
        _onSignal = onSignal;
        _fsrmSource = fsrmSource;
        _fsrmCursor = fsrmSource is null ? null : fsrmCursor ?? throw new ArgumentNullException(nameof(fsrmCursor));
    }

    public IReadOnlyList<FileEvent> Drain()
    {
        var parsed = new List<ParsedFileEvent>();
        var screen = new List<ParsedFileEvent>();

        var security = ReadTail(_source, _cursor, xml =>
        {
            if (SecurityEventParser.ParseDetailed(xml) is { } file) { parsed.Add(file); return; }
            if (_signals is null) return;
            // G2: eventos sobre o próprio log/auditoria; G3: pré-cifra (o 4625 bruto é agregado depois).
            var signal = VisibilityEventParser.Parse(xml) ?? PreEncryptionEventParser.Parse(xml);
            if (signal is null) return;
            _signals.Push(signal);
            _onSignal?.Invoke(signal);
        });

        var fsrm = _fsrmSource is null
            ? new DrainInfo(false, false, 0)
            : ReadTail(_fsrmSource, _fsrmCursor!, xml => { if (FsrmEventParser.Parse(xml) is { } v) screen.Add(v); });

        LastDrain = new DrainInfo(security.Baselined, security.Truncated || fsrm.Truncated, security.Read + fsrm.Read);

        if (parsed.Count == 0 && screen.Count == 0) return Array.Empty<FileEvent>();

        var map = _shares();
        var events = MarkOverwrites(parsed).Select(map.Canonicalize).ToList();
        var screenEvents = screen.Select(map.Canonicalize).ToList();

        // O FSRM não conhece o IP do cliente. Uma violação vinda pela rede (sem processo local) herda a origem do
        // evento de share mais recente do MESMO usuário neste ciclo; sem isso, tenta as sessões abaixo.
        if (screenEvents.Count > 0)
        {
            var ipByUser = events
                .Where(e => e.SourceIp != SecurityEventParser.LocalOrigin)
                .GroupBy(e => e.User, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.OrderBy(e => e.At).Last().SourceIp, StringComparer.OrdinalIgnoreCase);
            events.AddRange(screenEvents.Select(e =>
                e.ProcessId is null && ipByUser.TryGetValue(e.User, out var ip) ? e with { SourceIp = ip } : e));
        }

        // L11 (laboratório, sessão 2): evento sem origem e sem processo local do MESMO usuário que, neste ciclo, acessou
        // pela rede herda essa origem. No laboratório as sessões SMB já tinham caído com a contenção quando o evento de
        // objeto chegou — e ele virava um segundo incidente, "local", sem IP.
        if (events.Any(NeedsSession))
        {
            var networkIpByUser = events
                .Where(e => e.SourceIp != SecurityEventParser.LocalOrigin)
                .GroupBy(e => e.User, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.OrderBy(e => e.At).Last().SourceIp, StringComparer.OrdinalIgnoreCase);
            if (networkIpByUser.Count > 0)
                events = events.Select(e => NeedsSession(e) && networkIpByUser.TryGetValue(e.User, out var ip) ? e with { SourceIp = ip } : e).ToList();
        }

        // Só eventos sem origem e sem processo local justificam consultar as sessões.
        if (events.Any(NeedsSession))
        {
            IReadOnlyList<SmbSession> sessions;
            try { sessions = _sessions(); }
            catch (Exception) { sessions = Array.Empty<SmbSession>(); }   // sem sessões: local continua local, nunca atribuição errada
            if (sessions.Count > 0)
                events = events.Select(e => NeedsSession(e) ? SessionCorrelator.Attribute(e, sessions) : e).ToList();
        }
        return events;
    }

    /// <summary>
    /// Evento sem IP que pode ter vindo pela rede: sem processo, ou atribuído ao sistema (PID 4, que é quem serve SMB).
    /// Um processo local identificado é local — atribuí-lo ao IP de uma sessão que o mesmo usuário tenha aberta
    /// mandaria a contenção para a estação errada e esconderia o processo que deveria ser encerrado.
    /// </summary>
    private static bool NeedsSession(FileEvent e) =>
        e.SourceIp == SecurityEventParser.LocalOrigin && e.ProcessId is null or <= 4;

    /// <summary>
    /// Laboratório, sessão 3 — marca a gravação num arquivo que já existia: a data de criação no disco é anterior à
    /// gravação. Um arquivo regravado no lugar mantém a data antiga; um arquivo novo nasce com ela no instante da
    /// gravação. Arquivo que já não está lá (renomeado, apagado) ou que não se consegue consultar fica sem marca.
    /// Uma consulta por arquivo gravado por ciclo, com teto.
    /// </summary>
    private IEnumerable<ParsedFileEvent> MarkOverwrites(List<ParsedFileEvent> parsed)
    {
        if (_creationTimeOf is null) return parsed;
        var created = new Dictionary<string, DateTime?>(StringComparer.OrdinalIgnoreCase);
        return parsed.Select(p =>
        {
            if (p.Event.Op != FileOp.Write || string.IsNullOrWhiteSpace(p.LocalFullPath)) return p;
            if (!created.TryGetValue(p.LocalFullPath!, out var at))
            {
                if (created.Count >= MaxCreationLookups) return p;
                try { at = _creationTimeOf(p.LocalFullPath!); } catch (Exception) { at = null; }
                created[p.LocalFullPath!] = at;
            }
            return at is { } c && c < p.Event.At - OverwriteMinimumAge ? p with { Event = p.Event with { Overwrite = true } } : p;
        });
    }

    /// <summary>Arquivo criado há mais que isto, quando gravado, conta como regravação de arquivo existente.</summary>
    public static readonly TimeSpan OverwriteMinimumAge = TimeSpan.FromMinutes(2);
    private const int MaxCreationLookups = 5_000;

    /// <summary>Lê o que é novo de um log, aplicando linha de base, reinício por limpeza e teto por ciclo.</summary>
    private static DrainInfo ReadTail(ISecurityLogSource source, EventCursor cursor, Action<string> onRecord)
    {
        var newest = source.NewestRecordId();

        if (!cursor.HasSavedPosition)
        {
            cursor.Baseline(newest ?? 0);
            return new DrainInfo(true, false, 0);
        }

        // Limpeza do log (passo de playbook, no caso do Security log) reinicia os RecordIds: sem isto o cursor ficaria
        // à frente de tudo e o agente cegaria em definitivo.
        if (newest is { } n) cursor.NoticeNewest(n);

        var read = 0;
        var truncated = false;
        var last = cursor.LastRecordId;

        foreach (var rec in source.ReadAfter(cursor.LastRecordId, MaxPerCycle + 1))
        {
            if (read == MaxPerCycle) { truncated = true; break; }   // o registro excedente fica para o próximo ciclo
            read++;
            last = Math.Max(last, rec.RecordId);
            onRecord(rec.Xml);
        }

        // Sem teto atingido, o cursor acompanha a ponta do log: eventos fora do filtro não são relidos depois.
        cursor.Advance(truncated ? last : Math.Max(last, newest ?? last));
        return new DrainInfo(false, truncated, read);
    }
}
