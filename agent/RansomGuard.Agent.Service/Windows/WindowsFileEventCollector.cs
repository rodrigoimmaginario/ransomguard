using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Service.Windows;

/// <summary>
/// O Security log do Windows como fonte do coletor. Toda a filtragem acontece no serviço de eventos:
/// só os tipos de interesse e só o que veio depois do cursor (A1) — o log não é percorrido em C#.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsSecurityLogSource : ISecurityLogSource
{
    // 4663/5145: arquivos. G2: 4719 (política de auditoria) e 1102 (log limpo). G3: 4688 (processo com linha de
    // comando), 4697 (serviço), 4720/4728/4732/4756 (conta/grupo privilegiado), 4625 (falha de logon).
    public const string EventFilter =
        "EventID=4663 or EventID=5145 or EventID=4719 or EventID=1102 or EventID=4688 or EventID=4697"
        + " or EventID=4720 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4625";

    /// <summary>
    /// E3 — violações de file screen: o FSRM (provedor SRMSVC) grava o 8215 no log de Aplicativo. O texto é o que o
    /// produto configurou na notificação; eventos de outros file screens passam pelo filtro e são descartados pelo parser.
    /// </summary>
    public const string FsrmFilter = "Provider[@Name='SRMSVC'] and (EventID=8215)";

    private readonly string _logName;
    private readonly string _filter;

    /// <param name="logName">Log de eventos a ler.</param>
    /// <param name="filter">Condição XPath sobre <c>System</c> (tipos/provedor de interesse).</param>
    public WindowsSecurityLogSource(string logName = "Security", string? filter = null)
    {
        _logName = logName;
        _filter = filter ?? $"({EventFilter})";
    }

    /// <summary>O log de Aplicativo, só com as violações de file screen do FSRM.</summary>
    public static WindowsSecurityLogSource ForFsrm() => new("Application", FsrmFilter);

    /// <summary>Consulta XPath: eventos de interesse com RecordId acima do cursor.</summary>
    public string QueryAfter(long recordId) =>
        $"*[System[{_filter} and (EventRecordID > {Math.Max(0, recordId)})]]";

    public long? NewestRecordId()
    {
        using var reader = new EventLogReader(new EventLogQuery(_logName, PathType.LogName) { ReverseDirection = true });
        using var rec = reader.ReadEvent();
        return rec?.RecordId;
    }

    public IEnumerable<SecurityLogRecord> ReadAfter(long recordId, int max)
    {
        using var reader = new EventLogReader(new EventLogQuery(_logName, PathType.LogName, QueryAfter(recordId)));
        var read = 0;
        while (read < max && reader.ReadEvent() is { } rec)
        {
            using (rec)
            {
                read++;
                string xml;
                try { xml = rec.ToXml(); }
                catch (EventLogException) { xml = ""; }   // evento truncado: o id ainda avança o cursor
                yield return new SecurityLogRecord(rec.RecordId ?? 0, xml);
            }
        }
    }
}

/// <summary>
/// Coletor real de eventos de arquivo. Lê o **Security log** (4663 e 5145), traduz com o
/// <see cref="SecurityEventParser"/>, dá a cada evento o share canônico (<see cref="ShareMap"/>) e atribui
/// origem com o <see cref="SessionCorrelator"/>. A lógica de retomada vive no
/// <see cref="SecurityLogCollector"/> (testável); aqui ficam o Windows e o registro de falhas.
///
/// **Pré-requisitos que o agente não pode criar sozinho:** a auditoria de acesso precisa estar
/// ligada (o Score já reporta isso) e o serviço precisa de direito de leitura no Security log.
/// Faltando qualquer um, o coletor **avisa** — não fica em silêncio fingindo que está tudo calmo.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsFileEventCollector : IFileEventCollector
{
    private readonly ILogger<WindowsFileEventCollector> _log;
    private readonly SecurityLogCollector _core;

    /// <summary>Falhas seguidas de leitura — vira sinal de host, não silêncio (F11c).</summary>
    public int ConsecutiveFailures { get; private set; }

    /// <param name="shares">Tabela de shares do servidor (D1). Padrão: registro do LanmanServer desta máquina.</param>
    /// <param name="readSessions">Sessões SMB abertas. Padrão: <c>Get-SmbSession</c>, só quando há evento sem origem.</param>
    /// <param name="source">Fonte de eventos. Padrão: o Security log.</param>
    /// <param name="fsrmCursor">
    /// E3: cursor do log onde o FSRM grava as violações do file screen. Informado, o coletor passa a ler esses
    /// eventos — é por eles que uma renomeação para extensão do catálogo aparece. <c>null</c> = não lê.
    /// </param>
    public WindowsFileEventCollector(
        ILogger<WindowsFileEventCollector> log,
        EventCursor cursor,
        Func<ShareMap>? shares = null,
        Func<IReadOnlyList<SmbSession>>? readSessions = null,
        HostSignalBuffer? signals = null,
        ISecurityLogSource? source = null,
        EventCursor? fsrmCursor = null)
    {
        _log = log;
        var table = shares ?? new WindowsShareTable(Environment.MachineName).Current;
        _core = new SecurityLogCollector(source ?? new WindowsSecurityLogSource(), cursor, table,
            readSessions ?? DefaultReadSessions, signals, LogSignal,
            fsrmSource: fsrmCursor is null ? null : WindowsSecurityLogSource.ForFsrm(), fsrmCursor: fsrmCursor,
            // Laboratório, sessão 3: a data de criação no disco diz se a gravação foi num arquivo que já existia.
            creationTimeOf: path => File.Exists(path) ? File.GetCreationTimeUtc(path) : null);
    }

    public IReadOnlyList<FileEvent> Drain()
    {
        try
        {
            var eventos = _core.Drain();
            ConsecutiveFailures = 0;
            if (_core.LastDrain.Baselined)
                _log.LogInformation("Primeira execução neste servidor: a leitura do Security log começa a partir de agora (histórico não é reprocessado).");
            if (_core.LastDrain.Truncated)
                _log.LogWarning("Mais de {Max} eventos novos num ciclo; o restante vem no próximo.", SecurityLogCollector.MaxPerCycle);
            return eventos;
        }
        catch (UnauthorizedAccessException ex)
        {
            ConsecutiveFailures++;
            _log.LogError(ex, "Sem permissão para ler o Security log. O agente está CEGO — " +
                              "o serviço precisa de direito de leitura no log de segurança.");
            return Array.Empty<FileEvent>();
        }
        catch (Exception ex)
        {
            ConsecutiveFailures++;
            _log.LogError(ex, "Falha ao ler eventos de segurança (tentativa {N})", ConsecutiveFailures);
            return Array.Empty<FileEvent>();
        }
    }

    private void LogSignal(HostSignal signal)
    {
        switch (signal.Kind)
        {
            case HostSignalKind.LogonFailure:
                break;   // bruto: só o agregador decide se é rajada
            case HostSignalKind.AuditPolicyChanged or HostSignalKind.SecurityLogCleared:
                _log.LogError("Sinal de visibilidade: {Detail}", signal.Detail);
                break;
            default:
                _log.LogWarning("Sinal de pré-cifra: {Detail}", signal.Detail);
                break;
        }
    }

    /// <summary>Sessões SMB abertas, em formato próprio (uma por linha) — não a tabela que o PowerShell desenha para humanos.</summary>
    public static IReadOnlyList<SmbSession> DefaultReadSessions() =>
        SessionCorrelator.ParseSessionLines(PowerShellRunner.Run(SessionCorrelator.SessionLinesCommand));
}
