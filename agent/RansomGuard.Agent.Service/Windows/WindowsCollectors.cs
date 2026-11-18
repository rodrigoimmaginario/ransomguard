using System.Runtime.Versioning;
using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Service.Windows;

// A postura real vive em WindowsPostureCollector.cs e os eventos em WindowsFileEventCollector.cs.

/// <summary>
/// Coletor real de sinais de host. Duas coisas, ambas de alta confiança:
///
/// <list type="number">
///   <item><b>Cópias de sombra apagadas</b> — passo quase universal do playbook, feito antes de
///   pedir resgate para tirar a saída fácil da vítima. Detectado por queda na contagem, não por
///   evento: o utilitário de linha de comando do VSS e a API de backup produzem rastros diferentes (ou
///   nenhum), mas o sumiço das cópias é observável de qualquer jeito.</item>
///   <item><b>Saúde do próprio sensor</b> — se o coletor de eventos falha repetidamente, o agente
///   está cego e precisa dizer isso. Silêncio no painel pareceria calmaria.</item>
/// </list>
///
/// A decisão vive no lib testável (<see cref="VssWatcher"/>, <see cref="SensorHealth"/>); aqui só
/// a leitura do WMI.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsHostSignalCollector : IHostSignalCollector
{
    private readonly ILogger<WindowsHostSignalCollector> _log;
    private readonly VssWatcher _vss;
    private readonly string _server;
    private readonly Func<int> _sensorFailures;
    private readonly RansomGuard.Agent.Sensors.HostSignalBuffer? _buffer;
    private readonly RansomGuard.Agent.Sensors.LogonFailureAggregator _logons = new();
    private readonly SystemLogServiceInstallReader? _system;
    private readonly Func<int?> _countShadowCopies;
    private readonly Func<DateTime> _clock;
    private DateTime _lastVssRead = DateTime.MinValue;

    /// <summary>
    /// D5 — as cópias de sombra são contadas neste intervalo, não a cada ciclo de 1–5 s: apagar o VSS não precisa
    /// ser visto em um segundo, e consultar a cada ciclo custava um processo auxiliar (e um evento 4688) por vez.
    /// </summary>
    public static readonly TimeSpan VssInterval = TimeSpan.FromSeconds(30);

    /// <param name="sensorFailures">Falhas seguidas do coletor de eventos (injetado para não acoplar).</param>
    /// <param name="buffer">G2: sinais produzidos fora do ciclo (visibilidade, canário sumido).</param>
    /// <param name="countShadowCopies">Contagem de cópias de sombra. Padrão: WMI em processo.</param>
    public WindowsHostSignalCollector(
        ILogger<WindowsHostSignalCollector> log, string server, Func<int>? sensorFailures = null,
        RansomGuard.Agent.Sensors.HostSignalBuffer? buffer = null,
        Func<int?>? countShadowCopies = null, Func<DateTime>? clock = null)
    {
        _log = log;
        _server = server;
        _vss = new VssWatcher(server);
        _sensorFailures = sensorFailures ?? (() => 0);
        _buffer = buffer;
        _system = buffer is null ? null : new SystemLogServiceInstallReader(log);
        _countShadowCopies = countShadowCopies ?? WindowsShadowCopies.TryCount;
        _clock = clock ?? (() => DateTime.UtcNow);
    }

    public IReadOnlyList<HostSignal> Drain()
    {
        var now = _clock();
        var sinais = new List<HostSignal>();

        if (now - _lastVssRead >= VssInterval)
        {
            _lastVssRead = now;
            if (_vss.Observe(ContarShadowCopies(), now) is { } vss)
            {
                _log.LogWarning("Sinal de alta confiança: {Detail}", vss.Detail);
                sinais.Add(vss);
            }
        }

        if (SensorHealth.Evaluate(_sensorFailures(), _server, now) is { } saude)
        {
            _log.LogError("Sinal de saúde do sensor: {Detail}", saude.Detail);
            sinais.Add(saude);
        }

        if (_buffer is not null)
        {
            // G2/G3: sinais fora do ciclo + 7045 do System log; 4625 bruto vira força bruta só em rajada.
            var pending = _buffer.Drain().ToList();
            if (_system is not null) pending.AddRange(_system.Drain());
            sinais.AddRange(_logons.Aggregate(pending));
        }

        return sinais;
    }

    /// <summary><c>null</c> quando não deu para contar — o watcher trata como "não sei".</summary>
    private int? ContarShadowCopies()
    {
        try
        {
            return _countShadowCopies();
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Não foi possível contar as cópias de sombra");
            return null;
        }
    }
}

/// <summary>
/// D5 — contagem de cópias de sombra por WMI, dentro do próprio processo. Sem <c>powershell.exe</c>: nenhum
/// processo criado, nenhum evento 4688 gerado pelo próprio agente.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WindowsShadowCopies
{
    /// <summary><c>null</c> quando a consulta não pôde ser feita (sem privilégio, WMI indisponível).</summary>
    public static int? TryCount()
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(@"root\cimv2", "SELECT ID FROM Win32_ShadowCopy");
            using var results = searcher.Get();
            return results.Count;
        }
        catch (Exception)
        {
            return null;
        }
    }
}

/// <summary>
/// G3 — 7045 (serviço instalado) vive no System log, não no Security. Leitor próprio, com cursor em memória
/// (no primeiro ciclo só memoriza o ponto atual: instalar o agente não pode gerar um sinal contra ele mesmo).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SystemLogServiceInstallReader(ILogger log)
{
    private long _lastRecord = -1;

    public IReadOnlyList<HostSignal> Drain()
    {
        var result = new List<HostSignal>();
        try
        {
            var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(
                new System.Diagnostics.Eventing.Reader.EventLogQuery("System", System.Diagnostics.Eventing.Reader.PathType.LogName, "*[System[(EventID=7045)]]"));
            long newest = _lastRecord;
            for (var rec = reader.ReadEvent(); rec is not null; rec = reader.ReadEvent())
            {
                using (rec)
                {
                    var id = rec.RecordId ?? 0;
                    if (id > newest) newest = id;
                    if (_lastRecord < 0 || id <= _lastRecord) continue;
                    string xml;
                    try { xml = rec.ToXml(); } catch (System.Diagnostics.Eventing.Reader.EventLogException) { continue; }
                    if (RansomGuard.Agent.Sensors.PreEncryptionEventParser.Parse(xml) is { } s) { log.LogWarning("Sinal de pré-cifra: {Detail}", s.Detail); result.Add(s); }
                }
            }
            _lastRecord = newest;
        }
        catch (Exception ex)
        {
            log.LogDebug(ex, "System log (7045) indisponível neste ciclo.");
        }
        return result;
    }
}
