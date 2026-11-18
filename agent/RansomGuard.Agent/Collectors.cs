using RansomGuard.Core.Detection;
using RansomGuard.Core.Score;

namespace RansomGuard.Agent;

/// <summary>
/// Coleta o retrato de postura do servidor (SMB, shares, VSS, auditoria…). A implementação real lê
/// o Windows (registro/WMI/cmdlets) e vive no serviço; aqui é abstração testável.
/// </summary>
public interface IPostureCollector
{
    PostureSnapshot Collect(string server);
}

/// <summary>Coleta eventos de arquivo desde a última chamada (EventLog 4663/5145, USN).</summary>
public interface IFileEventCollector
{
    IReadOnlyList<FileEvent> Drain();
}

/// <summary>Coleta sinais de host (deleção de VSS, backup parado) desde a última chamada.</summary>
public interface IHostSignalCollector
{
    IReadOnlyList<HostSignal> Drain();
}
