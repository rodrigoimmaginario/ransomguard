using RansomGuard.Core.Detection;
using RansomGuard.Core.Score;

namespace RansomGuard.Server.Ingestion;

/// <summary>
/// Lote enviado por um agente ao backend: o retrato de postura do servidor, os eventos de arquivo
/// e sinais de host observados desde o último envio, e o batimento (heartbeat). Metadado apenas.
/// É o contrato entre o agente Windows (fatia 2+, no lab) e o servidor; aqui a ingestão o consome
/// no formato do modelo, sem depender de como o agente coletou.
/// </summary>
public sealed record AgentBatch(
    string Server,
    DateTime At,
    PostureSnapshot? Posture,
    IReadOnlyList<FileEvent> Events,
    IReadOnlyList<HostSignal> HostSignals,
    IReadOnlyList<RansomGuard.Core.Incidents.AgentIncident>? Incidents = null,
    IReadOnlyList<RansomGuard.Core.Policy.CommandOutcome>? CommandResults = null)
{
    public static AgentBatch Heartbeat(string server, DateTime at)
        => new(server, at, null, Array.Empty<FileEvent>(), Array.Empty<HostSignal>());
}
