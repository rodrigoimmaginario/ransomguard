using DetectionModel = RansomGuard.Core.Detection.Detection;

namespace RansomGuard.Core.Incidents;

/// <summary>
/// L3 (laboratório, sessão 1) — um ataque, um incidente. O agente analisa em ciclos de poucos segundos; um ataque de
/// oito segundos produzia uma detecção por ciclo, e cada uma virava um incidente novo no painel (e um alerta).
///
/// Detecções do mesmo ator (servidor, usuário, origem, share) separadas por menos que <see cref="Gap"/> pertencem ao
/// mesmo episódio e recebem o mesmo identificador; o painel atualiza o incidente em vez de criar outro. A memória é
/// do processo: reiniciar o agente começa episódios novos.
/// </summary>
public sealed class IncidentEpisodes
{
    /// <summary>Silêncio do ator depois do qual a próxima detecção já é outro incidente.</summary>
    public static readonly TimeSpan Gap = TimeSpan.FromMinutes(10);

    private readonly Dictionary<string, (string Id, DateTime LastAt)> _open = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public string IdFor(DetectionModel d)
    {
        var key = string.Join("|", d.Server, d.User, d.SourceIp, d.Share);
        lock (_gate)
        {
            // Limpeza barata: o que já passou do intervalo sai da memória.
            if (_open.Count > 2_000)
                foreach (var stale in _open.Where(kv => d.LastAt - kv.Value.LastAt > Gap).Select(kv => kv.Key).ToList())
                    _open.Remove(stale);

            if (_open.TryGetValue(key, out var open) && d.FirstAt - open.LastAt <= Gap)
            {
                _open[key] = (open.Id, d.LastAt > open.LastAt ? d.LastAt : open.LastAt);
                return open.Id;
            }
            var id = AgentIncident.ComputeId(d.Server, d.User, d.SourceIp, d.Share, d.FirstAt);
            _open[key] = (id, d.LastAt);
            return id;
        }
    }
}
