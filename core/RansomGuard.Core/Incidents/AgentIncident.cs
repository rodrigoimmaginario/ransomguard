using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using RansomGuard.Core.Audit;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;

namespace RansomGuard.Core.Incidents;

/// <summary>
/// F32 — a verdade única do incidente. O agente detecta, decide e executa; este documento leva ao
/// painel exatamente o que aconteceu (detecção + decisão + cada ação com resultado), em vez de o
/// painel re-analisar eventos crus e inventar a própria versão. O <see cref="Id"/> é determinístico
/// (servidor, usuário, origem, share, primeiro evento) para a ingestão ser idempotente.
/// </summary>
public sealed record AgentIncident(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("report")] IncidentReport Report,
    [property: JsonPropertyName("mode")] string Mode,
    [property: JsonPropertyName("rationale")] string Rationale,
    [property: JsonPropertyName("contained")] bool Contained)
{
    public static string ComputeId(string server, string user, string sourceIp, string share, DateTime firstAt)
    {
        var material = string.Join("|", server.ToUpperInvariant(), user.ToUpperInvariant(), sourceIp, share.ToUpperInvariant(),
            DateTime.SpecifyKind(firstAt, DateTimeKind.Utc).ToString("O"));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return Convert.ToHexString(hash.AsSpan(0, 12)).ToLowerInvariant();   // 24 hex = 96 bits: colisão irrelevante
    }

    /// <param name="incidentId">
    /// Identificador do episódio a que esta detecção pertence (<see cref="IncidentEpisodes"/>). Sem ele, cada detecção
    /// é um incidente próprio, identificado pelo seu início.
    /// </param>
    public static AgentIncident From(Detection.Detection d, ResponseDecision decision, IEnumerable<AuditEntry> audit, ResponseMode mode, string? incidentId = null)
    {
        var entries = audit.ToList();
        return new AgentIncident(
            incidentId ?? ComputeId(d.Server, d.User, d.SourceIp, d.Share, d.FirstAt),
            IncidentReport.From(d, entries),
            mode.ToString(),
            decision.Rationale,
            entries.Any(e => e.Operation == "execute" && e.Action.Step != ResponseStep.PreemptiveSnapshot));
    }
}
