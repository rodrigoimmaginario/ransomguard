using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Score;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Data;

namespace RansomGuard.Server.Ingestion;

/// <summary>
/// Processa um <see cref="AgentBatch"/>: atualiza o servidor, recalcula o Score sobre a postura,
/// roda o motor de detecção sobre os eventos, persiste incidentes e dispara alertas. Toda a lógica
/// vive aqui (não no controller/endpoint), para ser testável sem HTTP.
/// </summary>
public sealed class IngestionService
{
    private readonly RansomGuardDb _db;
    private readonly RiskScoreEngine _score;
    private readonly DetectionEngine _detect;
    private readonly AlertEngine _alerts;
    private readonly Policy.AgentPolicyService? _policies;
    private readonly Func<DateTime> _clock;

    public IngestionService(RansomGuardDb db, AlertEngine alerts,
        RiskScoreEngine? score = null, DetectionEngine? detect = null,
        Policy.AgentPolicyService? policies = null, Func<DateTime>? clock = null)
    {
        _policies = policies;
        _clock = clock ?? (() => DateTime.UtcNow);
        _db = db;
        _alerts = alerts;
        _score = score ?? new RiskScoreEngine();
        _detect = detect ?? new DetectionEngine();
    }

    /// <summary>
    /// Resultado do processamento de um lote (para o simulador e o endpoint). O produto é gratuito: não há
    /// licença na resposta. O que o painel manda ao agente vai assinado pela chave da instalação.
    /// </summary>
    /// <param name="Policy">F33: política de resposta efetiva para o servidor, assinada (null = nada configurado).</param>
    /// <param name="Commands">F33: reversões pendentes para o servidor, assinadas (null = nada pendente).</param>
    public sealed record IngestResult(int? Score, int NewDetections, int AlertsRaised,
        RansomGuard.Core.Auth.SignedAssertion? Policy = null,
        RansomGuard.Core.Auth.SignedAssertion? Commands = null);

    public async Task<IngestResult> IngestAsync(AgentBatch batch, CancellationToken ct = default)
    {
        // B3: "visto por último" e batimento são a hora em que o PAINEL recebeu o lote. A hora declarada pelo agente
        // (batch.At) continua valendo como dado — postura, emissão da política — mas não decide se ele está vivo:
        // um relógio adiantado, ou um lote forjado com data futura, calaria o alerta de agente silencioso.
        var receivedAt = _clock();
        var server = await _db.Servers.FirstOrDefaultAsync(s => s.Name == batch.Server, ct);
        if (server is null)
        {
            server = new ServerEntity { Name = batch.Server, FirstSeen = receivedAt, LastSeen = receivedAt };
            _db.Servers.Add(server);
        }
        server.LastSeen = receivedAt;

        // Heartbeat sempre atualiza (agente vivo).
        await TouchHeartbeatAsync(batch.Server, receivedAt, ct);

        int? score = null;
        if (batch.Posture is not null)
        {
            var scored = _score.ScoreServer(batch.Posture);
            score = scored.Score;
            server.LastScore = scored.Score;
            server.LastBand = scored.Band;
            _db.PostureRecords.Add(new PostureRecord
            {
                Server = server,
                At = batch.At,
                Score = scored.Score,
                Band = scored.Band,
                FindingsJson = JsonSerializer.Serialize(
                    scored.Findings.Select(f => new { f.Rule.Id, f.Rule.Title, f.Rule.Fix })),
                UnknownJson = JsonSerializer.Serialize(
                    scored.Unknown.Select(r => new { r.Id, r.Title, r.AttackPremise }))
            });
        }

        var alertsRaised = 0;
        var newDetections = 0;

        // F32: quando o agente manda a verdade (detecção + decisão + trilha), o painel NÃO re-analisa os
        // eventos — persiste o que aconteceu, idempotente por IncidentId. Agente antigo (Incidents null)
        // cai no fallback abaixo, marcado como "panel".
        if (batch.Incidents is not null)
        {
            foreach (var inc in batch.Incidents)
            {
                if (string.IsNullOrWhiteSpace(inc.Id)) continue;
                var r = inc.Report;
                var reasons = (r.Reasons ?? Array.Empty<string>())
                    .Select(x => Enum.TryParse<DetectionReason>(x, out var dr) ? dr : (DetectionReason?)null)
                    .Where(x => x is not null).Select(x => x!.Value).ToHashSet();
                var confidence = Enum.TryParse<Confidence>(r.Confidence, out var c) ? c : Confidence.Medium;

                // L3 (laboratório, sessão 1): o agente manda o mesmo identificador para os ciclos de um mesmo ataque. O que
                // chega depois ATUALIZA o incidente; um lote reentregue (mesmo instante ou anterior) não muda nada.
                var existing = await _db.Detections.Include(x => x.Actions).FirstOrDefaultAsync(x => x.IncidentId == inc.Id, ct);
                if (existing is not null)
                {
                    if (r.LastAt <= existing.At) continue;
                    var escalated = confidence > existing.Confidence;
                    existing.At = r.LastAt;
                    if (escalated) existing.Confidence = confidence;
                    // L12 (laboratório, sessão 2): o mesmo arquivo aparece em ciclos seguidos (gravado num, renomeado no outro);
                    // somar contava 650 arquivos num ataque a 300. Com a lista completa, conta-se a união; acima do teto da
                    // lista, a soma é o que resta (limite superior).
                    var knownPaths = existing.AffectedPathsJson is null ? new List<string>() : JsonSerializer.Deserialize<List<string>>(existing.AffectedPathsJson) ?? new List<string>();
                    var union = knownPaths.Concat(r.AffectedPaths ?? Array.Empty<string>()).Distinct(StringComparer.OrdinalIgnoreCase).Count();
                    var complete = r.AffectedPaths is { Count: > 0 } && r.AffectedPaths.Count >= r.AffectedFiles
                                   && knownPaths.Count >= existing.AffectedFiles && union < Detection.MaxAffectedPaths;
                    existing.AffectedFiles = complete ? union : existing.AffectedFiles + r.AffectedFiles;
                    existing.Reasons = string.Join(",", existing.Reasons.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Concat(reasons.Select(x => x.ToString())).Distinct(StringComparer.Ordinal));
                    if (inc.Contained || !existing.Contained) { existing.Mode = inc.Mode; existing.Rationale = inc.Rationale; }
                    existing.Contained |= inc.Contained;
                    if (r.AffectedPaths is { Count: > 0 })
                    {
                        var known = existing.AffectedPathsJson is null ? new List<string>() : JsonSerializer.Deserialize<List<string>>(existing.AffectedPathsJson) ?? new List<string>();
                        existing.AffectedPathsJson = JsonSerializer.Serialize(known.Concat(r.AffectedPaths).Distinct(StringComparer.OrdinalIgnoreCase).Take(Detection.MaxAffectedPaths).ToList());
                    }
                    foreach (var act in r.Actions)
                        if (!existing.Actions.Any(a => a.At == act.At && a.Operation == act.Operation && a.Step == act.Step && a.Target == act.Target))
                            existing.Actions.Add(new ResponseActionRecord
                            {
                                At = act.At, Actor = act.Actor, Operation = act.Operation, Step = act.Step, Target = act.Target,
                                Justification = act.Justification, Account = act.Account
                            });
                    if (_policies is not null && inc.Contained && existing.Confidence == Confidence.High
                        && !string.Equals(r.SourceIp, Detection.LocalOrigin, StringComparison.OrdinalIgnoreCase))
                        await _policies.AddToNetworkBlocklistAsync(r.SourceIp, batch.At, ct);
                    // Alerta de novo só quando o incidente SOBE de nível — não a cada ciclo do mesmo ataque.
                    if (escalated)
                    {
                        var merged = existing.Reasons.Split(',').Select(x => Enum.TryParse<DetectionReason>(x, out var dr) ? dr : (DetectionReason?)null)
                            .Where(x => x is not null).Select(x => x!.Value).ToHashSet();
                        await _alerts.RaiseDetectionAsync(new Detection(r.Server, r.User, r.SourceIp, r.Share, existing.Confidence, merged, existing.AffectedFiles, r.FirstAt, r.LastAt), ct);
                        existing.Alerted = true;
                        alertsRaised++;
                    }
                    continue;
                }

                var rec = new DetectionRecord
                {
                    Server = server, At = r.LastAt, User = r.User, SourceIp = r.SourceIp, Share = r.Share,
                    Confidence = confidence, AffectedFiles = r.AffectedFiles, Reasons = string.Join(",", reasons),
                    IncidentId = inc.Id, Source = "agent", Mode = inc.Mode, Rationale = inc.Rationale, Contained = inc.Contained,
                    AffectedPathsJson = r.AffectedPaths is { Count: > 0 } ? JsonSerializer.Serialize(r.AffectedPaths) : null
                };
                foreach (var act in r.Actions)
                    rec.Actions.Add(new ResponseActionRecord
                    {
                        At = act.At, Actor = act.Actor, Operation = act.Operation, Step = act.Step, Target = act.Target,
                        Justification = act.Justification, Account = act.Account
                    });
                _db.Detections.Add(rec);
                newDetections++;

                // G4b: o que FS01 conteve protege FS02 — IP de origem remoto de incidente Alta contido entra na blocklist.
                if (_policies is not null && inc.Contained && confidence == Confidence.High
                    && !string.Equals(r.SourceIp, Detection.LocalOrigin, StringComparison.OrdinalIgnoreCase))
                    await _policies.AddToNetworkBlocklistAsync(r.SourceIp, batch.At, ct);

                var model = new Detection(r.Server, r.User, r.SourceIp, r.Share, confidence, reasons, r.AffectedFiles, r.FirstAt, r.LastAt);
                await _alerts.RaiseDetectionAsync(model, ct);
                rec.Alerted = true;
                alertsRaised++;
            }
        }
        else if (batch.Events.Count > 0)
        {
            foreach (var d in _detect.Analyze(batch.Events, batch.HostSignals))
            {
                var rec = new DetectionRecord
                {
                    Server = server,
                    At = d.LastAt,
                    User = d.User,
                    SourceIp = d.SourceIp,
                    Share = d.Share,
                    Confidence = d.Confidence,
                    AffectedFiles = d.AffectedFiles,
                    Reasons = string.Join(",", d.Reasons)
                };
                _db.Detections.Add(rec);
                newDetections++;

                if (_alerts.ShouldAlert(d))
                {
                    await _alerts.RaiseDetectionAsync(d, ct);
                    rec.Alerted = true;
                    alertsRaised++;
                }
            }
        }

        await _db.SaveChangesAsync(ct);

        // F33: resultados de comandos (reversões) fecham as ações; a resposta leva política e comandos assinados.
        if (_policies is not null && batch.CommandResults is { Count: > 0 })
            await _policies.ApplyResultsAsync(batch.CommandResults, ct);
        var policy = _policies is null ? null : await _policies.IssuePolicyAsync(batch.Server, batch.At, ct);
        var commands = _policies is null ? null : await _policies.IssueCommandsAsync(batch.Server, batch.At, ct);
        return new IngestResult(score, newDetections, alertsRaised, policy, commands);
    }

    private async Task TouchHeartbeatAsync(string server, DateTime at, CancellationToken ct)
    {
        var hb = await _db.Heartbeats.FirstOrDefaultAsync(h => h.Server == server, ct);
        if (hb is null)
            _db.Heartbeats.Add(new AgentHeartbeat { Server = server, LastBeat = at });
        else
        {
            hb.LastBeat = at;
            hb.TamperAlerted = false; // voltou a bater → limpa o estado de tamper
        }
    }

    /// <summary>
    /// Varre os heartbeats e, para agentes silenciosos além do limite, dispara alerta de tamper
    /// (agente morto = possível EDR killer). Idempotente: só alerta uma vez por silêncio.
    /// Chamado por um timer no servidor (fatia 2) — aqui é testável isoladamente.
    /// </summary>
    public async Task<int> CheckHeartbeatsAsync(DateTime now, TimeSpan maxSilence, CancellationToken ct = default)
    {
        var stale = await _db.Heartbeats
            .Where(h => !h.TamperAlerted)
            .ToListAsync(ct);

        var raised = 0;
        foreach (var hb in stale.Where(h => now - h.LastBeat > maxSilence))
        {
            await _alerts.RaiseTamperAsync(hb.Server, hb.LastBeat, ct);
            hb.TamperAlerted = true;
            raised++;
        }
        await _db.SaveChangesAsync(ct);
        return raised;
    }
}
