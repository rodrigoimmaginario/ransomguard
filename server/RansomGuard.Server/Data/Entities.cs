using RansomGuard.Core.Detection;
using RansomGuard.Core.Score;

namespace RansomGuard.Server.Data;

/// <summary>Servidor monitorado. Uma linha por file server que já reportou ao backend.</summary>
public sealed class ServerEntity
{
    public int Id { get; set; }
    public required string Name { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }

    /// <summary>Última nota calculada (desnormalizada para a visão geral).</summary>
    public int LastScore { get; set; }
    public RiskBand LastBand { get; set; }

    public List<PostureRecord> PostureRecords { get; set; } = new();
    public List<DetectionRecord> Detections { get; set; } = new();
}

/// <summary>Registro de uma avaliação de postura + score num instante (histórico do score).</summary>
public sealed class PostureRecord
{
    public int Id { get; set; }
    public int ServerId { get; set; }
    public ServerEntity? Server { get; set; }

    public DateTime At { get; set; }
    public int Score { get; set; }
    public RiskBand Band { get; set; }

    /// <summary>Achados serializados (id da regra → título) para exibição sem recalcular.</summary>
    public string FindingsJson { get; set; } = "[]";

    /// <summary>
    /// Checagens que o agente **não conseguiu realizar** neste retrato. Coluna aditiva: bancos
    /// antigos leem `[]` e nada quebra. Precisa ser persistida, senão a honestidade existe só no
    /// cálculo e não chega à tela — e uma nota que parece completa sem ser é o problema original
    /// com outra roupa.
    /// </summary>
    public string UnknownJson { get; set; } = "[]";
}

/// <summary>Um incidente detectado (metadado da detecção correlacionada).</summary>
public sealed class DetectionRecord
{
    public int Id { get; set; }
    public int ServerId { get; set; }
    public ServerEntity? Server { get; set; }

    public DateTime At { get; set; }
    public required string User { get; set; }
    public required string SourceIp { get; set; }
    public required string Share { get; set; }
    public Confidence Confidence { get; set; }
    public int AffectedFiles { get; set; }

    /// <summary>Razões da detecção, separadas por vírgula.</summary>
    public string Reasons { get; set; } = "";

    /// <summary>Se um alerta já foi disparado para este incidente (idempotência do alerta).</summary>
    public bool Alerted { get; set; }

    // ── F32: verdade única do incidente ──────────────────────────────────────────────────────
    /// <summary>Id determinístico vindo do agente (null = incidente derivado pelo painel, agente antigo).</summary>
    public string? IncidentId { get; set; }
    /// <summary>"agent" = o agente detectou/decidiu/executou; "panel" = re-análise de eventos crus (fallback).</summary>
    public string Source { get; set; } = "panel";
    /// <summary>Modo do agente no momento (Monitor/Alert/Block).</summary>
    public string? Mode { get; set; }
    /// <summary>Explicação da escada de resposta (por que conteve ou não).</summary>
    public string? Rationale { get; set; }
    /// <summary>Se pelo menos uma ação de contenção foi executada com sucesso.</summary>
    public bool Contained { get; set; }
    /// <summary>G5: caminhos afetados (JSON array, até 500) — a lista do restore.</summary>
    public string? AffectedPathsJson { get; set; }
    public List<ResponseActionRecord> Actions { get; set; } = new();
}

/// <summary>F32 — uma ação da escada de resposta, como o agente a executou (ou falhou/pulou).</summary>
public sealed class ResponseActionRecord
{
    public int Id { get; set; }
    public int DetectionId { get; set; }
    public DetectionRecord? Detection { get; set; }
    public DateTime At { get; set; }
    public required string Actor { get; set; }
    /// <summary>execute | skip | fail | revert</summary>
    public required string Operation { get; set; }
    public required string Step { get; set; }
    public required string Target { get; set; }
    public string Justification { get; set; } = "";
    /// <summary>Operador pediu reversão pelo painel (o agente executa via política/comandos assinados — F33).</summary>
    public DateTime? RevertRequestedAt { get; set; }
    public DateTime? RevertedAt { get; set; }
    /// <summary>F33: resultado devolvido pelo agente (Executed | Failed | Skipped); null = ainda pendente.</summary>
    public string? RevertStatus { get; set; }
    public string? RevertDetail { get; set; }
    /// <summary>Conta envolvida (DenyUserOnShare) — necessária para reverter.</summary>
    public string? Account { get; set; }
}

/// <summary>Último batimento do agente por servidor — heartbeat perdido = suspeita de tamper.</summary>
public sealed class AgentHeartbeat
{
    public int Id { get; set; }
    public required string Server { get; set; }
    public DateTime LastBeat { get; set; }
    public bool TamperAlerted { get; set; }
}
