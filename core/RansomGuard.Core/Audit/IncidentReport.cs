using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using RansomGuard.Core.Response;
using RansomGuard.Core.Signing;
using DetectionModel = RansomGuard.Core.Detection.Detection;

namespace RansomGuard.Core.Audit;

/// <summary>Uma ação registrada no relatório (subconjunto auditável de AuditEntry).</summary>
public sealed record ReportedAction(
    [property: JsonPropertyName("at")] DateTime At,
    [property: JsonPropertyName("actor")] string Actor,
    [property: JsonPropertyName("operation")] string Operation,
    [property: JsonPropertyName("step")] string Step,
    [property: JsonPropertyName("target")] string Target,
    [property: JsonPropertyName("justification")] string Justification,
    [property: JsonPropertyName("account")] string? Account = null);

/// <summary>
/// Documento canônico de um incidente + sua resposta, para assinar (minisign) e arquivar como
/// evidência à prova de adulteração. Metadado apenas.
/// A serialização é determinística (mesmos dados → mesmos bytes) para a assinatura ser estável.
/// </summary>
public sealed class IncidentReport
{
    [JsonPropertyName("server")] public required string Server { get; init; }
    [JsonPropertyName("user")] public required string User { get; init; }
    [JsonPropertyName("sourceIp")] public required string SourceIp { get; init; }
    [JsonPropertyName("share")] public required string Share { get; init; }
    [JsonPropertyName("confidence")] public required string Confidence { get; init; }
    [JsonPropertyName("reasons")] public required IReadOnlyList<string> Reasons { get; init; }
    [JsonPropertyName("affectedFiles")] public int AffectedFiles { get; init; }
    [JsonPropertyName("firstAt")] public DateTime FirstAt { get; init; }
    [JsonPropertyName("lastAt")] public DateTime LastAt { get; init; }
    [JsonPropertyName("actions")] public required IReadOnlyList<ReportedAction> Actions { get; init; }
    /// <summary>G5: caminhos tocados (metadado), para o restore. Até 500.</summary>
    [JsonPropertyName("affectedPaths")] public IReadOnlyList<string>? AffectedPaths { get; init; }

    public static IncidentReport From(DetectionModel d, IEnumerable<AuditEntry> audit) => new()
    {
        Server = d.Server, User = d.User, SourceIp = d.SourceIp, Share = d.Share,
        Confidence = d.Confidence.ToString(),
        Reasons = d.Reasons.Select(r => r.ToString()).OrderBy(x => x, StringComparer.Ordinal).ToList(),
        AffectedFiles = d.AffectedFiles, FirstAt = d.FirstAt, LastAt = d.LastAt,
        AffectedPaths = d.AffectedPaths,
        Actions = audit.Select(a => new ReportedAction(
            a.At, a.Actor, a.Operation, a.Action.Step.ToString(), a.Action.Target, a.Justification, a.Action.Account)).ToList()
    };

    /// <summary>JSON canônico (o que é assinado). Determinístico.</summary>
    public string ToCanonicalJson()
        => JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = false });

    /// <summary>Assina o relatório com a chave de auditoria (seed Ed25519). Retorna (json, minisig).</summary>
    public (string Json, string Signature) Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> keyId)
    {
        var json = ToCanonicalJson();
        var sig = Minisign.Sign(Encoding.UTF8.GetBytes(json), seed, keyId,
            $"incident {Server} {LastAt:O}");
        return (json, sig);
    }

    /// <summary>Verifica um relatório assinado contra a chave pública de auditoria.</summary>
    public static MinisignVerificationResult Verify(string json, string minisig, MinisignPublicKey key)
        => Minisign.Verify(Encoding.UTF8.GetBytes(json), MinisignSignature.Parse(minisig), key);
}
