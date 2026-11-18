using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using RansomGuard.Core.Auth;
using RansomGuard.Core.Response;
using RansomGuard.Core.Signing;

namespace RansomGuard.Core.Policy;

/// <summary>
/// F33 — política de resposta publicada pelo painel e assinada pela chave da instalação. Substitui a
/// configuração por registro (RDP + regedit em cada servidor) por um documento versionado que o agente
/// puxa e verifica como faz com o catálogo: assinatura inválida, servidor errado ou versão menor que a
/// última aceita → ignora e mantém a política vigente (fail-safe). Escopo <c>"*"</c> = todos os servidores.
/// </summary>
public sealed record AgentPolicyDocument(
    [property: JsonPropertyName("server")] string Server,
    [property: JsonPropertyName("version")] long Version,
    [property: JsonPropertyName("mode")] string Mode,
    [property: JsonPropertyName("maxStep")] string MaxStep,
    [property: JsonPropertyName("allowlistedUsers")] IReadOnlyList<string> AllowlistedUsers,
    [property: JsonPropertyName("allowlistedIps")] IReadOnlyList<string> AllowlistedIps,
    [property: JsonPropertyName("learningMode")] bool LearningMode,
    [property: JsonPropertyName("issuedAt")] DateTime IssuedAt,
    [property: JsonPropertyName("blockedIps")] IReadOnlyList<string>? BlockedIps = null)
{
    public const string AllServers = "*";
    /// <summary>G4b: IPs que TODOS os agentes bloqueiam no firewall (o que FS01 viu protege FS02). Vazio = nenhum.</summary>
    public IReadOnlyList<string> NetworkBlocklist => BlockedIps ?? Array.Empty<string>();
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    public bool AppliesTo(string server) =>
        Server == AllServers || string.Equals(Server, server, StringComparison.OrdinalIgnoreCase);

    public string ToCanonicalJson() => JsonSerializer.Serialize(this, Json);

    /// <summary>Converte para a política que a escada consome. Valores desconhecidos caem no padrão seguro.</summary>
    public ResponsePolicy ToResponsePolicy() => new()
    {
        Mode = Enum.TryParse<ResponseMode>(Mode, true, out var m) ? m : ResponseMode.Monitor,
        MaxStep = Enum.TryParse<ResponseStep>(MaxStep, true, out var s) ? s : ResponseStep.DenyUserOnShare,
        AllowlistedUsers = AllowlistedUsers.ToHashSet(StringComparer.OrdinalIgnoreCase),
        AllowlistedIps = AllowlistedIps.ToHashSet(StringComparer.OrdinalIgnoreCase),
        LearningMode = LearningMode
    };

    public static SignedAssertion Sign(AgentPolicyDocument doc, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> keyId)
    {
        var payload = doc.ToCanonicalJson();
        return new SignedAssertion(payload, Minisign.Sign(Encoding.UTF8.GetBytes(payload), seed, keyId, $"agent-policy v{doc.Version}"));
    }

    /// <summary>Nunca lança. <paramref name="lastVersion"/>: maior versão já aceita (anti-rollback).</summary>
    public static PolicyResult Verify(SignedAssertion? signed, MinisignPublicKey key, string server, DateTime now, long? lastVersion)
    {
        if (signed is null || string.IsNullOrWhiteSpace(signed.Payload) || string.IsNullOrWhiteSpace(signed.Signature))
            return PolicyResult.Fail(PolicyOutcome.Malformed);
        MinisignSignature sig;
        try { sig = MinisignSignature.Parse(signed.Signature); } catch (Exception) { return PolicyResult.Fail(PolicyOutcome.Malformed); }
        if (Minisign.Verify(Encoding.UTF8.GetBytes(signed.Payload), sig, key) != MinisignVerificationResult.Valid)
            return PolicyResult.Fail(PolicyOutcome.InvalidSignature);

        AgentPolicyDocument? doc;
        try { doc = JsonSerializer.Deserialize<AgentPolicyDocument>(signed.Payload, Json); } catch (Exception) { doc = null; }
        if (doc is null || string.IsNullOrWhiteSpace(doc.Server) || doc.Version <= 0)
            return PolicyResult.Fail(PolicyOutcome.Malformed);
        if (!doc.AppliesTo(server)) return PolicyResult.Fail(PolicyOutcome.WrongServer);
        if (doc.IssuedAt > now + SignedDocuments.ClockSkew) return PolicyResult.Fail(PolicyOutcome.NotYetValid);
        if (lastVersion is { } last && doc.Version < last) return PolicyResult.Fail(PolicyOutcome.Rollback);
        return new PolicyResult(PolicyOutcome.Valid, doc);
    }
}

public enum PolicyOutcome { Valid, Malformed, InvalidSignature, WrongServer, NotYetValid, Rollback }

public sealed record PolicyResult(PolicyOutcome Outcome, AgentPolicyDocument? Policy)
{
    public static PolicyResult Fail(PolicyOutcome o) => new(o, null);
}

/// <summary>Um comando do painel para o agente (hoje: reverter uma ação de contenção).</summary>
public sealed record AgentCommand(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("step")] string Step,
    [property: JsonPropertyName("target")] string Target,
    [property: JsonPropertyName("account")] string? Account,
    [property: JsonPropertyName("reason")] string Reason)
{
    public const string Revert = "revert";

    public ResponseAction? ToAction(string server) =>
        Enum.TryParse<ResponseStep>(Step, true, out var s) ? new ResponseAction(s, server, Target, Reason, Account) : null;
}

/// <summary>Lote de comandos assinado, amarrado ao servidor e com validade curta.</summary>
public sealed record CommandEnvelope(
    [property: JsonPropertyName("server")] string Server,
    [property: JsonPropertyName("issuedAt")] DateTime IssuedAt,
    [property: JsonPropertyName("expiresAt")] DateTime ExpiresAt,
    [property: JsonPropertyName("commands")] IReadOnlyList<AgentCommand> Commands)
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };
    public static readonly TimeSpan Validity = TimeSpan.FromMinutes(15);

    public static SignedAssertion Sign(CommandEnvelope env, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> keyId)
    {
        var payload = JsonSerializer.Serialize(env, Json);
        return new SignedAssertion(payload, Minisign.Sign(Encoding.UTF8.GetBytes(payload), seed, keyId, $"agent-commands {env.Server}"));
    }

    public static CommandResult Verify(SignedAssertion? signed, MinisignPublicKey key, string server, DateTime now)
    {
        if (signed is null || string.IsNullOrWhiteSpace(signed.Payload) || string.IsNullOrWhiteSpace(signed.Signature))
            return CommandResult.Fail(PolicyOutcome.Malformed);
        MinisignSignature sig;
        try { sig = MinisignSignature.Parse(signed.Signature); } catch (Exception) { return CommandResult.Fail(PolicyOutcome.Malformed); }
        if (Minisign.Verify(Encoding.UTF8.GetBytes(signed.Payload), sig, key) != MinisignVerificationResult.Valid)
            return CommandResult.Fail(PolicyOutcome.InvalidSignature);
        CommandEnvelope? env;
        try { env = JsonSerializer.Deserialize<CommandEnvelope>(signed.Payload, Json); } catch (Exception) { env = null; }
        if (env is null || string.IsNullOrWhiteSpace(env.Server)) return CommandResult.Fail(PolicyOutcome.Malformed);
        if (!string.Equals(env.Server, server, StringComparison.OrdinalIgnoreCase)) return CommandResult.Fail(PolicyOutcome.WrongServer);
        if (env.IssuedAt > now + SignedDocuments.ClockSkew) return CommandResult.Fail(PolicyOutcome.NotYetValid);
        if (env.ExpiresAt < now) return CommandResult.Fail(PolicyOutcome.Rollback);   // vencido = tratado como antigo
        return new CommandResult(PolicyOutcome.Valid, env);
    }
}

public sealed record CommandResult(PolicyOutcome Outcome, CommandEnvelope? Envelope)
{
    public static CommandResult Fail(PolicyOutcome o) => new(o, null);
}

/// <summary>O que o agente devolve ao painel sobre um comando executado.</summary>
public sealed record CommandOutcome(
    [property: JsonPropertyName("commandId")] string CommandId,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("detail")] string Detail,
    [property: JsonPropertyName("at")] DateTime At);
