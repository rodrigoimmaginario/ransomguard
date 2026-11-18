using RansomGuard.Core.Auth;
using RansomGuard.Core.Policy;
using RansomGuard.Core.Signing;

namespace RansomGuard.Agent.Auth;

/// <summary>Onde o agente guarda a chave pública fixada do painel (ProgramData no serviço; memória nos testes).</summary>
public interface IPanelKeyStore
{
    string? Load();
    void Save(string publicKeyFileContent);
}

public sealed class InMemoryPanelKeyStore : IPanelKeyStore
{
    private string? _content;
    public string? Load() => _content;
    public void Save(string publicKeyFileContent) => _content = publicKeyFileContent;
}

/// <summary>
/// F38 — confiança do agente no painel. Guarda a chave pública fixada (explícita por configuração ou
/// fixada no primeiro contato — TOFU) e verifica cada política e cada lote de comandos. Uma chave já fixada
/// <b>nunca</b> é substituída automaticamente: painel "novo" com chave diferente é tratado como
/// suspeita, não como atualização.
/// </summary>
public sealed class PanelTrust
{
    private readonly IPanelKeyStore _store;
    private MinisignPublicKey? _key;
    private long? _lastPolicyVersion;

    public PanelTrust(IPanelKeyStore store, string? configuredPublicKey = null)
    {
        _store = store;
        var content = string.IsNullOrWhiteSpace(configuredPublicKey) ? store.Load() : configuredPublicKey;
        if (!string.IsNullOrWhiteSpace(content))
        {
            try { _key = MinisignPublicKey.Parse(content); } catch (Exception) { _key = null; }
        }
        Pinned = !string.IsNullOrWhiteSpace(configuredPublicKey) && _key is not null;
    }

    /// <summary>Chave veio de configuração explícita (não pode ser trocada nem por TOFU).</summary>
    public bool Pinned { get; }
    public bool HasKey => _key is not null;
    public string? KeyIdHex => _key?.KeyIdHex;
    public long? LastPolicyVersion => _lastPolicyVersion;

    /// <summary>
    /// Fixa a chave no primeiro contato (TOFU). Retorna false — sem alterar nada — se já há chave e a
    /// apresentada é diferente.
    /// </summary>
    public bool TryPin(string publicKeyFileContent)
    {
        MinisignPublicKey parsed;
        try { parsed = MinisignPublicKey.Parse(publicKeyFileContent); } catch (Exception) { return false; }
        if (_key is not null)
            return _key.Key.Span.SequenceEqual(parsed.Key.Span) && _key.KeyId.Span.SequenceEqual(parsed.KeyId.Span);
        _key = parsed;
        _store.Save(publicKeyFileContent);
        return true;
    }

    /// <summary>F33: política assinada. Só <c>Valid</c> avança a versão aceita (anti-rollback).</summary>
    public PolicyResult EvaluatePolicy(SignedAssertion? policy, string server, DateTime now)
    {
        if (_key is null) return PolicyResult.Fail(PolicyOutcome.Malformed);
        var r = AgentPolicyDocument.Verify(policy, _key, server, now, _lastPolicyVersion);
        if (r.Outcome == PolicyOutcome.Valid) _lastPolicyVersion = r.Policy!.Version;
        return r;
    }

    /// <summary>F33: lote de comandos assinado (reversões pedidas no painel).</summary>
    public CommandResult EvaluateCommands(SignedAssertion? commands, string server, DateTime now)
        => _key is null ? CommandResult.Fail(PolicyOutcome.Malformed) : CommandEnvelope.Verify(commands, _key, server, now);
}
