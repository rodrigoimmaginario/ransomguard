using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace RansomGuard.Core.Auth;

/// <summary>
/// B1 — chave Ed25519 de UM agente. Gerada no próprio servidor monitorado, nunca sai dele; o painel só conhece a
/// metade pública, vinculada ao nome do servidor no enrolamento.
/// </summary>
public sealed class AgentKey
{
    private static readonly Regex ServerNamePattern = new(@"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}\z", RegexOptions.Compiled);

    private AgentKey(byte[] seed)
    {
        Seed = seed;
        PublicKey = new Ed25519PrivateKeyParameters(seed, 0).GeneratePublicKey().GetEncoded();
    }

    public byte[] Seed { get; }
    public byte[] PublicKey { get; }
    public string PublicKeyBase64 => Convert.ToBase64String(PublicKey);

    /// <summary>Impressão digital curta da chave pública (16 hexa) — o que o administrador confere no painel.</summary>
    public string Fingerprint => FingerprintOf(PublicKey);

    public static AgentKey Generate() => new(RandomNumberGenerator.GetBytes(32));

    public static AgentKey FromSeed(byte[] seed) =>
        seed.Length == 32 ? new AgentKey(seed.ToArray()) : throw new ArgumentException("Seed Ed25519 deve ter 32 bytes.", nameof(seed));

    public static string FingerprintOf(byte[] publicKey) => Convert.ToHexString(SHA256.HashData(publicKey))[..16];

    public static bool IsValidPublicKey(string? base64)
    {
        if (string.IsNullOrWhiteSpace(base64)) return false;
        try { return Convert.FromBase64String(base64).Length == 32; }
        catch (FormatException) { return false; }
    }

    /// <summary>Nome de servidor aceito no enrolamento: nome de máquina ou FQDN, sem nada que sirva a injeção.</summary>
    public static bool IsValidServerName(string? name) => name is not null && ServerNamePattern.IsMatch(name);
}

public enum BatchSignatureResult { Valid, Malformed, Expired, BadSignature }

/// <summary>
/// Assinatura do lote que o agente envia ao painel. Cobre o nome do agente, o instante e o corpo exato — um lote
/// capturado não serve para outro servidor, nem depois da janela, nem com o conteúdo trocado.
/// </summary>
public static class BatchSignature
{
    public const string AgentHeader = "X-RansomGuard-Agent";
    public const string TimestampHeader = "X-RansomGuard-Timestamp";
    public const string SignatureHeader = "X-RansomGuard-Signature";

    /// <summary>Diferença máxima entre o relógio do agente e o do painel. Fora disso o lote é recusado (e o agente avisa).</summary>
    public static readonly TimeSpan MaxSkew = TimeSpan.FromMinutes(5);

    private const string TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";

    public static string Timestamp(DateTime utc) => utc.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture);

    public static string Sign(AgentKey key, string agent, string timestamp, ReadOnlySpan<byte> body)
    {
        var message = Message(agent, timestamp, body);
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(key.Seed, 0));
        signer.BlockUpdate(message, 0, message.Length);
        return Convert.ToBase64String(signer.GenerateSignature());
    }

    public static BatchSignatureResult Verify(byte[] publicKey, string agent, string? timestamp, string? signature, ReadOnlySpan<byte> body, DateTime now)
    {
        if (publicKey.Length != 32 || string.IsNullOrWhiteSpace(timestamp) || string.IsNullOrWhiteSpace(signature))
            return BatchSignatureResult.Malformed;
        if (!DateTime.TryParseExact(timestamp, TimestampFormat, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var at))
            return BatchSignatureResult.Malformed;

        byte[] sig;
        try { sig = Convert.FromBase64String(signature); }
        catch (FormatException) { return BatchSignatureResult.Malformed; }
        if (sig.Length != 64) return BatchSignatureResult.Malformed;

        // A assinatura é conferida ANTES da janela: "expirado" só é dito a quem provou ter a chave.
        var message = Message(agent, timestamp, body);
        var verifier = new Ed25519Signer();
        verifier.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
        verifier.BlockUpdate(message, 0, message.Length);
        if (!verifier.VerifySignature(sig)) return BatchSignatureResult.BadSignature;

        return (now.ToUniversalTime() - at).Duration() <= MaxSkew ? BatchSignatureResult.Valid : BatchSignatureResult.Expired;
    }

    private static byte[] Message(string agent, string timestamp, ReadOnlySpan<byte> body)
    {
        var head = Encoding.UTF8.GetBytes($"RG-BATCH-v1\n{agent.Trim().ToUpperInvariant()}\n{timestamp}\n");
        var message = new byte[head.Length + 32];
        head.CopyTo(message, 0);
        SHA256.HashData(body, message.AsSpan(head.Length));
        return message;
    }
}
