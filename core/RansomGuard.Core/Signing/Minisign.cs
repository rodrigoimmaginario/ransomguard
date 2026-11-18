using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace RansomGuard.Core.Signing;

public enum MinisignVerificationResult
{
    Valid,
    KeyIdMismatch,
    InvalidSignature,
    InvalidGlobalSignature,
}

/// <summary>
/// Verificação (e geração, para testes/tooling) de assinaturas no formato minisign sobre Ed25519.
/// Nunca lança para resultado de verificação — retorna o motivo; exceções só para formato inválido.
/// </summary>
public static class Minisign
{
    public static MinisignVerificationResult Verify(
        ReadOnlySpan<byte> content, MinisignSignature signature, MinisignPublicKey publicKey)
    {
        if (!signature.KeyId.Span.SequenceEqual(publicKey.KeyId.Span))
            return MinisignVerificationResult.KeyIdMismatch;

        var message = signature.Prehashed ? Blake2b512(content) : content.ToArray();
        if (!VerifyEd25519(message, signature.Signature.Span, publicKey.Key.Span))
            return MinisignVerificationResult.InvalidSignature;

        var globalMessage = Concat(signature.Signature.Span, Encoding.UTF8.GetBytes(signature.TrustedComment));
        if (!VerifyEd25519(globalMessage, signature.GlobalSignature.Span, publicKey.Key.Span))
            return MinisignVerificationResult.InvalidGlobalSignature;

        return MinisignVerificationResult.Valid;
    }

    /// <summary>Gera um arquivo .minisig (texto) para o conteúdo, com chave privada Ed25519 crua (seed 32 bytes).</summary>
    public static string Sign(
        ReadOnlySpan<byte> content, ReadOnlySpan<byte> privateKeySeed, ReadOnlySpan<byte> keyId,
        string trustedComment, bool prehashed = true)
    {
        if (privateKeySeed.Length != 32) throw new ArgumentException("Seed Ed25519 deve ter 32 bytes.", nameof(privateKeySeed));
        if (keyId.Length != 8) throw new ArgumentException("keyId deve ter 8 bytes.", nameof(keyId));

        var message = prehashed ? Blake2b512(content) : content.ToArray();
        var signature = SignEd25519(message, privateKeySeed);
        var globalSignature = SignEd25519(Concat(signature, Encoding.UTF8.GetBytes(trustedComment)), privateKeySeed);

        var blob = new byte[74];
        blob[0] = (byte)'E';
        blob[1] = (byte)(prehashed ? 'D' : 'd');
        keyId.CopyTo(blob.AsSpan(2, 8));
        signature.CopyTo(blob.AsSpan(10, 64));

        var sb = new StringBuilder();
        sb.Append("untrusted comment: signature from RansomGuard.Core\n");
        sb.Append(Convert.ToBase64String(blob)).Append('\n');
        sb.Append("trusted comment: ").Append(trustedComment).Append('\n');
        sb.Append(Convert.ToBase64String(globalSignature)).Append('\n');
        return sb.ToString();
    }

    /// <summary>Deriva a chave pública Ed25519 a partir do seed privado (para tooling/testes).</summary>
    public static byte[] PublicKeyFromSeed(ReadOnlySpan<byte> seed)
    {
        var priv = new Ed25519PrivateKeyParameters(seed.ToArray(), 0);
        return priv.GeneratePublicKey().GetEncoded();
    }

    private static byte[] Blake2b512(ReadOnlySpan<byte> content)
    {
        var digest = new Blake2bDigest(512);
        var input = content.ToArray();
        digest.BlockUpdate(input, 0, input.Length);
        var output = new byte[64];
        digest.DoFinal(output, 0);
        return output;
    }

    private static bool VerifyEd25519(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
    {
        var signer = new Ed25519Signer();
        signer.Init(forSigning: false, new Ed25519PublicKeyParameters(publicKey.ToArray(), 0));
        var msg = message.ToArray();
        signer.BlockUpdate(msg, 0, msg.Length);
        return signer.VerifySignature(signature.ToArray());
    }

    private static byte[] SignEd25519(ReadOnlySpan<byte> message, ReadOnlySpan<byte> seed)
    {
        var signer = new Ed25519Signer();
        signer.Init(forSigning: true, new Ed25519PrivateKeyParameters(seed.ToArray(), 0));
        var msg = message.ToArray();
        signer.BlockUpdate(msg, 0, msg.Length);
        return signer.GenerateSignature();
    }

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }
}
