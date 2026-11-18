namespace RansomGuard.Core.Signing;

/// <summary>
/// Chave pública no formato minisign (Ed25519): base64 de [alg "Ed" (2) | keyId (8) | chave (32)].
/// </summary>
public sealed class MinisignPublicKey
{
    private const int BlobLength = 42;

    public ReadOnlyMemory<byte> KeyId { get; }
    public ReadOnlyMemory<byte> Key { get; }

    /// <summary>Key id como o minisign exibe: hex maiúsculo dos 8 bytes em ordem invertida.</summary>
    public string KeyIdHex { get; }

    private MinisignPublicKey(byte[] keyId, byte[] key)
    {
        KeyId = keyId;
        Key = key;
        KeyIdHex = Convert.ToHexString(keyId.Reverse().ToArray());
    }

    /// <summary>Interpreta o conteúdo de um arquivo minisign.pub.</summary>
    /// <exception cref="FormatException">Arquivo fora do formato minisign.</exception>
    public static MinisignPublicKey Parse(string fileContent)
    {
        var blob = MinisignFormat.DecodeBase64Line(fileContent, lineIndex: 1);
        if (blob.Length != BlobLength)
            throw new FormatException($"Chave pública minisign deve ter {BlobLength} bytes; encontrado {blob.Length}.");
        if (blob[0] != (byte)'E' || blob[1] != (byte)'d')
            throw new FormatException("Chave pública com algoritmo não suportado (esperado Ed25519 'Ed').");

        return new MinisignPublicKey(blob[2..10], blob[10..42]);
    }

    public static MinisignPublicKey FromRaw(ReadOnlySpan<byte> keyId, ReadOnlySpan<byte> publicKey)
    {
        if (keyId.Length != 8) throw new ArgumentException("keyId deve ter 8 bytes.", nameof(keyId));
        if (publicKey.Length != 32) throw new ArgumentException("Chave Ed25519 deve ter 32 bytes.", nameof(publicKey));
        return new MinisignPublicKey(keyId.ToArray(), publicKey.ToArray());
    }

    /// <summary>Serializa no formato <c>minisign.pub</c> (para verificação com a ferramenta padrão).</summary>
    public string ToFileContent(string untrustedComment)
    {
        var blob = new byte[BlobLength];
        blob[0] = (byte)'E';
        blob[1] = (byte)'d';
        KeyId.Span.CopyTo(blob.AsSpan(2, 8));
        Key.Span.CopyTo(blob.AsSpan(10, 32));
        return $"untrusted comment: {untrustedComment}\n{Convert.ToBase64String(blob)}\n";
    }
}
