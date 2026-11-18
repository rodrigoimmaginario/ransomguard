namespace RansomGuard.Core.Signing;

/// <summary>
/// Assinatura no formato minisign (.minisig): 4 linhas — comentário não confiável, base64 de
/// [alg (2) | keyId (8) | assinatura (64)], "trusted comment: ...", base64 da assinatura global (64)
/// sobre [assinatura | trusted comment]. "ED" = prehashed (Blake2b-512); "Ed" = legado (bruto).
/// </summary>
public sealed class MinisignSignature
{
    private const int SigBlobLength = 74;
    private const string TrustedCommentPrefix = "trusted comment:";

    public bool Prehashed { get; }
    public ReadOnlyMemory<byte> KeyId { get; }
    public ReadOnlyMemory<byte> Signature { get; }
    public string TrustedComment { get; }
    public ReadOnlyMemory<byte> GlobalSignature { get; }

    private MinisignSignature(bool prehashed, byte[] keyId, byte[] signature, string trustedComment, byte[] globalSignature)
    {
        Prehashed = prehashed;
        KeyId = keyId;
        Signature = signature;
        TrustedComment = trustedComment;
        GlobalSignature = globalSignature;
    }

    /// <summary>Interpreta o conteúdo de um arquivo .minisig.</summary>
    /// <exception cref="FormatException">Arquivo fora do formato minisign.</exception>
    public static MinisignSignature Parse(string fileContent)
    {
        var lines = MinisignFormat.Lines(fileContent);
        if (lines.Length < 4)
            throw new FormatException("Arquivo .minisig deve ter 4 linhas.");

        var blob = MinisignFormat.DecodeBase64(lines[1], "linha da assinatura");
        if (blob.Length != SigBlobLength)
            throw new FormatException($"Bloco de assinatura deve ter {SigBlobLength} bytes; encontrado {blob.Length}.");

        bool prehashed = blob[0] == (byte)'E' && blob[1] == (byte)'D';
        bool legacy = blob[0] == (byte)'E' && blob[1] == (byte)'d';
        if (!prehashed && !legacy)
            throw new FormatException("Assinatura com algoritmo não suportado (esperado Ed25519 'Ed'/'ED').");

        if (!lines[2].StartsWith(TrustedCommentPrefix, StringComparison.Ordinal))
            throw new FormatException("Terceira linha deve iniciar com 'trusted comment:'.");
        var trustedComment = lines[2][TrustedCommentPrefix.Length..].TrimStart(' ');

        var globalSig = MinisignFormat.DecodeBase64(lines[3], "assinatura global");
        if (globalSig.Length != 64)
            throw new FormatException($"Assinatura global deve ter 64 bytes; encontrado {globalSig.Length}.");

        return new MinisignSignature(prehashed, blob[2..10], blob[10..74], trustedComment, globalSig);
    }
}
