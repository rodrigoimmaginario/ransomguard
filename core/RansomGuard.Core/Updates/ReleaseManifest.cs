using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using RansomGuard.Core.Signing;

namespace RansomGuard.Core.Updates;

/// <summary>Um arquivo de release com seu hash esperado (SHA-256 hex).</summary>
public sealed record ReleaseFile(
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("sha256")] string Sha256);

/// <summary>
/// Manifesto de auto-update: versão + arquivos com SHA-256. Distribuído assinado (minisign) ao lado
/// de um .minisig. O agente só aplica um update cuja versão avança (anti-downgrade) e cujos arquivos
/// batem o hash.
/// </summary>
public sealed class ReleaseManifest
{
    [JsonPropertyName("version")]
    public int Version { get; init; }

    [JsonPropertyName("files")]
    public IReadOnlyList<ReleaseFile> Files { get; init; } = new List<ReleaseFile>();

    public static ReleaseManifest FromJson(string json)
        => JsonSerializer.Deserialize<ReleaseManifest>(json)
           ?? throw new FormatException("Manifesto inválido.");

    public string ToJson()
        => JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });

    public static string Sha256Hex(ReadOnlySpan<byte> content)
        => Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
}

public enum UpdateStatus
{
    Accepted,
    BadSignature,
    Downgrade,
    HashMismatch,
    InvalidFormat
}

public sealed record UpdateResult(UpdateStatus Status, int Version, string Detail)
{
    public bool Accepted => Status == UpdateStatus.Accepted;
}

/// <summary>
/// Verifica um manifesto de update: assinatura minisign, anti-downgrade e o SHA-256 de cada arquivo
/// entregue. Lógica pura; a busca dos bytes de cada arquivo é injetada (para testar sem disco).
/// </summary>
public sealed class ReleaseManifestVerifier
{
    private readonly MinisignPublicKey _trustedKey;
    public int CurrentVersion { get; private set; }

    public ReleaseManifestVerifier(MinisignPublicKey trustedKey, int currentVersion = 0)
    {
        _trustedKey = trustedKey;
        CurrentVersion = currentVersion;
    }

    /// <param name="manifestJson">Conteúdo exato do manifesto (o que foi assinado).</param>
    /// <param name="minisig">Arquivo .minisig ao lado.</param>
    /// <param name="fileBytes">Resolve os bytes de cada `path` do manifesto (o pacote baixado).</param>
    public UpdateResult TryApply(string manifestJson, string minisig, Func<string, byte[]?> fileBytes)
    {
        ReleaseManifest manifest;
        MinisignSignature signature;
        try
        {
            manifest = ReleaseManifest.FromJson(manifestJson);
            signature = MinisignSignature.Parse(minisig);
        }
        catch (FormatException ex)
        {
            return new UpdateResult(UpdateStatus.InvalidFormat, 0, ex.Message);
        }

        var verdict = Minisign.Verify(
            System.Text.Encoding.UTF8.GetBytes(manifestJson), signature, _trustedKey);
        if (verdict != MinisignVerificationResult.Valid)
            return new UpdateResult(UpdateStatus.BadSignature, manifest.Version, $"Assinatura inválida: {verdict}");

        if (manifest.Version <= CurrentVersion)
            return new UpdateResult(UpdateStatus.Downgrade, manifest.Version,
                $"Anti-downgrade: versão {manifest.Version} ≤ atual {CurrentVersion}.");

        foreach (var f in manifest.Files)
        {
            var bytes = fileBytes(f.Path);
            if (bytes is null)
                return new UpdateResult(UpdateStatus.HashMismatch, manifest.Version, $"Arquivo ausente: {f.Path}");
            if (!string.Equals(ReleaseManifest.Sha256Hex(bytes), f.Sha256, StringComparison.OrdinalIgnoreCase))
                return new UpdateResult(UpdateStatus.HashMismatch, manifest.Version, $"Hash não confere: {f.Path}");
        }

        CurrentVersion = manifest.Version;
        return new UpdateResult(UpdateStatus.Accepted, manifest.Version, "OK");
    }
}
