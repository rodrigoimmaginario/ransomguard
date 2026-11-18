using System.Security.Cryptography;
using System.Text.Json;
using RansomGuard.Core.Signing;

namespace RansomGuard.Server.Auth;

/// <summary>
/// F38 — chave Ed25519 da instalação do painel. Gerada uma vez no primeiro boot, guardada fora do banco
/// (arquivo protegido na pasta de dados do painel). Assina a política de resposta, os comandos
/// e os relatórios de incidente que o agente e terceiros verificam. A chave pública é publicada em <c>/api/identity</c> para o agente fixar (TOFU ou
/// configuração explícita).
/// </summary>
public sealed class InstallSigningKey
{
    public InstallSigningKey(byte[] seed, byte[] keyId)
    {
        if (seed.Length != 32) throw new ArgumentException("Seed Ed25519 deve ter 32 bytes.", nameof(seed));
        if (keyId.Length != 8) throw new ArgumentException("KeyId deve ter 8 bytes.", nameof(keyId));
        Seed = seed; KeyId = keyId;
        PublicKey = MinisignPublicKey.FromRaw(keyId, Minisign.PublicKeyFromSeed(seed));
    }

    public byte[] Seed { get; }
    public byte[] KeyId { get; }
    public MinisignPublicKey PublicKey { get; }

    /// <summary>Conteúdo no formato <c>minisign.pub</c> — o que o agente guarda.</summary>
    public string PublicKeyFileContent => PublicKey.ToFileContent("RansomGuard panel install key");

    public static InstallSigningKey Generate()
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        var keyId = RandomNumberGenerator.GetBytes(8);
        return new InstallSigningKey(seed, keyId);
    }
}

public interface IInstallKeyStore
{
    Task<InstallSigningKey> GetOrCreateAsync(CancellationToken ct = default);
}

/// <summary>
/// Persistência em arquivo protegido (B2, <see cref="RansomGuard.Server.Security.ProtectedFile"/>). Cria se não existir;
/// nunca regenera uma chave existente — nem quando o arquivo existe e não abre: aí o painel para com erro.
/// </summary>
public sealed class FileInstallKeyStore(string path) : IInstallKeyStore
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private InstallSigningKey? _cached;

    private sealed record Stored(string Seed, string KeyId, DateTime CreatedAt);

    public async Task<InstallSigningKey> GetOrCreateAsync(CancellationToken ct = default)
    {
        if (_cached is not null) return _cached;
        await _gate.WaitAsync(ct);
        try
        {
            if (_cached is not null) return _cached;
            if (RansomGuard.Server.Security.ProtectedFile.ReadAndSeal(path) is { } existing)
            {
                var stored = JsonSerializer.Deserialize<Stored>(existing)
                             ?? throw new InvalidDataException("install-key inválido");
                _cached = new InstallSigningKey(Convert.FromBase64String(stored.Seed), Convert.FromBase64String(stored.KeyId));
                return _cached;
            }
            var key = InstallSigningKey.Generate();
            var json = JsonSerializer.Serialize(new Stored(Convert.ToBase64String(key.Seed), Convert.ToBase64String(key.KeyId), DateTime.UtcNow));
            RansomGuard.Server.Security.ProtectedFile.Write(path, json);
            _cached = key;
            return key;
        }
        finally { _gate.Release(); }
    }
}
