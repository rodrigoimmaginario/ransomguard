using System.Text;
using RansomGuard.Core.Catalog;
using RansomGuard.Core.Fsrm;
using RansomGuard.Core.Signing;
using RansomGuard.Core.Updates;

namespace RansomGuard.Core.Tests;

/// <summary>Par de chaves de teste, gerado em runtime (nunca commitado).</summary>
internal static class TestKey
{
    // Seed Ed25519 de 32 bytes e keyId de 8 bytes, fixos só para reprodutibilidade dos testes.
    public static readonly byte[] Seed = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
    public static readonly byte[] KeyId = { 9, 8, 7, 6, 5, 4, 3, 2 };

    public static MinisignPublicKey PublicKey()
        => MinisignPublicKey.FromRaw(KeyId, Minisign.PublicKeyFromSeed(Seed));

    public static string Sign(string content, string trustedComment)
        => Minisign.Sign(Encoding.UTF8.GetBytes(content), Seed, KeyId, trustedComment);
}

public class MinisignTests
{
    [Fact]
    public void Signed_content_verifies_with_matching_key()
    {
        const string content = "{\"version\":1,\"patterns\":[\"*.locked\"]}";
        var sig = MinisignSignature.Parse(TestKey.Sign(content, "catalog v1"));

        var result = Minisign.Verify(Encoding.UTF8.GetBytes(content), sig, TestKey.PublicKey());
        Assert.Equal(MinisignVerificationResult.Valid, result);
    }

    [Fact]
    public void One_byte_change_invalidates_signature()
    {
        const string content = "{\"version\":1,\"patterns\":[\"*.locked\"]}";
        var sig = MinisignSignature.Parse(TestKey.Sign(content, "catalog v1"));

        var tampered = content.Replace("*.locked", "*.locke_"); // 1 byte diferente
        var result = Minisign.Verify(Encoding.UTF8.GetBytes(tampered), sig, TestKey.PublicKey());
        Assert.Equal(MinisignVerificationResult.InvalidSignature, result);
    }

    [Fact]
    public void Wrong_key_id_is_rejected()
    {
        const string content = "conteúdo";
        var sig = MinisignSignature.Parse(TestKey.Sign(content, "x"));
        var otherKey = MinisignPublicKey.FromRaw(
            new byte[] { 1, 1, 1, 1, 1, 1, 1, 1 }, Minisign.PublicKeyFromSeed(TestKey.Seed));

        Assert.Equal(MinisignVerificationResult.KeyIdMismatch,
            Minisign.Verify(Encoding.UTF8.GetBytes(content), sig, otherKey));
    }
}

public class CatalogVerifierTests
{
    private static string CatalogJson(int version) =>
        new RansomwareCatalog { Version = version, Patterns = new[] { "*.locked", "*.crypted" } }.ToJson();

    [Fact]
    public void Accepts_valid_signed_catalog_and_yields_fsrm_plan()
    {
        var json = CatalogJson(5);
        var sig = TestKey.Sign(json, "ransomware catalog v5");
        var verifier = new CatalogVerifier(TestKey.PublicKey());

        var result = verifier.TryLoad(json, sig);

        Assert.True(result.Accepted);
        Assert.Equal(5, verifier.LastAcceptedVersion);
        // O catálogo aceito produz um plano FSRM (a defesa só existe após verificação).
        var ps = FsrmPlan.BuildPowerShell(result.Catalog!, new[] { @"D:\X" });
        Assert.Contains("'*.locked'", ps);
    }

    [Fact]
    public void Rejects_tampered_catalog_and_produces_no_plan()
    {
        var json = CatalogJson(5);
        var sig = TestKey.Sign(json, "v5");
        var verifier = new CatalogVerifier(TestKey.PublicKey());

        var tampered = json.Replace("*.crypted", "*.evil00"); // mesmo tamanho, 1 assinatura quebrada
        var result = verifier.TryLoad(tampered, sig);

        Assert.Equal(CatalogLoadStatus.BadSignature, result.Status);
        Assert.Null(result.Catalog);
    }

    [Fact]
    public void Anti_rollback_rejects_older_or_equal_version()
    {
        var verifier = new CatalogVerifier(TestKey.PublicKey());
        var v5 = CatalogJson(5);
        verifier.TryLoad(v5, TestKey.Sign(v5, "v5"));

        var v3 = CatalogJson(3);
        var older = verifier.TryLoad(v3, TestKey.Sign(v3, "v3"));
        Assert.Equal(CatalogLoadStatus.Rollback, older.Status);

        var same = verifier.TryLoad(v5, TestKey.Sign(v5, "v5"));
        Assert.Equal(CatalogLoadStatus.Rollback, same.Status);

        Assert.Equal(5, verifier.LastAcceptedVersion); // não regrediu
    }

    [Fact]
    public void Unsigned_garbage_is_invalid_format_not_accepted()
    {
        var verifier = new CatalogVerifier(TestKey.PublicKey());
        var result = verifier.TryLoad(CatalogJson(1), "isto não é um minisig");
        Assert.Equal(CatalogLoadStatus.InvalidFormat, result.Status);
    }
}

public class ReleaseManifestTests
{
    private static string ManifestJson(int version, string path, byte[] content) =>
        new ReleaseManifest
        {
            Version = version,
            Files = new[] { new ReleaseFile(path, ReleaseManifest.Sha256Hex(content)) }
        }.ToJson();

    [Fact]
    public void Valid_manifest_with_matching_hash_is_accepted()
    {
        var payload = Encoding.UTF8.GetBytes("agent-v2-binary");
        var json = ManifestJson(2, "agent.exe", payload);
        var sig = TestKey.Sign(json, "release v2");
        var v = new ReleaseManifestVerifier(TestKey.PublicKey(), currentVersion: 1);

        var result = v.TryApply(json, sig, _ => payload);
        Assert.True(result.Accepted);
        Assert.Equal(2, v.CurrentVersion);
    }

    [Fact]
    public void Anti_downgrade_rejects_older_version()
    {
        var payload = Encoding.UTF8.GetBytes("x");
        var json = ManifestJson(1, "agent.exe", payload);
        var sig = TestKey.Sign(json, "v1");
        var v = new ReleaseManifestVerifier(TestKey.PublicKey(), currentVersion: 3);

        Assert.Equal(UpdateStatus.Downgrade, v.TryApply(json, sig, _ => payload).Status);
    }

    [Fact]
    public void Tampered_file_fails_hash_check()
    {
        var payload = Encoding.UTF8.GetBytes("agent-v2-binary");
        var json = ManifestJson(2, "agent.exe", payload);
        var sig = TestKey.Sign(json, "v2");
        var v = new ReleaseManifestVerifier(TestKey.PublicKey(), currentVersion: 1);

        // Entrega bytes diferentes dos assinados no manifesto.
        var result = v.TryApply(json, sig, _ => Encoding.UTF8.GetBytes("agent-v2-TROJAN"));
        Assert.Equal(UpdateStatus.HashMismatch, result.Status);
    }
}
