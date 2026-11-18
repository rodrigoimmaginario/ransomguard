using RansomGuard.Core.Detection;
using RansomGuard.Core.Fsrm;

namespace RansomGuard.Core.Tests;

/// <summary>
/// F18a — a assinatura prova quem publicou, não que o conteúdo é seguro de aplicar. Um catálogo
/// legítimo mas perigoso (lista vazia que cega o produto, ou curinga universal que bloquearia
/// arquivo de trabalho no FSRM) não pode virar file screen. A CatalogPolicy é a segunda porta,
/// depois da assinatura: recusa o que é operacionalmente inseguro.
/// </summary>
public class CatalogPolicyTests
{
    private static RansomwareCatalog Cat(int version, params string[] patterns)
        => new() { Version = version, Patterns = patterns };

    [Fact]
    public void Accepts_a_reasonable_catalog()
    {
        var r = CatalogPolicy.Check(Cat(3, "*.locked", "*.lockbit", "HOW_TO_DECRYPT*"));
        Assert.True(r.Ok);
    }

    [Theory]
    [InlineData(0)]      // versão precisa ser >= 1 (0 é reservado à semente)
    [InlineData(-1)]
    public void Rejects_non_positive_version(int version)
        => Assert.False(CatalogPolicy.Check(Cat(version, "*.locked")).Ok);

    [Fact]
    public void Rejects_empty_pattern_list()
        => Assert.False(CatalogPolicy.Check(Cat(2)).Ok);

    [Theory]
    [InlineData("*")]      // pega tudo
    [InlineData("*.*")]    // idem, com ponto
    [InlineData("*.")]     // degenerado
    [InlineData("")]       // vazio
    [InlineData("   ")]    // branco
    public void Rejects_dangerous_or_empty_pattern(string bad)
        => Assert.False(CatalogPolicy.Check(Cat(2, "*.locked", bad)).Ok);

    [Fact]
    public void Rejects_duplicate_patterns()
        => Assert.False(CatalogPolicy.Check(Cat(2, "*.locked", "*.LOCKED")).Ok);

    [Fact]
    public void Rejects_catalog_above_pattern_limit()
    {
        var many = Enumerable.Range(0, CatalogPolicy.MaxPatterns + 1)
            .Select(i => $"*.ext{i}").ToArray();
        Assert.False(CatalogPolicy.Check(Cat(2, many)).Ok);
    }

    [Fact]
    public void The_seed_catalog_satisfies_the_policy_shape_except_version()
    {
        // A semente é versão 0 (degrau), então a policy a recusa por versão — de propósito: ela não
        // é um catálogo publicado. Mas seus padrões, com uma versão real, passam.
        var seed = RansomwareCatalog.FromJson(SeedCatalog.Json);
        var asPublished = Cat(1, seed.Patterns.ToArray());
        Assert.True(CatalogPolicy.Check(asPublished).Ok);
    }
}

/// <summary>G7 — catálogo v2: notas de resgate e afinação de limiares, validados pela policy e aplicados pelo motor.</summary>
public class CatalogV2Tests
{
    private static readonly DateTime T0 = new(2026, 10, 4, 17, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void V1_json_still_loads_and_v2_fields_round_trip()
    {
        var v1 = RansomwareCatalog.FromJson("{\"version\":1,\"patterns\":[\"*.locked\"]}");
        Assert.Null(v1.NotePatterns); Assert.Null(v1.Tuning);
        Assert.Contains(".locked", v1.Extensions);

        var v2 = RansomwareCatalog.FromJson("{\"version\":2,\"patterns\":[\"*.abc\",\"*rec*ver*\"],\"notePatterns\":[\"*_leia_me*.txt\"],\"tuning\":{\"massThreshold\":60}}");
        Assert.Equal(new[] { "*_leia_me*.txt" }, v2.NotePatterns);
        Assert.Equal(60, v2.Tuning!.MassThreshold);
        Assert.Equal(new[] { ".abc" }, v2.Extensions);   // padrão com curinga interno não vira "extensão conhecida"
        Assert.Contains("notePatterns", v2.ToJson());
    }

    [Theory]
    [InlineData("[\"*decrypt*\"]", null, true)]
    [InlineData("[\"**\"]", null, false)]
    [InlineData("[\"..\\\\x\"]", null, false)]
    [InlineData("[\"$(x)*\"]", null, false)]
    [InlineData(null, "{\"massThreshold\":5}", false)]
    [InlineData(null, "{\"massThreshold\":60,\"readThreshold\":5000}", true)]
    [InlineData(null, "{\"slowThreshold\":1}", false)]
    public void Policy_validates_notes_and_tuning_ranges(string? notes, string? tuning, bool ok)
    {
        var json = $"{{\"version\":1,\"patterns\":[\"*.locked\"]{(notes is null ? "" : $",\"notePatterns\":{notes}")}{(tuning is null ? "" : $",\"tuning\":{tuning}")}}}";
        Assert.Equal(ok, CatalogPolicy.Check(RansomwareCatalog.FromJson(json)).Ok);
    }

    [Fact]
    public void Engine_uses_catalog_tuning_and_extra_note_patterns()
    {
        RansomwareCatalog? active = null;
        var opts = new DetectionOptions { MassThreshold = 40, CatalogProvider = () => active };
        FileEvent Ev(int i, string path) => new(T0.AddSeconds(i * 0.1), @"CORP\u", "10.0.9.66", @"\\FS01\Fin", FileOp.Write, path);
        var fifty = Enumerable.Range(0, 50).Select(i => Ev(i, $"f{i}.xlsx")).ToList();

        Assert.Single(new DetectionEngine(opts).Analyze(fifty));                                     // padrão: 50 ≥ 40
        active = RansomwareCatalog.FromJson("{\"version\":1,\"patterns\":[\"*.locked\"],\"tuning\":{\"massThreshold\":100}}");
        Assert.Empty(new DetectionEngine(opts).Analyze(fifty));                                      // catálogo afinou para 100

        active = RansomwareCatalog.FromJson("{\"version\":1,\"patterns\":[\"*.locked\"],\"notePatterns\":[\"*_leia_me*.txt\"]}");
        var notes = new[] { "a", "b", "c" }.Select((d, i) => Ev(i, $"{d}\\AVISO_leia_me_agora.txt")).ToList();
        var det = new DetectionEngine(opts).Analyze(notes).Single();
        Assert.Contains(DetectionReason.RansomNote, det.Reasons);
    }
}

/// <summary>O candidato real em list/catalog.json (o que a cerimônia vai assinar) passa na policy e é v2 completo.</summary>
public class CatalogCandidateTests
{
    private static string Repo()
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "RansomGuard.sln"))) dir = Path.GetDirectoryName(dir);
        return dir ?? throw new InvalidOperationException("raiz do repositório não encontrada");
    }

    [Fact]
    public void Candidate_catalog_is_valid_v2_with_notes_and_tuning()
    {
        var c = RansomwareCatalog.FromJson(File.ReadAllText(Path.Combine(Repo(), "list", "catalog.json")));
        var check = CatalogPolicy.Check(c);
        Assert.True(check.Ok, check.Reason);
        Assert.True(c.Version >= 2);
        Assert.True(c.Patterns.Count >= 100, $"{c.Patterns.Count} padrões");
        Assert.True(c.NotePatterns!.Count >= 20);
        Assert.NotNull(c.Tuning);
        Assert.True(c.Extensions.Count >= 100);
        Assert.All(c.Patterns, p => Assert.StartsWith("*", p));   // v2: notas saíram de patterns
    }
}

/// <summary>
/// O artefato PUBLICADO (list/catalog.json + .minisig, assinado na cerimônia de 2026-10-04) verifica com a chave pública
/// embarcada nos appsettings do agente e do painel. Se alguém trocar o catálogo sem reassinar, ou trocar a chave sem
/// reassinar, este teste reprova.
/// </summary>
public class PublishedCatalogSignatureTests
{
    private static string Repo()
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "RansomGuard.sln"))) dir = Path.GetDirectoryName(dir);
        return dir ?? throw new InvalidOperationException("raiz do repositório não encontrada");
    }

    private static string EmbeddedKey(string appsettings, string section, string name)
    {
        using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(Repo(), appsettings)));
        return doc.RootElement.GetProperty(section).GetProperty(name).GetString()!;
    }

    [Theory]
    [InlineData("agent/RansomGuard.Agent.Service/appsettings.json", "Agent", "CatalogPublicKeyBase64")]
    [InlineData("server/RansomGuard.Server/appsettings.json", "Catalog", "PublicKeyBase64")]
    public void Published_catalog_verifies_with_the_embedded_production_key(string appsettings, string section, string name)
    {
        var blob = Convert.FromBase64String(EmbeddedKey(appsettings, section, name));
        Assert.Equal(40, blob.Length);
        var key = RansomGuard.Core.Signing.MinisignPublicKey.FromRaw(blob.AsSpan(0, 8), blob.AsSpan(8, 32));
        Assert.Equal("CCCF0CA23A0B75AC", Convert.ToHexString(blob.AsSpan(0, 8)));   // keyId da cerimônia de 2026-10-04

        var json = File.ReadAllBytes(Path.Combine(Repo(), "list", "catalog.json"));
        var sig = RansomGuard.Core.Signing.MinisignSignature.Parse(File.ReadAllText(Path.Combine(Repo(), "list", "catalog.json.minisig")));
        Assert.Equal(RansomGuard.Core.Signing.MinisignVerificationResult.Valid, RansomGuard.Core.Signing.Minisign.Verify(json, sig, key));

        var tampered = (byte[])json.Clone(); tampered[^3] ^= 0x01;
        Assert.NotEqual(RansomGuard.Core.Signing.MinisignVerificationResult.Valid, RansomGuard.Core.Signing.Minisign.Verify(tampered, sig, key));
    }
}
