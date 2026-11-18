using RansomGuard.Core.Auth;
using RansomGuard.Core.Detection;

namespace RansomGuard.Core.Tests;

/// <summary>
/// D2 — "troca de extensão" precisa ser uma troca OBSERVADA. O coletor real preenche a extensão de todo arquivo
/// gravado; tratar isso como troca fazia qualquer gravação em massa aparecer como "troca de extensão".
/// </summary>
public class ExtensionChangeTests
{
    private static readonly DateTime T0 = new(2026, 11, 16, 10, 0, 0, DateTimeKind.Utc);
    private const string User = @"CORP\ana", Ip = "10.0.9.66", Share = @"\\FS01\Projetos";

    /// <summary>Como o coletor real entrega uma gravação: a extensão é a do próprio arquivo.</summary>
    private static FileEvent RealWrite(int second, string path) =>
        new(T0.AddSeconds(second), User, Ip, Share, FileOp.Write, path, NewExtension: Path.GetExtension(path));

    private static FileEvent RealDelete(int second, string path) =>
        new(T0.AddSeconds(second), User, Ip, Share, FileOp.Delete, path, NewExtension: Path.GetExtension(path));

    [Fact]
    public void Gravar_muitos_arquivos_com_a_propria_extensao_e_volume_e_nao_troca()
    {
        var events = Enumerable.Range(0, 120).Select(i => RealWrite(i % 50, $"planta{i}.dwg")).ToList();

        var detection = Assert.Single(new DetectionEngine().Analyze(events));

        Assert.Contains(DetectionReason.MassRewrite, detection.Reasons);
        Assert.DoesNotContain(DetectionReason.ExtensionFlip, detection.Reasons);
        Assert.Empty(ExtensionChanges.Observed(events));
    }

    [Fact]
    public void Gravar_o_cifrado_com_extensao_acrescentada_e_apagar_o_original_e_troca()
    {
        var events = Enumerable.Range(0, 60).SelectMany(i => new[]
        {
            RealWrite(i % 50, $@"2024\rel{i}.xlsx.locked"),
            RealDelete(i % 50, $@"2024\rel{i}.xlsx")
        }).ToList();

        var changes = ExtensionChanges.Observed(events);
        var detection = Assert.Single(new DetectionEngine().Analyze(events));

        Assert.Equal(60, changes.Count);
        Assert.All(changes, c => Assert.Equal(".locked", c.NewExtension));
        Assert.Contains(DetectionReason.ExtensionFlip, detection.Reasons);
    }

    [Fact]
    public void Extensao_substituida_no_mesmo_nome_e_na_mesma_pasta_tambem_e_troca()
    {
        var events = new[] { RealWrite(0, @"2024\rel.locked"), RealDelete(1, @"2024\rel.xlsx") };

        var change = Assert.Single(ExtensionChanges.Observed(events));

        Assert.Equal(".locked", change.NewExtension);
    }

    [Fact]
    public void Apagar_um_arquivo_e_gravar_outro_sem_relacao_nao_e_troca()
    {
        var events = new[]
        {
            RealWrite(0, @"2024\ata.docx"), RealDelete(1, @"2024\rascunho.docx"),      // nomes diferentes
            RealWrite(2, @"2025\rel.locked"), RealDelete(3, @"2024\rel.xlsx"),         // pastas diferentes
            RealWrite(4, @"2024\foto.jpg"), RealDelete(5, @"2024\foto.jpg")            // mesmo arquivo regravado e apagado
        };

        Assert.Empty(ExtensionChanges.Observed(events));
    }

    /// <summary>Fonte que já traz as duas pontas (nome antigo + extensão nova) continua valendo.</summary>
    [Fact]
    public void Evento_que_ja_traz_o_nome_antigo_e_a_extensao_nova_e_troca()
    {
        var e = new FileEvent(T0, User, Ip, Share, FileOp.Rename, "rel.xlsx", NewExtension: ".locked");

        Assert.Equal(".locked", Assert.Single(ExtensionChanges.Observed(new[] { e })).NewExtension);
    }

    [Theory]
    [InlineData(".dwg")] [InlineData(".PSD")] [InlineData(".sql")] [InlineData(".docx")] [InlineData(".mdf")]
    [InlineData(".pst")] [InlineData(".vhdx")] [InlineData(".indd")] [InlineData(".rvt")] [InlineData(".bak")]
    public void Extensoes_de_trabalho_sao_reconhecidas_como_legitimas(string ext)
        => Assert.True(LegitExtensions.Contains(ext));

    [Theory]
    [InlineData(".locked")] [InlineData(".zzq")] [InlineData(".lockbit")] [InlineData("")]
    public void Extensao_desconhecida_nao_e_legitima(string ext)
        => Assert.False(LegitExtensions.Contains(ext));
}

/// <summary>D10 — custo do hash de senha atualizado sem invalidar as contas que já existem.</summary>
public class PasswordHashUpgradeTests
{
    [Fact]
    public void Hash_novo_registra_as_iteracoes_e_usa_o_custo_atual()
    {
        var stored = PasswordHasher.Hash("senha-forte-123");

        var parts = stored.Split('.');
        Assert.Equal(3, parts.Length);
        Assert.Equal(PasswordHasher.CurrentIterations, int.Parse(parts[0]));
        Assert.True(PasswordHasher.CurrentIterations >= 600_000);
        Assert.True(PasswordHasher.Verify("senha-forte-123", stored));
        Assert.False(PasswordHasher.Verify("senha-errada", stored));
        Assert.False(PasswordHasher.NeedsRehash(stored));
    }

    [Fact]
    public void Hash_do_formato_antigo_continua_valendo_e_pede_atualizacao()
    {
        // Formato da RC: base64(salt).base64(hash), 100 mil iterações.
        var salt = new byte[16];
        var hash = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("senha-antiga-1", salt, 100_000, System.Security.Cryptography.HashAlgorithmName.SHA256, 32);
        var legacy = $"{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";

        Assert.True(PasswordHasher.Verify("senha-antiga-1", legacy));
        Assert.False(PasswordHasher.Verify("outra", legacy));
        Assert.True(PasswordHasher.NeedsRehash(legacy));
    }

    [Theory]
    [InlineData("")] [InlineData("abc")] [InlineData("1.2.3.4")] [InlineData("x.AAAA.AAAA")] [InlineData("0.AAAA.AAAA")] [InlineData("999999999999.AAAA.AAAA")]
    public void Valor_malformado_nunca_confere(string stored)
        => Assert.False(PasswordHasher.Verify("qualquer", stored));

    [Fact]
    public async Task Freio_de_login_aguenta_chamadas_simultaneas_e_nao_cresce_sem_limite()
    {
        var throttle = new LoginThrottle(maxFails: 5, lockout: TimeSpan.FromMinutes(5));
        var now = new DateTime(2026, 11, 16, 10, 0, 0, DateTimeKind.Utc);

        await Task.WhenAll(Enumerable.Range(0, 32).Select(t => Task.Run(() =>
        {
            for (var i = 0; i < 2_000; i++)
            {
                throttle.RegisterFailure($"conta-{t}-{i}|10.0.0.{t}", now);
                throttle.IsLocked($"conta-{t}-{i}|10.0.0.{t}", now);
            }
        })));

        Assert.True(throttle.TrackedKeys <= LoginThrottle.MaxTrackedKeys);

        // Quem está bloqueado agora continua bloqueado mesmo com a limpeza.
        for (var i = 0; i < 5; i++) throttle.RegisterFailure("admin|10.9.9.9", now.AddMinutes(1));
        Assert.True(throttle.IsLocked("admin|10.9.9.9", now.AddMinutes(2)));
        Assert.False(throttle.IsLocked("admin|10.9.9.9", now.AddMinutes(7)));
    }
}
