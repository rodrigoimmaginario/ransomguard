using RansomGuard.Core.Auth;

namespace RansomGuard.Core.Tests;

public class PasswordHasherTests
{
    [Fact]
    public void Senha_correta_verifica()
    {
        var stored = PasswordHasher.Hash("s3nh4-do-adm!");
        Assert.True(PasswordHasher.Verify("s3nh4-do-adm!", stored));
    }

    [Fact]
    public void Senha_errada_nao_verifica()
    {
        var stored = PasswordHasher.Hash("s3nh4-do-adm!");
        Assert.False(PasswordHasher.Verify("outra", stored));
    }

    /// <summary>Salt por conta: a mesma senha gera hashes diferentes.</summary>
    [Fact]
    public void Mesma_senha_gera_hashes_diferentes()
        => Assert.NotEqual(PasswordHasher.Hash("igual"), PasswordHasher.Hash("igual"));

    [Fact]
    public void O_hash_nao_contem_a_senha_em_claro()
    {
        var stored = PasswordHasher.Hash("senha-secreta-xyz");
        Assert.DoesNotContain("senha-secreta-xyz", stored);
    }

    [Theory]
    [InlineData("")]
    [InlineData("sem-ponto")]
    [InlineData("a.b.c")]
    [InlineData("não-base64!.também-não!")]
    public void Formato_invalido_nao_explode_e_nao_verifica(string lixo)
        => Assert.False(PasswordHasher.Verify("qualquer", lixo));
}

public class LoginThrottleTests
{
    private static readonly DateTime T0 = new(2026, 7, 27, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Comeca_desbloqueado()
        => Assert.False(new LoginThrottle().IsLocked("adm", T0));

    [Fact]
    public void Bloqueia_apos_o_teto_de_falhas()
    {
        var t = new LoginThrottle(maxFails: 3);
        for (var i = 0; i < 3; i++) t.RegisterFailure("adm", T0);

        Assert.True(t.IsLocked("adm", T0));
    }

    [Fact]
    public void Nao_bloqueia_antes_do_teto()
    {
        var t = new LoginThrottle(maxFails: 3);
        t.RegisterFailure("adm", T0);
        t.RegisterFailure("adm", T0);

        Assert.False(t.IsLocked("adm", T0));
    }

    [Fact]
    public void O_bloqueio_expira()
    {
        var t = new LoginThrottle(maxFails: 3, lockout: TimeSpan.FromMinutes(5));
        for (var i = 0; i < 3; i++) t.RegisterFailure("adm", T0);

        Assert.False(t.IsLocked("adm", T0.AddMinutes(6)));
    }

    [Fact]
    public void Sucesso_limpa_o_historico()
    {
        var t = new LoginThrottle(maxFails: 3);
        t.RegisterFailure("adm", T0);
        t.RegisterFailure("adm", T0);
        t.RegisterSuccess("adm");
        t.RegisterFailure("adm", T0);

        Assert.False(t.IsLocked("adm", T0));   // recomeçou do zero
    }

    /// <summary>Uma conta bloqueada não bloqueia as outras (nem é o caso aqui, mas é a garantia certa).</summary>
    [Fact]
    public void Chaves_diferentes_sao_independentes()
    {
        var t = new LoginThrottle(maxFails: 2);
        t.RegisterFailure("origem-A", T0);
        t.RegisterFailure("origem-A", T0);

        Assert.True(t.IsLocked("origem-A", T0));
        Assert.False(t.IsLocked("origem-B", T0));
    }
}
