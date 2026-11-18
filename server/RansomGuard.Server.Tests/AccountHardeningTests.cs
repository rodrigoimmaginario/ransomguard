using Bunit;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using RansomGuard.Core.Auth;
using RansomGuard.Server.Auth;
using RansomGuard.Server.Components.Pages;
using RansomGuard.Server.Data;
using RansomGuard.Server.Policy;
using RansomGuard.Server.Security;

namespace RansomGuard.Server.Tests;

/// <summary>D10 — conta criada com o custo antigo de hash é atualizada no primeiro login certo, sem trocar a senha.</summary>
public class PasswordRehashTests : DbTestBase
{
    private static readonly DateTime T0 = new(2026, 11, 16, 10, 0, 0, DateTimeKind.Utc);

    private static string LegacyHash(string password)
    {
        var salt = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
        var hash = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, System.Security.Cryptography.HashAlgorithmName.SHA256, 32);
        return $"{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
    }

    [Fact]
    public async Task Login_certo_atualiza_o_hash_antigo_e_login_errado_nao_mexe_nele()
    {
        var legacy = LegacyHash("senha-forte-123");
        Db.OwnerAccounts.Add(new OwnerAccount { Id = 1, Username = "admin", PasswordHash = legacy, CreatedAt = T0, Role = Roles.Admin });
        await Db.SaveChangesAsync();
        var accounts = new OwnerAccountService(Db);

        var wrong = await accounts.TryLoginWithRoleAsync("admin", "senha-errada", "rehash-a", T0);
        Assert.Equal(LoginOutcome.WrongCredentials, wrong.Item1);
        Assert.Equal(legacy, (await Db.OwnerAccounts.AsNoTracking().SingleAsync()).PasswordHash);

        var right = await accounts.TryLoginWithRoleAsync("admin", "senha-forte-123", "rehash-b", T0);
        Assert.Equal(LoginOutcome.Success, right.Item1);

        var stored = (await Db.OwnerAccounts.AsNoTracking().SingleAsync()).PasswordHash;
        Assert.NotEqual(legacy, stored);
        Assert.False(PasswordHasher.NeedsRehash(stored));
        Assert.Equal(LoginOutcome.Success, (await accounts.TryLoginWithRoleAsync("admin", "senha-forte-123", "rehash-c", T0)).Item1);
    }
}

/// <summary>
/// D10 — as telas que alteram política ou desfazem contenção só mostram os controles a quem É administrador. Antes,
/// a falta de estado de autenticação era tratada como administrador (falha aberta).
/// </summary>
public sealed class AdminOnlyControlsTests : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly BunitContext _ctx = new();
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rg-admin-" + Guid.NewGuid().ToString("N"));

    public AdminOnlyControlsTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:"); _conn.Open();
        _ctx.Services.AddDbContext<RansomGuardDb>(o => o.UseSqlite(_conn));
        _ctx.Services.AddSingleton(new InstallSecrets { IngestSecret = "segredo-de-teste-123", CertificateThumbprint = "ABCDEF" });
        _ctx.Services.AddSingleton<IHttpContextAccessor>(new HttpContextAccessor { HttpContext = new DefaultHttpContext() });
        _ctx.Services.AddSingleton<IInstallKeyStore>(new FileInstallKeyStore(Path.Combine(_dir, "k.json")));
        _ctx.Services.AddScoped<AgentPolicyService>();
        using var db = new RansomGuardDb(new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite(_conn).Options);
        db.Database.EnsureCreated();
        AgentPolicyService.EnsureSchemaAsync(db).GetAwaiter().GetResult();
    }

    public void Dispose() { _ctx.Dispose(); _conn.Dispose(); if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    private const string SaveButton = "Salvar e publicar";

    [Fact]
    public void Sem_estado_de_autenticacao_a_tela_de_politica_nao_oferece_salvar()
        => Assert.DoesNotContain(SaveButton, _ctx.Render<Politica>().Markup);

    [Fact]
    public void Visitante_nao_autenticado_nao_ve_o_botao_de_salvar()
    {
        _ctx.AddAuthorization().SetNotAuthorized();

        Assert.DoesNotContain(SaveButton, _ctx.Render<Politica>().Markup);
    }

    [Fact]
    public void Conta_de_leitura_nao_ve_o_botao_e_o_administrador_ve()
    {
        var auth = _ctx.AddAuthorization();
        auth.SetAuthorized("soc");
        auth.SetRoles(Roles.Viewer);
        Assert.DoesNotContain(SaveButton, _ctx.Render<Politica>().Markup);

        auth.SetAuthorized("admin");
        auth.SetRoles(Roles.Admin);
        Assert.Contains(SaveButton, _ctx.Render<Politica>().Markup);
    }
}
