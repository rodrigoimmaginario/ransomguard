using Microsoft.EntityFrameworkCore;
using RansomGuard.Core.Auth;
using RansomGuard.Server.Data;

namespace RansomGuard.Server.Auth;

/// <summary>Desfecho de uma tentativa de login, legível para a tela.</summary>
public enum LoginOutcome { Success, WrongCredentials, Throttled, NoAccount }

/// <summary>
/// A conta do adm do painel: criação no primeiro acesso e verificação de login. O hash é do Core
/// (PBKDF2); aqui fica só a persistência e o freio de brute force.
///
/// O throttle é um singleton em memória (o painel é um processo só); zera ao reiniciar, o que é
/// aceitável para um painel self-hosted de um único adm.
/// </summary>
public sealed class OwnerAccountService
{
    private readonly RansomGuardDb _db;
    private static readonly LoginThrottle Throttle = new(maxFails: 5, lockout: TimeSpan.FromMinutes(5));

    public OwnerAccountService(RansomGuardDb db) => _db = db;

    /// <summary>Já existe conta? Se não, o painel força o setup antes de qualquer tela.</summary>
    public Task<bool> AccountExistsAsync(CancellationToken ct = default)
        => _db.OwnerAccounts.AnyAsync(ct);

    /// <summary>Cria a conta do adm (só uma vez). Recusa se já existir.</summary>
    public async Task<bool> CreateAsync(string username, string password, DateTime now, CancellationToken ct = default)
    {
        if (await AccountExistsAsync(ct)) return false;
        if (string.IsNullOrWhiteSpace(password) || password.Length < 8) return false;

        _db.OwnerAccounts.Add(new OwnerAccount
        {
            Id = 1,
            Username = string.IsNullOrWhiteSpace(username) ? "admin" : username.Trim(),
            PasswordHash = PasswordHasher.Hash(password),
            CreatedAt = now
        });
        await _db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>Verifica o login, aplicando o throttle. A <paramref name="key"/> é a origem (IP).</summary>
    public async Task<(LoginOutcome Outcome, string? Username)> TryLoginAsync(
        string username, string password, string key, DateTime now, CancellationToken ct = default)
    {
        var (outcome, user, _) = await TryLoginWithRoleAsync(username, password, key, now, ct);
        return (outcome, user);
    }

    /// <summary>G8: login devolvendo o papel. Várias contas: a admin (Id 1) e leitores.</summary>
    public async Task<(LoginOutcome Outcome, string? Username, string Role)> TryLoginWithRoleAsync(
        string username, string password, string key, DateTime now, CancellationToken ct = default)
    {
        if (Throttle.IsLocked(key, now)) return (LoginOutcome.Throttled, null, "");

        if (!await _db.OwnerAccounts.AnyAsync(ct)) return (LoginOutcome.NoAccount, null, "");
        var wanted = (username ?? "").Trim();
        var acc = await _db.OwnerAccounts.FirstOrDefaultAsync(a => a.Username.ToLower() == wanted.ToLower(), ct);

        // Compara o usuário e a senha; a verificação de senha é em tempo constante (hash falso quando a conta não existe,
        // para não revelar nomes por tempo de resposta).
        var ok = acc is not null && PasswordHasher.Verify(password ?? "", acc.PasswordHash);
        if (acc is null) PasswordHasher.Verify(password ?? "", PasswordHasher.Hash("tempo-constante"));
        if (!ok)
        {
            Throttle.RegisterFailure(key, now);
            return (LoginOutcome.WrongCredentials, null, "");
        }

        Throttle.RegisterSuccess(key);
        // D10: conta criada com o custo antigo de hash é regravada com o atual — só aqui, onde a senha certa está em mãos.
        if (PasswordHasher.NeedsRehash(acc!.PasswordHash))
        {
            acc.PasswordHash = PasswordHasher.Hash(password!);
            await _db.SaveChangesAsync(ct);
        }
        return (LoginOutcome.Success, acc!.Username, string.IsNullOrWhiteSpace(acc.Role) ? Roles.Admin : acc.Role);
    }

    // ── G8: contas de leitura ─────────────────────────────────────────────────────────────────
    public Task<List<OwnerAccount>> ListAsync(CancellationToken ct = default) => _db.OwnerAccounts.OrderBy(a => a.Id).ToListAsync(ct);

    /// <summary>Cria uma conta só-leitura. Recusa nome repetido, senha curta ou ausência da conta admin.</summary>
    public async Task<bool> AddViewerAsync(string username, string password, DateTime now, CancellationToken ct = default)
    {
        var name = (username ?? "").Trim();
        if (name.Length < 2 || name.Length > 64 || string.IsNullOrWhiteSpace(password) || password.Length < 8) return false;
        if (!await _db.OwnerAccounts.AnyAsync(a => a.Id == 1, ct)) return false;
        if (await _db.OwnerAccounts.AnyAsync(a => a.Username.ToLower() == name.ToLower(), ct)) return false;
        var nextId = (await _db.OwnerAccounts.MaxAsync(a => (int?)a.Id, ct) ?? 1) + 1;
        _db.OwnerAccounts.Add(new OwnerAccount { Id = nextId, Username = name, PasswordHash = PasswordHasher.Hash(password), CreatedAt = now, Role = Roles.Viewer });
        await _db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>Remove uma conta de leitura. A admin (Id 1) nunca é removida.</summary>
    public async Task<bool> RemoveAsync(int id, CancellationToken ct = default)
    {
        if (id == 1) return false;
        var acc = await _db.OwnerAccounts.FirstOrDefaultAsync(a => a.Id == id, ct);
        if (acc is null) return false;
        _db.OwnerAccounts.Remove(acc);
        await _db.SaveChangesAsync(ct);
        return true;
    }
}
