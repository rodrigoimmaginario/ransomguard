using Microsoft.EntityFrameworkCore;
using RansomGuard.Server.Data;

namespace RansomGuard.Server.Auth;

/// <summary>
/// Identidade única desta instalação do painel: um GUID gerado na primeira execução e persistido. Não é
/// segredo — é o número de série publicado em <c>/api/identity</c>, ao lado da chave pública da instalação.
/// Linha única na tabela.
/// </summary>
public sealed class Installation
{
    public int Id { get; set; }
    public required string InstallId { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>
/// Garante o Install ID desta instalação: cria na primeira vez, reusa depois. A geração do GUID é injetável
/// para testes determinísticos.
/// </summary>
public sealed class InstallIdentity
{
    private readonly RansomGuardDb _db;
    private readonly Func<string> _newId;

    public InstallIdentity(RansomGuardDb db, Func<string>? newId = null)
    {
        _db = db;
        _newId = newId ?? (() => Guid.NewGuid().ToString("D"));
    }

    /// <summary>Retorna o Install ID desta instalação, criando-o (e persistindo) se ainda não existir.</summary>
    public async Task<string> GetOrCreateAsync(DateTime now, CancellationToken ct = default)
    {
        var existing = await _db.Installations.FirstOrDefaultAsync(ct);
        if (existing is not null) return existing.InstallId;

        var created = new Installation { InstallId = _newId(), CreatedAt = now };
        _db.Installations.Add(created);
        await _db.SaveChangesAsync(ct);
        return created.InstallId;
    }
}
