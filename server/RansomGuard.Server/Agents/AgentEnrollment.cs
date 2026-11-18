using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using RansomGuard.Core.Auth;
using RansomGuard.Server.Data;

namespace RansomGuard.Server.Agents;

/// <summary>Um agente enrolado: o nome do servidor vinculado à chave pública que ele apresentou.</summary>
public sealed class AgentRecord
{
    /// <summary>Nome do servidor em maiúsculas — a chave. Um nome, uma chave.</summary>
    [Key] public string ServerKey { get; set; } = "";
    /// <summary>Nome como o agente o informou (o que aparece nas telas e precisa bater com o lote).</summary>
    public string Server { get; set; } = "";
    public string PublicKey { get; set; } = "";
    public string Fingerprint { get; set; } = "";
    public DateTime EnrolledAt { get; set; }
    public string EnrolledFrom { get; set; } = "";
    /// <summary>Último endereço de onde o agente falou — nunca entra na blocklist de rede.</summary>
    public string LastAddress { get; set; } = "";
}

/// <summary>Token de enrolamento. Só o resumo é guardado: quem lê o banco não ganha um token utilizável.</summary>
public sealed class EnrollmentToken
{
    public int Id { get; set; }
    public string TokenHash { get; set; } = "";
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public int MaxUses { get; set; }
    public int Uses { get; set; }
    public string CreatedBy { get; set; } = "";
}

public enum EnrollOutcome { Enrolled, AlreadyEnrolled, InvalidRequest, InvalidToken, NameTaken }

/// <summary>
/// B1 — identidade por agente. Substitui o segredo de ingestão único (em texto no registro de cada servidor e na
/// linha de comando do instalador): quem o lesse num servidor falava em nome de todos.
///
/// O token de enrolamento só apresenta a chave do agente ao painel. Tem prazo e número de usos; depois de usado
/// não vale nada, então pode passar pela linha de comando do instalador. A autenticação de cada lote é a assinatura
/// do agente (<see cref="BatchSignature"/>), com a chave que nunca sai do servidor monitorado.
/// </summary>
public sealed class AgentEnrollmentService(RansomGuardDb db)
{
    public const int MaxTokenUses = 500;
    public static readonly TimeSpan MaxTokenLifetime = TimeSpan.FromDays(7);
    public static readonly TimeSpan DefaultTokenLifetime = TimeSpan.FromHours(24);

    public static async Task EnsureSchemaAsync(RansomGuardDb db, CancellationToken ct = default)
    {
        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS "Agents" (
                "ServerKey" TEXT NOT NULL CONSTRAINT "PK_Agents" PRIMARY KEY,
                "Server" TEXT NOT NULL,
                "PublicKey" TEXT NOT NULL,
                "Fingerprint" TEXT NOT NULL,
                "EnrolledAt" TEXT NOT NULL,
                "EnrolledFrom" TEXT NOT NULL,
                "LastAddress" TEXT NOT NULL
            );
            """, ct);
        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS "EnrollmentTokens" (
                "Id" INTEGER NOT NULL CONSTRAINT "PK_EnrollmentTokens" PRIMARY KEY AUTOINCREMENT,
                "TokenHash" TEXT NOT NULL,
                "CreatedAt" TEXT NOT NULL,
                "ExpiresAt" TEXT NOT NULL,
                "MaxUses" INTEGER NOT NULL,
                "Uses" INTEGER NOT NULL,
                "CreatedBy" TEXT NOT NULL
            );
            """, ct);
    }

    /// <summary>Cria um token e devolve o valor em claro — a única vez em que ele existe fora de quem o recebeu.</summary>
    public async Task<string> CreateTokenAsync(int maxUses, TimeSpan lifetime, string createdBy, DateTime now, CancellationToken ct = default)
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(30)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var life = lifetime <= TimeSpan.Zero ? DefaultTokenLifetime : lifetime > MaxTokenLifetime ? MaxTokenLifetime : lifetime;
        db.EnrollmentTokens.Add(new EnrollmentToken
        {
            TokenHash = HashOf(token), CreatedAt = now, ExpiresAt = now + life,
            MaxUses = Math.Clamp(maxUses, 1, MaxTokenUses), Uses = 0, CreatedBy = createdBy
        });
        await db.SaveChangesAsync(ct);
        return token;
    }

    public async Task<EnrollOutcome> EnrollAsync(string? token, string? server, string? publicKey, string origin, DateTime now, CancellationToken ct = default)
    {
        if (!AgentKey.IsValidServerName(server) || !AgentKey.IsValidPublicKey(publicKey)) return EnrollOutcome.InvalidRequest;

        var key = server!.ToUpperInvariant();
        var existing = await db.Agents.FirstOrDefaultAsync(a => a.ServerKey == key, ct);
        if (existing is not null)
            // O mesmo agente repetindo o pedido (resposta perdida) não gasta token; outra chave nunca toma o nome —
            // o administrador precisa revogar antes.
            return existing.PublicKey == publicKey ? EnrollOutcome.AlreadyEnrolled : EnrollOutcome.NameTaken;

        if (string.IsNullOrWhiteSpace(token)) return EnrollOutcome.InvalidToken;
        var hash = HashOf(token);
        // Consumo atômico: dois pedidos simultâneos com um token de uso único não passam os dois.
        var consumed = await db.Database.ExecuteSqlInterpolatedAsync(
            $"""UPDATE "EnrollmentTokens" SET "Uses" = "Uses" + 1 WHERE "TokenHash" = {hash} AND "Uses" < "MaxUses" AND "ExpiresAt" > {now}""", ct);
        if (consumed != 1) return EnrollOutcome.InvalidToken;

        db.Agents.Add(new AgentRecord
        {
            ServerKey = key, Server = server, PublicKey = publicKey!, Fingerprint = AgentKey.FingerprintOf(Convert.FromBase64String(publicKey!)),
            EnrolledAt = now, EnrolledFrom = origin, LastAddress = origin
        });
        await db.SaveChangesAsync(ct);
        return EnrollOutcome.Enrolled;
    }

    public Task<AgentRecord?> FindAsync(string? server, CancellationToken ct = default)
    {
        var key = (server ?? "").ToUpperInvariant();
        return db.Agents.AsNoTracking().FirstOrDefaultAsync(a => a.ServerKey == key, ct);
    }

    public Task<List<AgentRecord>> ListAsync(CancellationToken ct = default) =>
        db.Agents.AsNoTracking().OrderBy(a => a.Server).ToListAsync(ct);

    public async Task<bool> RevokeAsync(string server, CancellationToken ct = default)
    {
        var key = server.ToUpperInvariant();
        // A exclusão vai direto ao banco; o que este contexto ainda tiver em memória para o mesmo nome é solto,
        // para um novo enrolamento na mesma requisição não esbarrar no registro antigo.
        foreach (var tracked in db.ChangeTracker.Entries<AgentRecord>().Where(e => e.Entity.ServerKey == key).ToList())
            tracked.State = EntityState.Detached;
        return await db.Agents.Where(a => a.ServerKey == key).ExecuteDeleteAsync(ct) > 0;
    }

    /// <summary>Registra de onde o agente está falando (só grava quando muda).</summary>
    public async Task TouchAddressAsync(string server, string address, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(address)) return;
        var key = server.ToUpperInvariant();
        await db.Agents.Where(a => a.ServerKey == key && a.LastAddress != address)
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.LastAddress, address), ct);
    }

    private static string HashOf(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}

/// <summary>
/// Memória curta das assinaturas já aceitas. Dentro da janela de relógio, a mesma assinatura só vale uma vez — um
/// pedido capturado não é reapresentado. Fora da janela, a própria verificação da assinatura recusa.
/// </summary>
public sealed class BatchReplayGuard
{
    private static readonly TimeSpan Keep = BatchSignature.MaxSkew * 2;
    private const int MaxEntries = 200_000;
    private readonly Dictionary<string, DateTime> _seen = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private DateTime _lastSweep = DateTime.MinValue;

    public bool TryRegister(string agent, string signature, DateTime now)
    {
        var key = agent.Trim().ToUpperInvariant() + "|" + signature;
        lock (_gate)
        {
            if (now - _lastSweep > TimeSpan.FromMinutes(1) || _seen.Count > MaxEntries)
            {
                foreach (var old in _seen.Where(kv => now - kv.Value > Keep).Select(kv => kv.Key).ToList()) _seen.Remove(old);
                _lastSweep = now;
            }
            if (_seen.TryGetValue(key, out var at) && now - at <= Keep) return false;
            _seen[key] = now;
            return true;
        }
    }
}
