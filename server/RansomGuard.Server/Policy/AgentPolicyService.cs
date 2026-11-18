using Microsoft.EntityFrameworkCore;
using RansomGuard.Core.Auth;
using RansomGuard.Core.Policy;
using RansomGuard.Server.Auth;
using RansomGuard.Server.Data;

namespace RansomGuard.Server.Policy;

/// <summary>Política de resposta por servidor (ou padrão <c>"*"</c>), editada no painel e versionada.</summary>
public sealed class AgentPolicyEntity
{
    public int Id { get; set; }
    /// <summary>Nome do servidor ou <c>"*"</c> (padrão da rede).</summary>
    public required string Server { get; set; }
    public string Mode { get; set; } = "Monitor";
    public string MaxStep { get; set; } = "DenyUserOnShare";
    /// <summary>Separados por ponto-e-vírgula.</summary>
    public string AllowlistedUsers { get; set; } = "";
    public string AllowlistedIps { get; set; } = "";
    public bool LearningMode { get; set; }
    /// <summary>G4b: blocklist de rede "ip@expiraUtcIso;…" — só na política padrão (*). Todos os agentes aplicam.</summary>
    public string BlockedIps { get; set; } = "";
    /// <summary>Contador global da instalação (anti-rollback no agente): cada salvamento recebe max+1.</summary>
    public long Version { get; set; }
    public DateTime UpdatedAt { get; set; }

    public static IReadOnlyList<string> Split(string csv) =>
        csv.Split(new[] { ';', ',', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

/// <summary>
/// F33 — publica a política e os comandos para o agente, assinados com a chave da instalação. A política
/// efetiva de um servidor é a específica, senão a padrão <c>"*"</c>; sem nenhuma, o agente mantém a sua.
/// </summary>
public sealed class AgentPolicyService(RansomGuardDb db, IInstallKeyStore keys, Func<IReadOnlySet<string>>? ownAddresses = null)
{
    /// <summary>B1: teto de endereços ativos na blocklist de rede. Acima disso é ruído ou abuso, não contenção.</summary>
    public const int MaxBlocklistEntries = 200;

    public static async Task EnsureSchemaAsync(RansomGuardDb db, CancellationToken ct = default)
    {
        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS "AgentPolicies" (
                "Id" INTEGER NOT NULL CONSTRAINT "PK_AgentPolicies" PRIMARY KEY AUTOINCREMENT,
                "Server" TEXT NOT NULL,
                "Mode" TEXT NOT NULL,
                "MaxStep" TEXT NOT NULL,
                "AllowlistedUsers" TEXT NOT NULL,
                "AllowlistedIps" TEXT NOT NULL,
                "LearningMode" INTEGER NOT NULL,
                "BlockedIps" TEXT NOT NULL DEFAULT '',
                "Version" INTEGER NOT NULL,
                "UpdatedAt" TEXT NOT NULL
            );
            """, ct);
        await db.Database.ExecuteSqlRawAsync("CREATE UNIQUE INDEX IF NOT EXISTS \"IX_AgentPolicies_Server\" ON \"AgentPolicies\" (\"Server\")", ct);
        var policyCols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using (var cmd = db.Database.GetDbConnection().CreateCommand())
        {
            if (cmd.Connection!.State != System.Data.ConnectionState.Open) await cmd.Connection.OpenAsync(ct);
            cmd.CommandText = "PRAGMA table_info(\"AgentPolicies\")";
            await using var r = await cmd.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct)) policyCols.Add(r.GetString(1));
        }
        if (!policyCols.Contains("BlockedIps"))
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"AgentPolicies\" ADD COLUMN \"BlockedIps\" TEXT NOT NULL DEFAULT ''", ct);
        // Resultado da reversão (F33) nas ações
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using (var cmd = db.Database.GetDbConnection().CreateCommand())
        {
            if (cmd.Connection!.State != System.Data.ConnectionState.Open) await cmd.Connection.OpenAsync(ct);
            cmd.CommandText = "PRAGMA table_info(\"ResponseActions\")";
            await using var r = await cmd.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct)) existing.Add(r.GetString(1));
        }
        if (!existing.Contains("RevertStatus"))
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"ResponseActions\" ADD COLUMN \"RevertStatus\" TEXT NULL", ct);
        if (!existing.Contains("RevertDetail"))
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"ResponseActions\" ADD COLUMN \"RevertDetail\" TEXT NULL", ct);
    }

    public Task<AgentPolicyEntity?> GetAsync(string server, CancellationToken ct = default) =>
        db.AgentPolicies.FirstOrDefaultAsync(p => p.Server == server, ct);

    /// <summary>Salva (cria ou atualiza) e atribui a próxima versão global.</summary>
    public async Task<AgentPolicyEntity> SaveAsync(AgentPolicyEntity input, DateTime now, CancellationToken ct = default)
    {
        var entity = await GetAsync(input.Server, ct) ?? new AgentPolicyEntity { Server = input.Server };
        entity.Mode = input.Mode; entity.MaxStep = input.MaxStep;
        entity.AllowlistedUsers = input.AllowlistedUsers; entity.AllowlistedIps = input.AllowlistedIps;
        entity.LearningMode = input.LearningMode; entity.UpdatedAt = now;
        entity.BlockedIps = input.BlockedIps ?? entity.BlockedIps;
        var max = await db.AgentPolicies.MaxAsync(p => (long?)p.Version, ct) ?? 0;
        entity.Version = max + 1;
        if (entity.Id == 0) db.AgentPolicies.Add(entity);
        await db.SaveChangesAsync(ct);
        return entity;
    }

    /// <summary>Política efetiva para o servidor, assinada — ou null se nada foi configurado no painel.</summary>
    public async Task<SignedAssertion?> IssuePolicyAsync(string server, DateTime now, CancellationToken ct = default)
    {
        var effective = await GetAsync(server, ct) ?? await GetAsync(AgentPolicyDocument.AllServers, ct);
        if (effective is null) return null;
        var key = await keys.GetOrCreateAsync(ct);
        // G4b: a blocklist vive na política padrão e vale para todos; a versão efetiva é a maior das duas, para que
        // uma entrada nova na blocklist nunca pareça "rollback" a um agente com política específica.
        var star = effective.Server == AgentPolicyDocument.AllServers ? effective : await GetAsync(AgentPolicyDocument.AllServers, ct);
        var blocklist = NetworkBlocklist.Active(star?.BlockedIps, now);
        var version = Math.Max(effective.Version, star?.Version ?? 0);
        var doc = new AgentPolicyDocument(effective.Server, version, effective.Mode, effective.MaxStep,
            AgentPolicyEntity.Split(effective.AllowlistedUsers), AgentPolicyEntity.Split(effective.AllowlistedIps),
            effective.LearningMode, now, blocklist);
        return AgentPolicyDocument.Sign(doc, key.Seed, key.KeyId);
    }

    /// <summary>Reversões pedidas no painel e ainda sem resultado, assinadas — ou null se não há nada pendente.</summary>
    public async Task<SignedAssertion?> IssueCommandsAsync(string server, DateTime now, CancellationToken ct = default)
    {
        var pending = await db.ResponseActions.Include(a => a.Detection).ThenInclude(d => d!.Server)
            .Where(a => a.RevertRequestedAt != null && a.RevertedAt == null && a.RevertStatus == null
                        && a.Detection!.Server!.Name == server)
            .OrderBy(a => a.Id).Take(50).ToListAsync(ct);
        if (pending.Count == 0) return null;
        var key = await keys.GetOrCreateAsync(ct);
        var commands = pending.Select(a => new AgentCommand(CommandId(a.Id), AgentCommand.Revert, a.Step, a.Target, a.Account,
            "reversão pedida no painel")).ToList();
        return CommandEnvelope.Sign(new CommandEnvelope(server, now, now + CommandEnvelope.Validity, commands), key.Seed, key.KeyId);
    }

    /// <summary>Aplica os resultados que o agente devolveu no lote.</summary>
    public async Task<int> ApplyResultsAsync(IReadOnlyList<CommandOutcome> results, CancellationToken ct = default)
    {
        var applied = 0;
        foreach (var r in results)
        {
            if (!TryActionId(r.CommandId, out var id)) continue;
            var action = await db.ResponseActions.FirstOrDefaultAsync(a => a.Id == id, ct);
            if (action is null || action.RevertStatus is not null) continue;
            action.RevertStatus = r.Status;
            action.RevertDetail = r.Detail;
            if (r.Status == "Executed") action.RevertedAt = r.At;
            applied++;
        }
        if (applied > 0) await db.SaveChangesAsync(ct);
        return applied;
    }

    /// <summary>
    /// G4b: um incidente remoto de Alta CONTIDO em qualquer servidor coloca o IP de origem na blocklist de rede por
    /// <see cref="NetworkBlocklist.Ttl"/>. Só IPs válidos e nunca os allowlisted na política padrão.
    /// </summary>
    public async Task<bool> AddToNetworkBlocklistAsync(string sourceIp, DateTime now, CancellationToken ct = default)
    {
        if (!RansomGuard.Core.Response.ResponseTarget.IsSafe(RansomGuard.Core.Response.ResponseStep.BlockIp, sourceIp)) return false;
        var star = await GetAsync(AgentPolicyDocument.AllServers, ct) ?? new AgentPolicyEntity { Server = AgentPolicyDocument.AllServers };
        if (AgentPolicyEntity.Split(star.AllowlistedIps).Contains(sourceIp, StringComparer.OrdinalIgnoreCase)) return false;
        var active = NetworkBlocklist.Active(star.BlockedIps, now);
        if (active.Contains(sourceIp, StringComparer.OrdinalIgnoreCase)) return false;   // já bloqueado: sem churn de versão
        // B1 — guarda da blocklist: o que TODOS os agentes passam a bloquear nunca inclui o próprio painel nem um
        // servidor monitorado (um incidente forjado, ou um file server usado como ponte, não derruba os demais), e
        // tem teto. Gateway e controladores de domínio são barrados em cada agente (InfrastructureGuardExecutor).
        if (active.Count >= MaxBlocklistEntries) return false;
        if ((ownAddresses ?? PanelAddresses.Current)().Contains(sourceIp)) return false;
        if (await db.Agents.AnyAsync(a => a.LastAddress == sourceIp, ct)) return false;
        var updated = NetworkBlocklist.Add(star.BlockedIps, sourceIp, now);
        if (updated == star.BlockedIps) return false;
        star.BlockedIps = updated;
        await SaveAsync(star, now, ct);
        return true;
    }

    public async Task RemoveFromNetworkBlocklistAsync(string ip, DateTime now, CancellationToken ct = default)
    {
        var star = await GetAsync(AgentPolicyDocument.AllServers, ct);
        if (star is null) return;
        star.BlockedIps = NetworkBlocklist.Remove(star.BlockedIps, ip);
        await SaveAsync(star, now, ct);
    }

    public static string CommandId(int actionId) => $"revert-{actionId}";
    private static bool TryActionId(string commandId, out int id)
    {
        id = 0;
        return commandId.StartsWith("revert-", StringComparison.Ordinal) && int.TryParse(commandId.AsSpan(7), out id);
    }
}

/// <summary>Formato persistido: "ip@2026-10-05T13:00:00Z;ip@…". Lógica pura (testável), TTL de 24 h.</summary>
/// <summary>Endereços do próprio painel (cache curto): nunca entram na blocklist que ele mesmo distribui.</summary>
public static class PanelAddresses
{
    private static IReadOnlySet<string> _cached = new HashSet<string>();
    private static DateTime _at = DateTime.MinValue;
    private static readonly object Gate = new();

    public static IReadOnlySet<string> Current()
    {
        lock (Gate)
        {
            if (DateTime.UtcNow - _at < TimeSpan.FromMinutes(5)) return _cached;
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "127.0.0.1", "::1" };
            try
            {
                foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                    foreach (var address in nic.GetIPProperties().UnicastAddresses)
                        set.Add(address.Address.ToString());
            }
            catch (Exception) { /* sem acesso às interfaces: fica só o loopback */ }
            _cached = set; _at = DateTime.UtcNow;
            return _cached;
        }
    }
}

public static class NetworkBlocklist
{
    public static readonly TimeSpan Ttl = TimeSpan.FromHours(24);

    public static IReadOnlyList<(string Ip, DateTime ExpiresAt)> Parse(string? stored) =>
        (stored ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(e => e.Split('@'))
            .Where(p => p.Length == 2 && DateTime.TryParse(p[1], null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out _))
            .Select(p => (p[0], DateTime.Parse(p[1], null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal)))
            .ToList();

    public static IReadOnlyList<string> Active(string? stored, DateTime now) =>
        Parse(stored).Where(e => e.ExpiresAt > now).Select(e => e.Ip).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    public static string Add(string? stored, string ip, DateTime now)
    {
        var entries = Parse(stored).Where(e => e.ExpiresAt > now && !e.Ip.Equals(ip, StringComparison.OrdinalIgnoreCase)).ToList();
        entries.Add((ip, now + Ttl));
        return Serialize(entries);
    }

    public static string Remove(string? stored, string ip) =>
        Serialize(Parse(stored).Where(e => !e.Ip.Equals(ip, StringComparison.OrdinalIgnoreCase)).ToList());

    private static string Serialize(IEnumerable<(string Ip, DateTime ExpiresAt)> entries) =>
        string.Join(";", entries.Select(e => $"{e.Ip}@{e.ExpiresAt:yyyy-MM-dd'T'HH:mm:ss'Z'}"));
}
