using Microsoft.EntityFrameworkCore;
using RansomGuard.Server.Auth;
using RansomGuard.Server.Notifications;

namespace RansomGuard.Server.Data;

/// <summary>
/// Contexto EF Core (SQLite) do backend self-hosted. Modelo mantido simples e aditivo
/// (retrocompatível) por convenção do projeto.
/// </summary>
public sealed class RansomGuardDb : DbContext
{
    public RansomGuardDb(DbContextOptions<RansomGuardDb> options) : base(options) { }

    public DbSet<ServerEntity> Servers => Set<ServerEntity>();
    public DbSet<PostureRecord> PostureRecords => Set<PostureRecord>();
    public DbSet<DetectionRecord> Detections => Set<DetectionRecord>();
    public DbSet<ResponseActionRecord> ResponseActions => Set<ResponseActionRecord>();
    public DbSet<Policy.AgentPolicyEntity> AgentPolicies => Set<Policy.AgentPolicyEntity>();
    public DbSet<AgentHeartbeat> Heartbeats => Set<AgentHeartbeat>();
    public DbSet<Installation> Installations => Set<Installation>();

    // Notificações (F13) — tabelas aditivas; banco antigo continua abrindo com EnsureCreated.
    public DbSet<NotificationChannelConfig> NotificationChannels => Set<NotificationChannelConfig>();
    public DbSet<NotificationSettings> NotificationSettings => Set<NotificationSettings>();

    // Autenticação do painel (F14) — conta única do adm, aditiva.
    public DbSet<OwnerAccount> OwnerAccounts => Set<OwnerAccount>();
    public DbSet<OperatorAuditEntry> OperatorAudit => Set<OperatorAuditEntry>();

    // B1 — identidade por agente: agentes enrolados e tokens de enrolamento (aditivo).
    public DbSet<Agents.AgentRecord> Agents => Set<Agents.AgentRecord>();
    public DbSet<Agents.EnrollmentToken> EnrollmentTokens => Set<Agents.EnrollmentToken>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<ServerEntity>().HasIndex(s => s.Name).IsUnique();
        // C2: os índices que antes só existiam nos ajustes aditivos da partida passam a fazer parte do modelo — um
        // banco criado pelas migrações precisa nascer com eles.
        b.Entity<Policy.AgentPolicyEntity>().HasIndex(p => p.Server).IsUnique();
        b.Entity<DetectionRecord>().HasIndex(d => d.IncidentId).IsUnique().HasFilter("\"IncidentId\" IS NOT NULL");
        b.Entity<OperatorAuditEntry>().HasIndex(a => a.At);
        b.Entity<AgentHeartbeat>().HasIndex(h => h.Server).IsUnique();
        b.Entity<DetectionRecord>().HasIndex(d => new { d.ServerId, d.At });
    }
}
