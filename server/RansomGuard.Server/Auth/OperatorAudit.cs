using Microsoft.EntityFrameworkCore;
using RansomGuard.Server.Data;

namespace RansomGuard.Server.Auth;

/// <summary>G8 — quem fez o quê no painel (login, política, blocklist, reversão, contas, backup). Metadado, nunca segredo.</summary>
public sealed class OperatorAuditEntry
{
    public int Id { get; set; }
    public DateTime At { get; set; }
    public required string User { get; set; }
    /// <summary>login.ok | login.fail | logout | policy.save | blocklist.release | revert.request | account.add | account.remove | backup | catalog.import</summary>
    public required string Action { get; set; }
    public string Detail { get; set; } = "";
    public string Origin { get; set; } = "";
}

public static class OperatorAudit
{
    public static async Task EnsureSchemaAsync(RansomGuardDb db, CancellationToken ct = default)
    {
        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS "OperatorAudit" (
                "Id" INTEGER NOT NULL CONSTRAINT "PK_OperatorAudit" PRIMARY KEY AUTOINCREMENT,
                "At" TEXT NOT NULL,
                "User" TEXT NOT NULL,
                "Action" TEXT NOT NULL,
                "Detail" TEXT NOT NULL,
                "Origin" TEXT NOT NULL
            );
            """, ct);
        await db.Database.ExecuteSqlRawAsync("CREATE INDEX IF NOT EXISTS \"IX_OperatorAudit_At\" ON \"OperatorAudit\" (\"At\")", ct);
    }

    public static async Task RecordAsync(RansomGuardDb db, string? user, string action, string detail, string origin = "", CancellationToken ct = default)
    {
        db.OperatorAudit.Add(new OperatorAuditEntry
        {
            At = DateTime.UtcNow, User = string.IsNullOrWhiteSpace(user) ? "-" : user, Action = action,
            Detail = detail.Length <= 500 ? detail : detail[..500], Origin = origin
        });
        await db.SaveChangesAsync(ct);
    }
}

/// <summary>Papéis do painel. <c>admin</c> altera; <c>viewer</c> só lê (G8).</summary>
public static class Roles
{
    public const string Admin = "admin";
    public const string Viewer = "viewer";
}
