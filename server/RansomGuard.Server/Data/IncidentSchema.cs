using Microsoft.EntityFrameworkCore;

namespace RansomGuard.Server.Data;

/// <summary>
/// F32 — schema aditivo para bancos criados por versões anteriores (o EnsureCreated não altera banco
/// existente). Idempotente: colunas só são adicionadas se faltarem; a tabela só é criada se não existir.
/// </summary>
public static class IncidentSchema
{
    public static async Task EnsureAsync(RansomGuardDb db, CancellationToken ct = default)
    {
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using (var cmd = db.Database.GetDbConnection().CreateCommand())
        {
            if (cmd.Connection!.State != System.Data.ConnectionState.Open) await cmd.Connection.OpenAsync(ct);
            cmd.CommandText = "PRAGMA table_info(\"Detections\")";
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) existing.Add(reader.GetString(1));
        }

        var columns = new (string Name, string Ddl)[]
        {
            ("IncidentId", "\"IncidentId\" TEXT NULL"),
            ("Source", "\"Source\" TEXT NOT NULL DEFAULT 'panel'"),
            ("Mode", "\"Mode\" TEXT NULL"),
            ("Rationale", "\"Rationale\" TEXT NULL"),
            ("Contained", "\"Contained\" INTEGER NOT NULL DEFAULT 0"),
            ("AffectedPathsJson", "\"AffectedPathsJson\" TEXT NULL"),
        };
        foreach (var (name, ddl) in columns)
            if (!existing.Contains(name))
                await db.Database.ExecuteSqlRawAsync($"ALTER TABLE \"Detections\" ADD COLUMN {ddl}", ct);

        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS "ResponseActions" (
                "Id" INTEGER NOT NULL CONSTRAINT "PK_ResponseActions" PRIMARY KEY AUTOINCREMENT,
                "DetectionId" INTEGER NOT NULL,
                "At" TEXT NOT NULL,
                "Actor" TEXT NOT NULL,
                "Operation" TEXT NOT NULL,
                "Step" TEXT NOT NULL,
                "Target" TEXT NOT NULL,
                "Justification" TEXT NOT NULL,
                "RevertRequestedAt" TEXT NULL,
                "RevertedAt" TEXT NULL,
                "RevertStatus" TEXT NULL,
                "RevertDetail" TEXT NULL,
                "Account" TEXT NULL,
                CONSTRAINT "FK_ResponseActions_Detections_DetectionId" FOREIGN KEY ("DetectionId") REFERENCES "Detections" ("Id") ON DELETE CASCADE
            );
            """, ct);
        await db.Database.ExecuteSqlRawAsync("CREATE INDEX IF NOT EXISTS \"IX_ResponseActions_DetectionId\" ON \"ResponseActions\" (\"DetectionId\")", ct);
        await db.Database.ExecuteSqlRawAsync("CREATE UNIQUE INDEX IF NOT EXISTS \"IX_Detections_IncidentId\" ON \"Detections\" (\"IncidentId\") WHERE \"IncidentId\" IS NOT NULL", ct);
    }
}
