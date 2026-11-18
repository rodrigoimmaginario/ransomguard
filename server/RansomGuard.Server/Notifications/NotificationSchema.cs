using Microsoft.EntityFrameworkCore;
using RansomGuard.Server.Data;

namespace RansomGuard.Server.Notifications;

/// <summary>
/// Migrações **aditivas e idempotentes** para bancos criados por versões anteriores.
///
/// O projeto usa <c>EnsureCreated</c> (sem migrações EF), e o <c>EnsureCreated</c> não toca num
/// banco que já existe. Toda tabela ou coluna adicionada depois do primeiro release precisa ser
/// criada aqui à mão — senão o tester que atualiza tem o painel quebrando na primeira consulta.
///
/// Foi exatamente o que aconteceu: a coluna <c>PostureRecords.UnknownJson</c> (F11a) faltava num
/// banco antigo e derrubava a tela inicial. Descoberto ao rodar o painel de verdade — teste nenhum
/// pega, porque os testes criam o banco do zero com o modelo atual.
///
/// Convenção: sempre aditivo/retrocompatível — nenhuma coluna existente é alterada, nenhum dado é
/// tocado. Ao adicionar campo/tabela nova no modelo, adicione aqui também.
/// </summary>
public static class NotificationSchema
{
    public static async Task EnsureAsync(RansomGuardDb db, CancellationToken ct = default)
    {
        // ── Tabelas de notificação (F13) ────────────────────────────────────────────────────
        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS "NotificationChannels" (
                "Id" INTEGER NOT NULL CONSTRAINT "PK_NotificationChannels" PRIMARY KEY AUTOINCREMENT,
                "Kind" INTEGER NOT NULL,
                "Enabled" INTEGER NOT NULL,
                "NtfyServer" TEXT NULL,
                "NtfyTopic" TEXT NULL,
                "NtfyToken" TEXT NULL,
                "WebhookUrl" TEXT NULL,
                "WebhookFormat" INTEGER NULL,
                "TelegramBotToken" TEXT NULL,
                "TelegramChatId" TEXT NULL,
                "SmtpHost" TEXT NULL,
                "SmtpPort" INTEGER NOT NULL,
                "SmtpSsl" INTEGER NOT NULL,
                "SmtpUser" TEXT NULL,
                "SmtpPassword" TEXT NULL,
                "SmtpFrom" TEXT NULL,
                "SmtpTo" TEXT NULL,
                "LastAttemptAt" TEXT NULL,
                "LastAttemptOk" INTEGER NULL,
                "LastAttemptDetail" TEXT NULL
            );
            """, ct);

        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS "NotificationSettings" (
                "Id" INTEGER NOT NULL CONSTRAINT "PK_NotificationSettings" PRIMARY KEY,
                "MinimumSeverity" INTEGER NOT NULL,
                "FloodWindowMinutes" INTEGER NOT NULL,
                "NotifyAgentSilent" INTEGER NOT NULL
            );
            """, ct);

        // ── Conta do adm do painel (F14) ────────────────────────────────────────────────────
        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS "OwnerAccounts" (
                "Id" INTEGER NOT NULL CONSTRAINT "PK_OwnerAccounts" PRIMARY KEY,
                "Username" TEXT NOT NULL,
                "PasswordHash" TEXT NOT NULL,
                "CreatedAt" TEXT NOT NULL
            );
            """, ct);

        // ── Colunas aditivas de fatias anteriores ───────────────────────────────────────────
        // F11a: o não-verificado do Score, persistido para chegar à tela.
        await EnsureColumnAsync(db, "PostureRecords", "UnknownJson", "TEXT NOT NULL DEFAULT '[]'", ct);
        // G8: papel da conta (admin | viewer); contas antigas são admin.
        await EnsureColumnAsync(db, "OwnerAccounts", "Role", "TEXT NOT NULL DEFAULT 'admin'", ct);
    }

    /// <summary>
    /// Adiciona uma coluna só se ela ainda não existir. O <c>ALTER TABLE ADD COLUMN</c> do SQLite
    /// falha se a coluna já existe, então checamos o <c>PRAGMA table_info</c> antes — deixando a
    /// operação idempotente.
    /// </summary>
    private static async Task EnsureColumnAsync(
        RansomGuardDb db, string table, string column, string definition, CancellationToken ct)
    {
        var colunas = await db.Database
            .SqlQueryRaw<string>($"SELECT \"name\" AS \"Value\" FROM pragma_table_info('{table}')")
            .ToListAsync(ct);

        // pragma_table_info vazio = a tabela não existe. Não é nossa função criá-la aqui (o
        // EnsureCreated cuida das tabelas do modelo atual); só adicionamos coluna a tabela existente.
        if (colunas.Count == 0) return;
        if (colunas.Contains(column, StringComparer.OrdinalIgnoreCase)) return;

        await db.Database.ExecuteSqlRawAsync($"ALTER TABLE \"{table}\" ADD COLUMN \"{column}\" {definition};", ct);
    }
}
