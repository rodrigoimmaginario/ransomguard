using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace RansomGuard.Server.Data;

/// <summary>
/// C2 — o esquema do banco evolui por migrações do EF (pasta <c>Data/Migrations</c>). Mudou uma entidade? Crie a
/// migração (<c>dotnet ef migrations add Nome --project server/RansomGuard.Server --output-dir Data/Migrations</c>);
/// um teste falha se o modelo andar sem ela.
///
/// Bancos criados ANTES das migrações (RC 0.9.0 e instalações de desenvolvimento) não têm o histórico do EF. Eles
/// passam uma vez pela ponte abaixo — os ajustes aditivos que o painel sempre fez na partida, mais a retirada do que
/// ficou órfão com o fim do licenciamento — e são marcados como estando na migração inicial. Dali em diante são
/// bancos como os outros.
/// </summary>
public static class SchemaUpgrade
{
    /// <summary>Migração que descreve o esquema em que a ponte deixa um banco antigo.</summary>
    public const string BaselineMigration = "20261116210717_Initial";

    public static async Task ApplyAsync(RansomGuardDb db, CancellationToken ct = default)
    {
        if (await TableExistsAsync(db, "Servers", ct) && !await TableExistsAsync(db, "__EFMigrationsHistory", ct))
            await BridgeLegacyDatabaseAsync(db, ct);

        await db.Database.MigrateAsync(ct);
    }

    private static async Task BridgeLegacyDatabaseAsync(RansomGuardDb db, CancellationToken ct)
    {
        // 1) Os ajustes aditivos de sempre (tabelas e colunas que versões sucessivas acrescentaram).
        await Notifications.NotificationSchema.EnsureAsync(db);
        await IncidentSchema.EnsureAsync(db);
        await Policy.AgentPolicyService.EnsureSchemaAsync(db, ct);
        await Auth.OperatorAudit.EnsureSchemaAsync(db, ct);
        await Agents.AgentEnrollmentService.EnsureSchemaAsync(db, ct);

        // 2) O que o fim do licenciamento deixou órfão e atrapalha: a coluna obrigatória que o painel não preenche
        //    mais impediria criar a identidade da instalação num banco da RC que ainda não a tivesse.
        if (await ColumnExistsAsync(db, "Installations", "HighWaterUtc", ct))
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"Installations\" DROP COLUMN \"HighWaterUtc\"", ct);
        //    As tabelas de licença e pagamento ficam onde estão: não atrapalham, e apagar dado do cliente numa
        //    atualização não é decisão para tomar em silêncio.

        // 3) A partir daqui o banco está no esquema da migração inicial: registra isso, para o EF não tentar criar tudo de novo.
        var history = db.GetService<IHistoryRepository>();
        await db.Database.ExecuteSqlRawAsync(history.GetCreateIfNotExistsScript(), ct);
        await db.Database.ExecuteSqlRawAsync(
            history.GetInsertScript(new HistoryRow(BaselineMigration, ProductInfo.GetVersion())), ct);
    }

    private static async Task<bool> TableExistsAsync(RansomGuardDb db, string table, CancellationToken ct)
    {
        var conn = db.Database.GetDbConnection();
        if (conn.State != System.Data.ConnectionState.Open) await conn.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = $name";
        var p = cmd.CreateParameter(); p.ParameterName = "$name"; p.Value = table; cmd.Parameters.Add(p);
        return Convert.ToInt64(await cmd.ExecuteScalarAsync(ct)) > 0;
    }

    private static async Task<bool> ColumnExistsAsync(RansomGuardDb db, string table, string column, CancellationToken ct)
    {
        var conn = db.Database.GetDbConnection();
        if (conn.State != System.Data.ConnectionState.Open) await conn.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = $"PRAGMA table_info(\"{table}\")";
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            if (string.Equals(reader.GetString(1), column, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }
}
