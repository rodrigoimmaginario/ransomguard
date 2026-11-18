using Microsoft.EntityFrameworkCore;
using RansomGuard.Core.Notifications;
using RansomGuard.Server.Data;
using RansomGuard.Server.Notifications;

namespace RansomGuard.Server.Tests;

/// <summary>
/// A persistência dos canais precisa de duas garantias: salvar/ler o que o admin configurou, e
/// **não quebrar o banco de um tester que já instalou uma versão anterior**. A segunda é a que dá
/// trabalho — o projeto usa EnsureCreated, que não toca em banco existente.
/// </summary>
public class NotificationPersistenceTests : IDisposable
{
    private readonly string _dbPath;

    public NotificationPersistenceTests()
        => _dbPath = Path.Combine(Path.GetTempPath(), $"rg-notif-{Guid.NewGuid():N}.db");

    public void Dispose()
    {
        try { if (File.Exists(_dbPath)) File.Delete(_dbPath); } catch { /* best-effort */ }
    }

    private RansomGuardDb Open() =>
        new(new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite($"Data Source={_dbPath}").Options);

    [Fact]
    public async Task Salva_e_le_um_canal_configurado()
    {
        await using (var db = Open())
        {
            await db.Database.EnsureCreatedAsync();
            db.NotificationChannels.Add(new NotificationChannelConfig
            {
                Kind = ChannelKind.Ntfy, Enabled = true,
                NtfyServer = "https://ntfy.corp.local", NtfyTopic = "ransomguard"
            });
            await db.SaveChangesAsync();
        }

        // Contexto novo: força ida ao disco, não ao cache.
        await using (var db = Open())
        {
            var c = await db.NotificationChannels.SingleAsync();
            Assert.Equal(ChannelKind.Ntfy, c.Kind);
            Assert.True(c.Enabled);
            Assert.Equal("ransomguard", c.NtfyTopic);
        }
    }

    /// <summary>
    /// **O teste que importa.** Simula o banco de um tester da versão anterior: criado sem as
    /// tabelas de notificação. Depois do EnsureAsync, a aba passa a funcionar — e nenhum dado antigo
    /// é tocado.
    /// </summary>
    [Fact]
    public async Task Banco_antigo_sem_as_tabelas_e_atualizado_sem_perder_dados()
    {
        // 1. "Banco antigo": só uma tabela de servidores, com um registro, e SEM as de notificação.
        await using (var db = Open())
        {
            await db.Database.ExecuteSqlRawAsync(
                "CREATE TABLE \"Servers\" (\"Id\" INTEGER PRIMARY KEY, \"Name\" TEXT);");
            await db.Database.ExecuteSqlRawAsync(
                "INSERT INTO \"Servers\" (\"Name\") VALUES ('FS01-legado');");
        }

        // 2. Atualização: cria as tabelas novas de forma aditiva.
        await using (var db = Open())
        {
            await NotificationSchema.EnsureAsync(db);

            db.NotificationChannels.Add(new NotificationChannelConfig
            {
                Kind = ChannelKind.Telegram, Enabled = true,
                TelegramBotToken = "123:ABC", TelegramChatId = "-100999"
            });
            await db.SaveChangesAsync();
        }

        // 3. O canal novo funciona E o dado legado continua lá.
        await using (var db = Open())
        {
            Assert.Equal(1, await db.NotificationChannels.CountAsync());

            var legado = await db.Database
                .SqlQueryRaw<string>("SELECT \"Name\" FROM \"Servers\"").ToListAsync();
            Assert.Contains("FS01-legado", legado);
        }
    }

    /// <summary>
    /// Regressão do bug que o F13 revelou ao rodar o painel de verdade: um banco criado antes do
    /// F11a não tem a coluna <c>PostureRecords.UnknownJson</c>, e a tela inicial quebrava com
    /// "no such column". A migração aditiva tem que adicionar a coluna sem tocar nos dados.
    /// </summary>
    [Fact]
    public async Task Banco_antigo_sem_UnknownJson_ganha_a_coluna()
    {
        // "Banco antigo": PostureRecords no formato pré-F11a (sem UnknownJson), com um registro.
        await using (var db = Open())
        {
            await db.Database.ExecuteSqlRawAsync("""
                CREATE TABLE "PostureRecords" (
                    "Id" INTEGER PRIMARY KEY, "ServerId" INTEGER, "At" TEXT,
                    "Score" INTEGER, "Band" INTEGER, "FindingsJson" TEXT);
                """);
            await db.Database.ExecuteSqlRawAsync(
                "INSERT INTO \"PostureRecords\" (\"Score\", \"FindingsJson\") VALUES (80, '[]');");
        }

        await using (var db = Open())
            await NotificationSchema.EnsureAsync(db);

        // A coluna existe, o default vale, e o registro antigo continua lá.
        await using (var db = Open())
        {
            var unknown = await db.Database
                .SqlQueryRaw<string>("SELECT \"UnknownJson\" AS \"Value\" FROM \"PostureRecords\"").ToListAsync();
            Assert.Single(unknown);
            Assert.Equal("[]", unknown[0]);
        }
    }

    [Fact]
    public async Task EnsureColumn_e_idempotente_em_banco_ja_atualizado()
    {
        await using var db = Open();
        await db.Database.EnsureCreatedAsync();   // já tem UnknownJson

        // Rodar a migração num banco novo não pode tentar adicionar a coluna de novo.
        await NotificationSchema.EnsureAsync(db);
        await NotificationSchema.EnsureAsync(db);

        Assert.Equal(0, await db.PostureRecords.CountAsync());
    }

    [Fact]
    public async Task EnsureAsync_e_idempotente()
    {
        await using var db = Open();
        await db.Database.EnsureCreatedAsync();

        // Rodar de novo num banco que já tem as tabelas não pode lançar.
        await NotificationSchema.EnsureAsync(db);
        await NotificationSchema.EnsureAsync(db);

        Assert.Equal(0, await db.NotificationChannels.CountAsync());
    }

    [Fact]
    public async Task Configuracao_de_quando_notificar_persiste()
    {
        await using (var db = Open())
        {
            await db.Database.EnsureCreatedAsync();
            db.NotificationSettings.Add(new NotificationSettings
            {
                Id = 1,
                MinimumSeverity = AlertSeverity.Warning,
                FloodWindowMinutes = 5,
                NotifyAgentSilent = false
            });
            await db.SaveChangesAsync();
        }

        await using (var db = Open())
        {
            var s = await db.NotificationSettings.SingleAsync();
            Assert.Equal(AlertSeverity.Warning, s.MinimumSeverity);
            Assert.Equal(5, s.FloodWindowMinutes);
            Assert.False(s.NotifyAgentSilent);
        }
    }
}
