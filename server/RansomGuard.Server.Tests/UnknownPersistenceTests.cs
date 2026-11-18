using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RansomGuard.Core.Score;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Data;
using RansomGuard.Server.Ingestion;

namespace RansomGuard.Server.Tests;

/// <summary>
/// As checagens não realizadas precisam sobreviver até a tela. Se ficarem só no cálculo, a nota
/// aparece no painel parecendo completa — que é exatamente o problema que a fatia veio corrigir.
/// </summary>
public class UnknownPersistenceTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 7, 26, 12, 0, 0, DateTimeKind.Utc);

    // Mesmo padrão dos outros testes do painel: uma conexão em memória própria, aberta pelo teste e fechada no fim.
    // O banco "compartilhado" de antes só existia enquanto o pool segurasse uma conexão (CI de 2026-11-17: "no such
    // table"); segurar a conexão sem fechá-la coincidiu com a CI travando até o runner perder contato (5 de 5).
    private readonly List<SqliteConnection> _connections = new();

    private RansomGuardDb NewDb()
    {
        var conn = new SqliteConnection("DataSource=:memory:");
        conn.Open();
        _connections.Add(conn);
        return new RansomGuardDb(new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite(conn).Options);
    }

    public void Dispose()
    {
        foreach (var c in _connections) c.Dispose();
    }

    private static PostureSnapshot Posture(params string[] desconhecidas) => new()
    {
        Server = "FS01",
        SmbSigningRequired = true,
        SmbAuthRateLimiter = true,
        VssEnabled = true,
        BackupServiceRunning = true,
        BackupsProtected = true,
        FsrmActive = true,
        ShareAuditingEnabled = true,
        CanariesPlanted = true,
        UnknownChecks = desconhecidas.ToHashSet()
    };

    private static async Task<PostureRecord> IngerirAsync(RansomGuardDb db, PostureSnapshot posture)
    {
        var svc = new IngestionService(db, new AlertEngine(new CollectingAlertSink()));
        await svc.IngestAsync(new AgentBatch(
            "FS01", Now, posture, Array.Empty<RansomGuard.Core.Detection.FileEvent>(),
            Array.Empty<RansomGuard.Core.Detection.HostSignal>()));
        return await db.PostureRecords.OrderByDescending(p => p.At).FirstAsync();
    }

    [Fact]
    public async Task Checagens_nao_realizadas_sao_persistidas_com_titulo_e_premissa()
    {
        var db = NewDb();
        await db.Database.EnsureCreatedAsync();

        var rec = await IngerirAsync(db, Posture("share-everyone", "fsrm"));

        var itens = JsonDocument.Parse(rec.UnknownJson).RootElement;
        Assert.Equal(2, itens.GetArrayLength());

        // A tela precisa do texto, não só do id — senão o painel mostra "fsrm" e o admin não entende.
        foreach (var i in itens.EnumerateArray())
        {
            Assert.False(string.IsNullOrWhiteSpace(i.GetProperty("Title").GetString()));
            Assert.False(string.IsNullOrWhiteSpace(i.GetProperty("AttackPremise").GetString()));
        }
    }

    [Fact]
    public async Task Sem_desconhecidas_a_coluna_fica_vazia_e_nao_nula()
    {
        var db = NewDb();
        await db.Database.EnsureCreatedAsync();

        var rec = await IngerirAsync(db, Posture());

        Assert.Equal(0, JsonDocument.Parse(rec.UnknownJson).RootElement.GetArrayLength());
    }

    /// <summary>A nota gravada é a calculada sobre o medido — não a antiga, sobre o total.</summary>
    [Fact]
    public async Task Nota_persistida_ignora_o_que_nao_foi_medido()
    {
        var db = NewDb();
        await db.Database.EnsureCreatedAsync();

        var rec = await IngerirAsync(db, Posture("fsrm"));

        Assert.Equal(100, rec.Score);
        Assert.Empty(JsonDocument.Parse(rec.FindingsJson).RootElement.EnumerateArray());
    }

    /// <summary>
    /// Retrato antigo, gravado antes da coluna existir: a migração é aditiva, então o valor padrão
    /// vale e a tela simplesmente não mostra a seção.
    /// </summary>
    [Fact]
    public async Task Retrato_antigo_sem_a_coluna_continua_legivel()
    {
        var db = NewDb();
        await db.Database.EnsureCreatedAsync();
        var server = new ServerEntity { Name = "FS02", FirstSeen = Now, LastSeen = Now };
        db.Servers.Add(server);
        db.PostureRecords.Add(new PostureRecord
        {
            Server = server, At = Now, Score = 80, Band = RiskBand.Good,
            FindingsJson = "[]"                      // UnknownJson não informado, como num banco antigo
        });
        await db.SaveChangesAsync();

        var rec = await db.PostureRecords.FirstAsync(p => p.Server!.Name == "FS02");

        Assert.Equal("[]", rec.UnknownJson);
        Assert.Empty(JsonDocument.Parse(rec.UnknownJson).RootElement.EnumerateArray());
    }
}
