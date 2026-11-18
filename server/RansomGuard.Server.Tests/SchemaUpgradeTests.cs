using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RansomGuard.Core.Auth;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Score;
using RansomGuard.Server.Agents;
using RansomGuard.Server.Auth;
using RansomGuard.Server.Data;
using RansomGuard.Server.Policy;

namespace RansomGuard.Server.Tests;

/// <summary>
/// C2 — o esquema do banco evolui por migrações, e um banco criado pela RC 0.9.0 chega ao esquema atual sem perder
/// nada. O ponto de partida é o esquema REAL da RC (<c>Fixtures/rc-0.9.0-schema.sql</c>, tirado do binário publicado).
/// </summary>
public sealed class SchemaUpgradeTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rg-schema-" + Guid.NewGuid().ToString("N")[..10]);
    private string DbPath => Path.Combine(_dir, "ransomguard.db");

    public SchemaUpgradeTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }

    private RansomGuardDb Open() => new(new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite($"Data Source={DbPath}").Options);

    private void Raw(string sql)
    {
        using var conn = new SqliteConnection($"Data Source={DbPath}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private void CreateRcDatabase()
    {
        Raw(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "rc-0.9.0-schema.sql")));
        // Dados como a RC os gravaria: conta com o hash antigo, servidor com incidente e ação, política, licença.
        var salt = new byte[16];
        var hash = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("senha-da-rc-123", salt, 100_000, System.Security.Cryptography.HashAlgorithmName.SHA256, 32);
        Raw($"""
            INSERT INTO "OwnerAccounts" ("Id","Username","PasswordHash","CreatedAt","Role") VALUES (1,'admin','{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}','2026-10-04 12:00:00','admin');
            INSERT INTO "Servers" ("Id","Name","FirstSeen","LastSeen","LastScore","LastBand") VALUES (1,'FS01','2026-10-04 12:00:00','2026-10-04 13:00:00',62,1);
            INSERT INTO "Heartbeats" ("Server","LastBeat","TamperAlerted") VALUES ('FS01','2026-10-04 13:00:00',0);
            INSERT INTO "PostureRecords" ("ServerId","At","Score","Band","FindingsJson","UnknownJson") VALUES (1,'2026-10-04 12:30:00',62,1,'[]','[]');
            INSERT INTO "Detections" ("Id","ServerId","At","User","SourceIp","Share","Confidence","AffectedFiles","Reasons","Alerted","IncidentId","Source","Mode","Rationale","Contained")
                VALUES (1,1,'2026-10-04 12:40:00','CORP\vendas1','10.0.9.66','\\FS01\Financeiro',2,120,'CanaryTouched,MassRewrite',1,'inc-rc-1','agent','Block','contido',1);
            INSERT INTO "ResponseActions" ("DetectionId","At","Actor","Operation","Step","Target","Justification") VALUES (1,'2026-10-04 12:40:05','system','Execute','BlockIp','10.0.9.66','Alta');
            INSERT INTO "AgentPolicies" ("Server","Mode","MaxStep","AllowlistedUsers","AllowlistedIps","LearningMode","BlockedIps","Version","UpdatedAt") VALUES ('*','Alert','DenyUserOnShare','CORP\svc-backup','',0,'',3,'2026-10-04 12:00:00');
            INSERT INTO "Licenses" ("LicenseJson","Signature","ActivatedAt","Customer","Plan","ExpiresAt") VALUES ('x','y','2026-10-04 12:00:00','Cliente','pro','2027-10-04 00:00:00');
            INSERT INTO "OperatorAudit" ("At","User","Action","Detail","Origin") VALUES ('2026-10-04 12:00:00','admin','login.ok','admin','10.0.0.2');
            """);
    }

    /// <summary>O que o modelo atual espera e o banco não tem (tabela ou coluna). Vazio = o banco serve.</summary>
    private static List<string> MissingFromDatabase(RansomGuardDb db)
    {
        var missing = new List<string>();
        var conn = db.Database.GetDbConnection();
        if (conn.State != System.Data.ConnectionState.Open) conn.Open();
        foreach (var entity in db.Model.GetEntityTypes())
        {
            var table = entity.GetTableName()!;
            var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = $"PRAGMA table_info(\"{table}\")";
                using var reader = cmd.ExecuteReader();
                while (reader.Read()) columns.Add(reader.GetString(1));
            }
            if (columns.Count == 0) { missing.Add(table); continue; }
            missing.AddRange(entity.GetProperties().Select(p => p.GetColumnName()).Where(c => !columns.Contains(c)).Select(c => $"{table}.{c}"));
        }
        return missing;
    }

    /// <summary>Grava uma linha de cada tipo que o painel grava: prova que nenhuma coluna obrigatória órfã ficou no caminho.</summary>
    private static async Task WriteOneOfEachAsync(RansomGuardDb db)
    {
        var now = new DateTime(2026, 11, 16, 12, 0, 0, DateTimeKind.Utc);
        var server = new ServerEntity { Name = "FS-NOVO", FirstSeen = now, LastSeen = now };
        db.Servers.Add(server);
        await db.SaveChangesAsync();
        db.Heartbeats.Add(new AgentHeartbeat { Server = "FS-NOVO", LastBeat = now });
        db.PostureRecords.Add(new PostureRecord { ServerId = server.Id, At = now, Score = 80, Band = RiskBands.Of(80), FindingsJson = "[]", UnknownJson = "[]" });
        var detection = new DetectionRecord
        {
            Server = server, At = now, User = "u", SourceIp = "10.0.0.9", Share = "s", Confidence = Confidence.Medium, Reasons = "MassRewrite",
            IncidentId = "inc-novo-1", Source = "agent"
        };
        detection.Actions.Add(new ResponseActionRecord { At = now, Actor = "system", Operation = "Execute", Step = "BlockIp", Target = "10.0.0.9", Justification = "x" });
        db.Detections.Add(detection);
        db.Installations.Add(new Installation { InstallId = Guid.NewGuid().ToString(), CreatedAt = now });
        db.OperatorAudit.Add(new OperatorAuditEntry { At = now, User = "admin", Action = "teste", Detail = "", Origin = "" });
        db.AgentPolicies.Add(new AgentPolicyEntity { Server = "FS-NOVO", Mode = "Monitor", UpdatedAt = now });
        await db.SaveChangesAsync();

        var agents = new AgentEnrollmentService(db);
        var token = await agents.CreateTokenAsync(1, TimeSpan.FromHours(1), "admin", now);
        Assert.Equal(EnrollOutcome.Enrolled, await agents.EnrollAsync(token, "FS-NOVO", AgentKey.Generate().PublicKeyBase64, "10.0.0.9", now));
    }

    [Fact]
    public async Task Banco_novo_nasce_pelas_migracoes_com_tudo_o_que_o_modelo_espera()
    {
        await using var db = Open();

        await SchemaUpgrade.ApplyAsync(db);

        Assert.Empty(MissingFromDatabase(db));
        Assert.Contains(SchemaUpgrade.BaselineMigration, await db.Database.GetAppliedMigrationsAsync());
        Assert.Empty(await db.Database.GetPendingMigrationsAsync());
        await WriteOneOfEachAsync(db);
    }

    [Fact]
    public async Task Banco_da_RC_e_levado_ao_esquema_atual_sem_perder_dados_e_o_painel_grava_de_tudo_nele()
    {
        CreateRcDatabase();
        await using var db = Open();

        await SchemaUpgrade.ApplyAsync(db);

        Assert.Empty(MissingFromDatabase(db));
        Assert.Empty(await db.Database.GetPendingMigrationsAsync());

        // O que a RC tinha continua lá.
        Assert.Equal("FS01", (await db.Servers.SingleAsync()).Name);
        var incident = await db.Detections.Include(d => d.Actions).SingleAsync();
        Assert.Equal("inc-rc-1", incident.IncidentId);
        Assert.Equal(Confidence.High, incident.Confidence);
        Assert.Equal("BlockIp", Assert.Single(incident.Actions).Step);
        Assert.Equal(3, (await db.AgentPolicies.SingleAsync()).Version);
        Assert.Equal("login.ok", (await db.OperatorAudit.SingleAsync()).Action);

        // A conta da RC entra com a mesma senha (e o hash é atualizado no login).
        var login = await new OwnerAccountService(db).TryLoginWithRoleAsync("admin", "senha-da-rc-123", "upgrade", DateTime.UtcNow);
        Assert.Equal(LoginOutcome.Success, login.Item1);

        await WriteOneOfEachAsync(db);

        // Rodar de novo (todo boot roda) não muda nada nem falha.
        await SchemaUpgrade.ApplyAsync(db);
        Assert.Equal(2, await db.Servers.CountAsync());
    }

    /// <summary>
    /// Trava de regressão: mudou uma entidade e não criou a migração? Este teste falha — antes de um banco de cliente
    /// descobrir a diferença em produção.
    /// </summary>
    [Fact]
    public void O_modelo_nao_tem_mudanca_sem_migracao_correspondente()
    {
        using var db = Open();

        Assert.False(db.Database.HasPendingModelChanges());
    }
}
