using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Data;
using RansomGuard.Server.Ingestion;

namespace RansomGuard.Server.Tests;

/// <summary>
/// R2 — o monitor precisa realmente acionar a varredura de heartbeats em produção. Aqui montamos um
/// ServiceProvider mínimo sobre uma conexão SQLite in-memory compartilhada (fiel ao provider real) e
/// provamos que um agente silencioso além do limite gera o alerta de tamper via o monitor.
/// </summary>
public sealed class HeartbeatMonitorTests : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly ServiceProvider _sp;
    private readonly CollectingAlertSink _sink = new();
    private static readonly DateTime Now = new(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc);

    public HeartbeatMonitorTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:");
        _conn.Open();

        var services = new ServiceCollection();
        services.AddDbContext<RansomGuardDb>(o => o.UseSqlite(_conn));
        services.AddSingleton<IAlertSink>(_sink);
        services.AddScoped<AlertEngine>(sp => new AlertEngine(sp.GetRequiredService<IAlertSink>()));
        services.AddScoped<IngestionService>();
        _sp = services.BuildServiceProvider();

        using var scope = _sp.CreateScope();
        scope.ServiceProvider.GetRequiredService<RansomGuardDb>().Database.EnsureCreated();
    }

    private HeartbeatMonitor Monitor() => new(
        _sp.GetRequiredService<IServiceScopeFactory>(),
        NullLogger<HeartbeatMonitor>.Instance,
        maxSilence: TimeSpan.FromMinutes(10));

    private async Task SeedHeartbeatAsync(DateTime lastBeat)
    {
        using var scope = _sp.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RansomGuardDb>();
        db.Heartbeats.Add(new AgentHeartbeat { Server = "FS01", LastBeat = lastBeat });
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task Silent_agent_beyond_limit_raises_tamper_alert()
    {
        await SeedHeartbeatAsync(Now.AddMinutes(-25));   // 25 min de silêncio > limite de 10

        var raised = await Monitor().RunOnceAsync(Now);

        Assert.Equal(1, raised);
        Assert.Contains(_sink.Sent, a => a.Subject.Contains("tamper"));
    }

    [Fact]
    public async Task Recent_heartbeat_raises_nothing()
    {
        await SeedHeartbeatAsync(Now.AddMinutes(-2));    // dentro do limite

        var raised = await Monitor().RunOnceAsync(Now);

        Assert.Equal(0, raised);
        Assert.Empty(_sink.Sent);
    }

    [Fact]
    public async Task Alert_fires_once_per_silence()
    {
        await SeedHeartbeatAsync(Now.AddMinutes(-25));

        var first = await Monitor().RunOnceAsync(Now);
        var second = await Monitor().RunOnceAsync(Now.AddMinutes(1));   // ainda silencioso

        Assert.Equal(1, first);
        Assert.Equal(0, second);   // idempotente: TamperAlerted já marcado
    }

    public void Dispose() { _sp.Dispose(); _conn.Dispose(); }
}
