using Microsoft.EntityFrameworkCore;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Score;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Data;
using RansomGuard.Server.Ingestion;

namespace RansomGuard.Server.Seed;

/// <summary>
/// Semeia dados de demonstração (só em Development) para o painel ter conteúdo real ao subir —
/// alimentando pela camada de ingestão de verdade, como um agente faria. Não roda em produção.
/// </summary>
public static class DemoSeed
{
    public static async Task EnsureAsync(IServiceProvider sp)
    {
        var db = sp.GetRequiredService<RansomGuardDb>();
        if (await db.Servers.AnyAsync()) return;

        var svc = new IngestionService(db, new AlertEngine(new CollectingAlertSink()));
        var now = DateTime.UtcNow;

        // FS01 — mal configurado, sob ataque remoto via SMB + VSS deletado (incidente High). O lote leva a TRILHA do
        // agente (F32): detecção + decisão + ações (snapshot ok, IP falhou, sessão ok, usuário negado no share) e a lista
        // de arquivos (G5) — o painel de demonstração mostra o produto real, não uma tabela derivada.
        var demoEvents = Enumerable.Range(0, 90).Select(i =>
            new FileEvent(now.AddMinutes(-5).AddSeconds(i), @"CORP\vendas1", "10.0.9.66",
                @"\\FS01\Financeiro", FileOp.Rename, $"2024\\rel{i}.xlsx", ".locked", IsCanary: i == 3)).ToList();
        var demoDetection = new RansomGuard.Core.Detection.DetectionEngine().Analyze(demoEvents,
            new[] { new HostSignal(now.AddMinutes(-5), HostSignalKind.VssDeleted, "FS01") }).Single();
        var demoDecision = new RansomGuard.Core.Response.ResponseLadder().Decide(demoDetection,
            new RansomGuard.Core.Response.ResponsePolicy { Mode = RansomGuard.Core.Response.ResponseMode.Block });
        var demoRunner = new RansomGuard.Core.Response.ResponseRunner(new DemoExecutor());
        await demoRunner.RunAsync(demoDecision, now.AddMinutes(-4).AddSeconds(50));
        var demoIncident = RansomGuard.Core.Incidents.AgentIncident.From(demoDetection, demoDecision, demoRunner.Audit, RansomGuard.Core.Response.ResponseMode.Block);

        await svc.IngestAsync(new AgentBatch("FS01", now.AddMinutes(-6),
            new PostureSnapshot
            {
                Server = "FS01",
                SmbV1Enabled = true, SmbSigningRequired = false, NtlmUnrestricted = true,
                SharesWritableByEveryone = true, BroadNtfsPermissions = true,
                VssEnabled = false, BackupServiceRunning = false,
                FsrmActive = false, ShareAuditingEnabled = false, CanariesPlanted = false,
                AgentInstalled = true, OsEndOfLifeOrUnpatched = true, RdpExposed = true
            },
            demoEvents,
            new[] { new HostSignal(now.AddMinutes(-5), HostSignalKind.VssDeleted, "FS01") },
            new[] { demoIncident }));

        // FS02 — mediano: alguns achados, sem incidente.
        await svc.IngestAsync(new AgentBatch("FS02", now.AddMinutes(-4),
            new PostureSnapshot
            {
                Server = "FS02",
                SmbSigningRequired = true, SmbAuthRateLimiter = true, NtlmUnrestricted = false,
                SharesWritableByEveryone = false, BroadNtfsPermissions = true,
                VssEnabled = true, BackupServiceRunning = true, BackupsProtected = false,
                FsrmActive = true, ShareAuditingEnabled = true, CanariesPlanted = false,
                AgentInstalled = true
            },
            Array.Empty<FileEvent>(), Array.Empty<HostSignal>()));

        // FS03 — bem configurado (nota alta).
        await svc.IngestAsync(new AgentBatch("FS03", now.AddMinutes(-3),
            new PostureSnapshot
            {
                Server = "FS03",
                SmbSigningRequired = true, SmbAuthRateLimiter = true, NtlmUnrestricted = false,
                SharesWritableByEveryone = false, BroadNtfsPermissions = false,
                VssEnabled = true, BackupServiceRunning = true, BackupsProtected = true,
                FsrmActive = true, ShareAuditingEnabled = true, CanariesPlanted = true,
                AgentInstalled = true
            },
            Array.Empty<FileEvent>(), Array.Empty<HostSignal>()));
    }

    /// <summary>Executor de demonstração: tudo executa, exceto o firewall (para a trilha mostrar uma falha real).</summary>
    private sealed class DemoExecutor : RansomGuard.Core.Response.IResponseExecutor
    {
        public Task<RansomGuard.Core.Response.ResponseOutcome> ExecuteAsync(RansomGuard.Core.Response.ResponseAction a, CancellationToken ct = default) =>
            Task.FromResult(a.Step == RansomGuard.Core.Response.ResponseStep.BlockIp
                ? RansomGuard.Core.Response.ResponseOutcome.Fail("New-NetFirewallRule: acesso negado (GPO)")
                : RansomGuard.Core.Response.ResponseOutcome.Done());
        public Task<RansomGuard.Core.Response.ResponseOutcome> RevertAsync(RansomGuard.Core.Response.ResponseAction a, CancellationToken ct = default) =>
            Task.FromResult(RansomGuard.Core.Response.ResponseOutcome.Done());
    }
}
