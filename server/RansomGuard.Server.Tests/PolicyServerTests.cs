using RansomGuard.Core.Incidents;
using RansomGuard.Core.Response;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Policy;
using RansomGuard.Server.Alerts;
using RansomGuard.Server.Auth;
using RansomGuard.Server.Data;
using RansomGuard.Server.Ingestion;
using RansomGuard.Server.Policy;

namespace RansomGuard.Server.Tests;

/// <summary>F33 — o painel publica política e comandos assinados; o agente devolve resultados.</summary>
public sealed class PolicyServerTests : IDisposable
{
    private static readonly DateTime T0 = new(2026, 10, 4, 9, 0, 0, DateTimeKind.Utc);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rg-f33-" + Guid.NewGuid().ToString("N"));
    private readonly SqliteConnection _conn;
    private readonly RansomGuardDb _db;
    private readonly FileInstallKeyStore _keys;
    private readonly AgentPolicyService _svc;

    public PolicyServerTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:"); _conn.Open();
        _db = new RansomGuardDb(new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite(_conn).Options);
        _db.Database.EnsureCreated();
        AgentPolicyService.EnsureSchemaAsync(_db).GetAwaiter().GetResult();   // idempotente sobre EnsureCreated
        _keys = new FileInstallKeyStore(Path.Combine(_dir, "k.json"));
        _svc = new AgentPolicyService(_db, _keys);
    }
    public void Dispose() { _db.Dispose(); _conn.Dispose(); if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    [Fact]
    public async Task Save_assigns_increasing_global_versions_across_scopes()
    {
        var v1 = (await _svc.SaveAsync(new AgentPolicyEntity { Server = "*", Mode = "Alert" }, T0)).Version;
        var v2 = (await _svc.SaveAsync(new AgentPolicyEntity { Server = "FS01", Mode = "Block" }, T0)).Version;
        var v3 = (await _svc.SaveAsync(new AgentPolicyEntity { Server = "*", Mode = "Block" }, T0.AddMinutes(1))).Version;
        Assert.Equal(1, v1); Assert.Equal(2, v2); Assert.Equal(3, v3);   // contador global: nunca regride entre escopos
        Assert.Equal(2, await _db.AgentPolicies.CountAsync());
    }

    [Fact]
    public async Task Issued_policy_is_server_specific_when_present_else_default_else_null()
    {
        Assert.Null(await _svc.IssuePolicyAsync("FS01", T0));
        await _svc.SaveAsync(new AgentPolicyEntity { Server = "*", Mode = "Alert", AllowlistedUsers = "CORP\\svc-backup; CORP\\svc-av" }, T0);
        await _svc.SaveAsync(new AgentPolicyEntity { Server = "FS02", Mode = "Block" }, T0);

        var key = (await _keys.GetOrCreateAsync()).PublicKey;
        var p1 = AgentPolicyDocument.Verify(await _svc.IssuePolicyAsync("FS01", T0), key, "FS01", T0, null);
        Assert.Equal(PolicyOutcome.Valid, p1.Outcome);
        Assert.Equal("*", p1.Policy!.Server); Assert.Equal("Alert", p1.Policy.Mode);
        Assert.Equal(2, p1.Policy.AllowlistedUsers.Count);

        var p2 = AgentPolicyDocument.Verify(await _svc.IssuePolicyAsync("FS02", T0), key, "FS02", T0, null);
        Assert.Equal("FS02", p2.Policy!.Server); Assert.Equal("Block", p2.Policy.Mode);
    }

    private async Task<ResponseActionRecord> SeedExecutedAction(string server = "FS01")
    {
        var srv = new ServerEntity { Name = server, FirstSeen = T0, LastSeen = T0 };
        var det = new DetectionRecord { Server = srv, At = T0, User = @"CORP\ana", SourceIp = "10.0.9.66", Share = @"\\FS01\Fin", Confidence = Confidence.High, Source = "agent", IncidentId = Guid.NewGuid().ToString("N") };
        var act = new ResponseActionRecord { Detection = det, At = T0, Actor = "RansomGuard", Operation = "execute", Step = "DenyUserOnShare", Target = @"\\FS01\Fin", Account = @"CORP\ana", Justification = "r" };
        _db.ResponseActions.Add(act);
        await _db.SaveChangesAsync();
        return act;
    }

    [Fact]
    public async Task Pending_revert_becomes_a_signed_command_and_the_result_closes_it()
    {
        var act = await SeedExecutedAction();
        Assert.Null(await _svc.IssueCommandsAsync("FS01", T0));           // nada pedido ainda

        act.RevertRequestedAt = T0.AddMinutes(1); await _db.SaveChangesAsync();
        var key = (await _keys.GetOrCreateAsync()).PublicKey;
        var env = CommandEnvelope.Verify(await _svc.IssueCommandsAsync("FS01", T0.AddMinutes(1)), key, "FS01", T0.AddMinutes(1));
        Assert.Equal(PolicyOutcome.Valid, env.Outcome);
        var cmd = Assert.Single(env.Envelope!.Commands);
        Assert.Equal($"revert-{act.Id}", cmd.Id);
        Assert.Equal("DenyUserOnShare", cmd.Step); Assert.Equal(@"CORP\ana", cmd.Account);
        Assert.Null(await _svc.IssueCommandsAsync("FS02", T0.AddMinutes(1)));   // outro servidor não recebe

        var applied = await _svc.ApplyResultsAsync(new[] { new CommandOutcome(cmd.Id, "Executed", "ok", T0.AddMinutes(2)) });
        Assert.Equal(1, applied);
        var reloaded = await _db.ResponseActions.SingleAsync();
        Assert.Equal("Executed", reloaded.RevertStatus);
        Assert.Equal(T0.AddMinutes(2), reloaded.RevertedAt);
        Assert.Null(await _svc.IssueCommandsAsync("FS01", T0.AddMinutes(3)));   // fechado: não reenvia
    }

    [Fact]
    public async Task Failed_result_is_recorded_without_marking_reverted_and_unknown_ids_are_ignored()
    {
        var act = await SeedExecutedAction();
        act.RevertRequestedAt = T0; await _db.SaveChangesAsync();
        var applied = await _svc.ApplyResultsAsync(new[]
        {
            new CommandOutcome($"revert-{act.Id}", "Failed", "Unblock-SmbShareAccess falhou", T0),
            new CommandOutcome("revert-999", "Executed", "x", T0),
            new CommandOutcome("garbage", "Executed", "x", T0)
        });
        Assert.Equal(1, applied);
        var r = await _db.ResponseActions.SingleAsync();
        Assert.Equal("Failed", r.RevertStatus); Assert.Null(r.RevertedAt); Assert.Contains("Unblock", r.RevertDetail);
    }

    [Fact]
    public async Task Ingest_reply_carries_signed_policy_and_commands_and_applies_results()
    {
        await _svc.SaveAsync(new AgentPolicyEntity { Server = "*", Mode = "Block" }, T0);
        var act = await SeedExecutedAction();
        act.RevertRequestedAt = T0; await _db.SaveChangesAsync();
        var ingest = new IngestionService(_db, new AlertEngine(new CollectingAlertSink()), policies: _svc);

        var r1 = await ingest.IngestAsync(new AgentBatch("FS01", T0.AddMinutes(1), null, Array.Empty<FileEvent>(), Array.Empty<HostSignal>(), Array.Empty<Core.Incidents.AgentIncident>()));
        Assert.NotNull(r1.Policy); Assert.NotNull(r1.Commands);

        var r2 = await ingest.IngestAsync(new AgentBatch("FS01", T0.AddMinutes(2), null, Array.Empty<FileEvent>(), Array.Empty<HostSignal>(), Array.Empty<Core.Incidents.AgentIncident>(),
            new[] { new CommandOutcome($"revert-{act.Id}", "Executed", "ok", T0.AddMinutes(2)) }));
        Assert.NotNull(r2.Policy); Assert.Null(r2.Commands);              // reversão fechada no mesmo lote
        Assert.NotNull((await _db.ResponseActions.SingleAsync()).RevertedAt);
    }
}

/// <summary>G4b — blocklist de rede: o que um servidor conteve, todos bloqueiam; expira; respeita allowlist.</summary>
public sealed class NetworkBlocklistTests : IDisposable
{
    private static readonly DateTime T0 = new(2026, 10, 4, 13, 0, 0, DateTimeKind.Utc);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rg-g4b-" + Guid.NewGuid().ToString("N"));
    private readonly SqliteConnection _conn;
    private readonly RansomGuardDb _db;
    private readonly FileInstallKeyStore _keys;
    private readonly AgentPolicyService _svc;

    public NetworkBlocklistTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:"); _conn.Open();
        _db = new RansomGuardDb(new DbContextOptionsBuilder<RansomGuardDb>().UseSqlite(_conn).Options);
        _db.Database.EnsureCreated();
        AgentPolicyService.EnsureSchemaAsync(_db).GetAwaiter().GetResult();
        _keys = new FileInstallKeyStore(Path.Combine(_dir, "k.json"));
        _svc = new AgentPolicyService(_db, _keys);
    }
    public void Dispose() { _db.Dispose(); _conn.Dispose(); if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    [Fact]
    public void Blocklist_format_adds_dedupes_expires_and_removes()
    {
        var s = NetworkBlocklist.Add("", "10.0.9.66", T0);
        s = NetworkBlocklist.Add(s, "10.0.9.66", T0.AddMinutes(1));          // renova, não duplica
        s = NetworkBlocklist.Add(s, "10.0.9.77", T0);
        Assert.Equal(2, NetworkBlocklist.Active(s, T0.AddHours(1)).Count);
        Assert.Equal(new[] { "10.0.9.66" }, NetworkBlocklist.Active(s, T0.AddHours(24).AddMinutes(0.5)));   // .77 expirou, .66 renovado
        Assert.Empty(NetworkBlocklist.Active(s, T0.AddHours(30)));
        Assert.Empty(NetworkBlocklist.Active(NetworkBlocklist.Remove(NetworkBlocklist.Remove(s, "10.0.9.66"), "10.0.9.77"), T0));
        Assert.Empty(NetworkBlocklist.Active("lixo;;a@b", T0));
    }

    [Fact]
    public async Task Contained_remote_high_incident_puts_the_ip_on_every_agents_policy()
    {
        await _svc.SaveAsync(new AgentPolicyEntity { Server = "FS02", Mode = "Alert" }, T0);   // FS02 tem política própria
        var ingest = new IngestionService(_db, new AlertEngine(new CollectingAlertSink()), policies: _svc);

        var det = new Detection("FS01", @"CORP\ana", "10.0.9.66", @"\FS01\Fin", Confidence.High, new HashSet<DetectionReason> { DetectionReason.CanaryTouched }, 50, T0, T0.AddSeconds(5));
        var decision = new ResponseLadder().Decide(det, new ResponsePolicy { Mode = ResponseMode.Block });
        var runner = new ResponseRunner(new RecordingExecutor()); await runner.RunAsync(decision, T0.AddSeconds(6));
        var inc = AgentIncident.From(det, decision, runner.Audit, ResponseMode.Block);
        Assert.True(inc.Contained);

        await ingest.IngestAsync(new AgentBatch("FS01", T0.AddSeconds(7), null, Array.Empty<FileEvent>(), Array.Empty<HostSignal>(), new[] { inc }));

        var key = (await _keys.GetOrCreateAsync()).PublicKey;
        var fs02 = AgentPolicyDocument.Verify(await _svc.IssuePolicyAsync("FS02", T0.AddSeconds(8)), key, "FS02", T0.AddSeconds(8), null);
        Assert.Equal(PolicyOutcome.Valid, fs02.Outcome);
        Assert.Equal("Alert", fs02.Policy!.Mode);                       // política própria preservada
        Assert.Contains("10.0.9.66", fs02.Policy.NetworkBlocklist);     // mas bloqueia o IP que FS01 conteve
        Assert.True(fs02.Policy.Version >= 2);                          // versão nunca regride (max das duas)

        var fs03 = AgentPolicyDocument.Verify(await _svc.IssuePolicyAsync("FS03", T0.AddSeconds(8)), key, "FS03", T0.AddSeconds(8), null);
        Assert.Contains("10.0.9.66", fs03.Policy!.NetworkBlocklist);
    }

    [Fact]
    public async Task Local_or_uncontained_or_allowlisted_sources_never_enter_the_blocklist()
    {
        await _svc.SaveAsync(new AgentPolicyEntity { Server = "*", AllowlistedIps = "10.0.1.9" }, T0);
        Assert.False(await _svc.AddToNetworkBlocklistAsync("local", T0));
        Assert.False(await _svc.AddToNetworkBlocklistAsync("10.0.1.9", T0));      // backup allowlisted
        Assert.False(await _svc.AddToNetworkBlocklistAsync("10.0.0.1; rm", T0));
        Assert.True(await _svc.AddToNetworkBlocklistAsync("10.0.9.66", T0));
        Assert.False(await _svc.AddToNetworkBlocklistAsync("10.0.9.66", T0.AddSeconds(1)));   // já está: sem versão nova
        await _svc.RemoveFromNetworkBlocklistAsync("10.0.9.66", T0.AddMinutes(1));
        var key = (await _keys.GetOrCreateAsync()).PublicKey;
        Assert.Empty(AgentPolicyDocument.Verify(await _svc.IssuePolicyAsync("X", T0.AddMinutes(2)), key, "X", T0.AddMinutes(2), null).Policy!.NetworkBlocklist);
    }
}
