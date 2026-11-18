using System.Runtime.Versioning;
using Microsoft.Extensions.Logging.Abstractions;
using RansomGuard.Agent.Protection;
using RansomGuard.Agent.Sensors;
using RansomGuard.Agent.Service.Windows;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Fsrm;
using RansomGuard.Core.Response;
using RansomGuard.Core.Security;
using Xunit.Abstractions;

namespace RansomGuard.Agent.Service.Tests;

/// <summary>O modo estrito do executor: erro vira exceção com a mensagem limpa; sucesso devolve a saída.</summary>
[SupportedOSPlatform("windows")]
public sealed class StrictRunnerTests
{
    [Fact]
    public void Script_que_da_certo_devolve_a_saida()
        => Assert.Equal("ok", PowerShellRunner.RunStrict("'ok'").Trim());

    [Fact]
    public void Erro_que_o_powershell_trataria_como_aviso_interrompe_e_vira_excecao()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            PowerShellRunner.RunStrict("Get-Item 'C:\\rg-nao-existe-" + Guid.NewGuid().ToString("N") + "'; 'depois do erro'"));

        Assert.DoesNotContain("depois do erro", ex.Message);
        Assert.DoesNotContain("CategoryInfo", ex.Message);       // sem o rodapé de posição do PowerShell
        Assert.False(string.IsNullOrWhiteSpace(ex.Message));
    }

    /// <summary>L1 — script longo roda de um arquivo: acentos preservados, erro vira exceção, e o arquivo some depois.</summary>
    [Fact]
    public void Script_em_arquivo_roda_preserva_acentos_e_nao_deixa_o_arquivo_para_tras()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rg-run-" + Guid.NewGuid().ToString("N")[..8]);
        try
        {
            var output = PowerShellRunner.RunScriptFile("$x = 'canário e extensão'; Write-Output $x.Length", directory: dir);

            Assert.Equal("18", output.Trim());   // lido como ANSI, cada letra acentuada viraria duas
            Assert.Empty(Directory.GetFiles(dir));
            Assert.Throws<InvalidOperationException>(() => PowerShellRunner.RunScriptFile("$ErrorActionPreference = 'Stop'; Get-Item 'C:\\rg-nao-existe-" + Guid.NewGuid().ToString("N") + "'", directory: dir));
            Assert.Empty(Directory.GetFiles(dir));
        }
        finally { try { Directory.Delete(dir, true); } catch (Exception) { } }
    }

    [Fact]
    public void Throw_do_script_chega_como_a_propria_mensagem()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => PowerShellRunner.RunStrict("throw 'a regra de bloqueio nao ficou ativa'"));

        Assert.Equal("a regra de bloqueio nao ficou ativa", ex.Message);
    }
}

/// <summary>
/// A2 — a contenção agindo num Windows de verdade, com o executor de produção: o efeito é conferido no próprio
/// sistema (regra de firewall, entrada de negação no share, sessões SMB), não no retorno do comando.
/// </summary>
[Collection("windows-real")]
[SupportedOSPlatform("windows")]
public sealed class ContainmentRealTests(ITestOutputHelper output)
{
    private readonly WindowsResponseExecutor _executor = new(NullLogger<WindowsResponseExecutor>.Instance);

    private static int RuleCount(string ip) => int.Parse(PowerShellRunner.Run(
        $"@(Get-NetFirewallRule -DisplayName '{ContainmentScripts.FirewallRulePrefix}{ip}' -ErrorAction SilentlyContinue).Count").Trim());

    [ElevatedFact]
    public async Task Bloquear_ip_cria_uma_unica_regra_ativa_e_liberar_a_remove()
    {
        const string ip = "203.0.113.77";                       // TEST-NET-3: não existe na rede
        var action = new ResponseAction(ResponseStep.BlockIp, "FS01", ip, "teste de integração");
        try
        {
            var firewallOff = PowerShellRunner.Run(
                "$c = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { if ($_.NetworkCategory -eq 'DomainAuthenticated') { 'Domain' } else { [string]$_.NetworkCategory } }); " +
                "@(Get-NetFirewallProfile | Where-Object { $c -contains $_.Name -and $_.Enabled -ne 'True' }).Count").Trim() != "0";
            output.WriteLine($"firewall desligado no perfil ativo: {firewallOff}");

            var first = await _executor.ExecuteAsync(action);
            output.WriteLine($"{first.Status}: {first.Detail}");

            if (firewallOff)
            {
                // Regra criada, mas sem efeito: o produto NÃO pode dizer "executada".
                Assert.Equal(ResponseStatus.Failed, first.Status);
                Assert.Contains("firewall", first.Detail);
                return;
            }

            Assert.Equal(ResponseStatus.Executed, first.Status);
            Assert.Equal(1, RuleCount(ip));

            Assert.Equal(ResponseStatus.Executed, (await _executor.ExecuteAsync(action)).Status);   // repetir não empilha
            Assert.Equal(1, RuleCount(ip));

            Assert.Equal(ResponseStatus.Executed, (await _executor.RevertAsync(action)).Status);
            Assert.Equal(0, RuleCount(ip));
            Assert.Equal(ResponseStatus.Executed, (await _executor.RevertAsync(action)).Status);    // liberar de novo: nada a fazer, sem erro
        }
        finally
        {
            try { PowerShellRunner.Run($"Get-NetFirewallRule -DisplayName '{ContainmentScripts.FirewallRulePrefix}{ip}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"); } catch (Exception) { }
        }
    }

    [ElevatedFact]
    public async Task Negar_usuario_no_share_aparece_na_permissao_do_share_e_e_revertido()
    {
        using var share = TempShare.Create();
        var user = "rgit" + Guid.NewGuid().ToString("N")[..8];
        PowerShellRunner.RunStrict($"New-LocalUser -Name '{user}' -NoPassword | Out-Null");
        try
        {
            var account = $@"{Environment.MachineName}\{user}";
            var action = new ResponseAction(ResponseStep.DenyUserOnShare, "FS01", $@"\\{Environment.MachineName}\{share.Name}", "teste", Account: account);
            string Access() => PowerShellRunner.Run($"Get-SmbShareAccess -Name '{share.Name}' | ForEach-Object {{ '{{0}}|{{1}}' -f $_.AccountName, $_.AccessControlType }}");

            var deny = await _executor.ExecuteAsync(action);
            output.WriteLine($"{deny.Status}: {deny.Detail}\n{Access()}");
            Assert.Equal(ResponseStatus.Executed, deny.Status);
            Assert.Contains($"{user}|Deny", Access(), StringComparison.OrdinalIgnoreCase);

            var allow = await _executor.RevertAsync(action);
            Assert.Equal(ResponseStatus.Executed, allow.Status);
            Assert.DoesNotContain($"{user}|Deny", Access(), StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { PowerShellRunner.Run($"Remove-LocalUser -Name '{user}' -ErrorAction SilentlyContinue"); } catch (Exception) { }
        }
    }

    [ElevatedFact]
    public async Task Negar_em_share_que_nao_existe_e_falha_e_nao_execucao()
    {
        var action = new ResponseAction(ResponseStep.DenyUserOnShare, "FS01", @"\\FS01\rgit-nao-existe", "teste",
            Account: $@"{Environment.MachineName}\{Environment.UserName}");

        var outcome = await _executor.ExecuteAsync(action);

        output.WriteLine($"{outcome.Status}: {outcome.Detail}");
        Assert.Equal(ResponseStatus.Failed, outcome.Status);
    }

    [ElevatedFact]
    public async Task Sessao_smb_e_lida_em_formato_proprio_e_encerrada_pelo_cliente_exato()
    {
        using var share = TempShare.Create();
        _ = Directory.GetFileSystemEntries(share.Unc);          // abre uma sessão SMB contra o próprio servidor

        var raw = PowerShellRunner.Run(SessionCorrelator.SessionLinesCommand);
        output.WriteLine(raw);
        var sessions = WindowsFileEventCollector.DefaultReadSessions();
        Assert.Contains(sessions, s => s.User.EndsWith("\\" + Environment.UserName, StringComparison.OrdinalIgnoreCase));

        // O cliente desta sessão, como o Windows o mostra, já sem os enfeites.
        var client = raw.Split('\n').Select(l => l.Trim()).Where(l => l.Contains('|'))
            .Where(l => l.Split('|')[1].EndsWith("\\" + Environment.UserName, StringComparison.OrdinalIgnoreCase))
            .Select(l => SessionCorrelator.NormalizeClient(l.Split('|')[0])).First();
        output.WriteLine($"cliente: {client}");

        var outcome = await _executor.ExecuteAsync(new ResponseAction(ResponseStep.KillSmbSession, "FS01", client, "teste"));

        output.WriteLine($"{outcome.Status}: {outcome.Detail}");
        Assert.Equal(ResponseStatus.Executed, outcome.Status);
    }
}

/// <summary>
/// D4 — canário com regra de auditoria: um processo DESTE servidor mexe no canário e o agente fica sabendo, com o
/// processo identificado. É o caminho que leva ao degrau que encerra processo.
/// </summary>
[Collection("windows-real")]
[SupportedOSPlatform("windows")]
public sealed class CanaryAuditRealTests(ITestOutputHelper output)
{
    [ElevatedFact]
    public void Processo_local_que_toca_o_canario_e_visto_com_o_proprio_pid_e_vira_alta_confianca()
    {
        using var audit = AuditScope.Enable(AuditScope.FileSystem);
        using var share = TempShare.Create();
        Directory.CreateDirectory(Path.Combine(share.LocalPath, "2024"));
        var planter = new CanaryPlanter(new WindowsCanaryFileSystem());

        var planted = planter.Plant(new[] { share.LocalPath });
        Assert.All(planted, r => Assert.True(r.Ok, r.Error));
        Assert.Equal(0, planted.Sum(r => r.Unaudited));         // todos com regra de auditoria
        Assert.Equal(2, planted.Count);                         // raiz e a subpasta

        var cursor = new MemoryCursorStore();
        var collector = new WindowsFileEventCollector(NullLogger<WindowsFileEventCollector>.Instance, new EventCursor(cursor),
            shares: new WindowsShareTable(Environment.MachineName, TimeSpan.Zero).Current, readSessions: () => Array.Empty<SmbSession>());
        Assert.Empty(collector.Drain());

        var canary = Path.Combine(share.LocalPath, "2024", CanaryPlan.NamesFor(share.LocalPath)[0]);
        using (var stream = new FileStream(canary, FileMode.Open, FileAccess.Write)) stream.WriteByte(0x21);   // processo local grava no canário

        var events = new List<FileEvent>();
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < deadline && !events.Any(e => e.IsCanary))
        {
            events.AddRange(collector.Drain());
            Thread.Sleep(500);
        }
        foreach (var e in events.Where(e => e.IsCanary))
            output.WriteLine($"{e.Op} share={e.Share} path={e.Path} pid={e.ProcessId} image={e.ProcessName}");

        var hit = events.First(e => e.IsCanary);
        Assert.Equal(Environment.ProcessId, hit.ProcessId);
        Assert.Equal(SecurityEventParser.LocalOrigin, hit.SourceIp);

        var detection = Assert.Single(new DetectionEngine().Analyze(events), d => d.Reasons.Contains(DetectionReason.CanaryTouched));
        Assert.Equal(Confidence.High, detection.Confidence);
        var decision = new ResponseLadder().Decide(detection, new ResponsePolicy { Mode = ResponseMode.Block });
        Assert.Contains(decision.Actions, a => a.Step == ResponseStep.StopProcess && a.Target == Environment.ProcessId.ToString());

        // Reverter leva embora os canários da raiz e da subpasta.
        planter.Remove(new[] { share.LocalPath });
        Assert.Empty(Directory.GetFiles(share.LocalPath, "*", SearchOption.AllDirectories).Where(f => CanaryPlan.IsCanary(f)));
    }
}

/// <summary>D9 — a pasta de dados deixa de herdar a permissão de ProgramData.</summary>
[Collection("windows-real")]
[SupportedOSPlatform("windows")]
public sealed class SecureDirectoryRealTests(ITestOutputHelper output)
{
    [ElevatedFact]
    public void Pasta_sob_ProgramData_nasce_aberta_a_usuarios_e_fica_restrita_depois()
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "rg-it-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "agent-cursor.txt"), "42");
            var before = SecureDirectory.BroadAccess(dir);
            output.WriteLine("antes: " + string.Join(", ", before));
            Assert.NotEmpty(before);                              // a premissa do achado: usuários comuns alcançam a pasta

            SecureDirectory.Ensure(dir);

            Assert.Empty(SecureDirectory.BroadAccess(dir));
            Assert.True(SecureDirectory.IsRestricted(dir));
            Assert.Equal("42", File.ReadAllText(Path.Combine(dir, "agent-cursor.txt")));   // o serviço continua lendo o que é dele

            SecureDirectory.Ensure(dir);                          // idempotente
            Assert.True(SecureDirectory.IsRestricted(dir));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch (Exception) { }
        }
    }
}

/// <summary>
/// A política de auditoria lida pela API do sistema, e não por texto do <c>auditpol</c>. O teste também registra a
/// saída bruta do relatório <c>/r</c> na máquina real: é a evidência de por que a leitura por texto não serviu.
/// </summary>
[Collection("windows-real")]
[SupportedOSPlatform("windows")]
public sealed class AuditPolicyRealTests(ITestOutputHelper output)
{
    [ElevatedFact]
    public void Subcategoria_e_lida_pelo_guid_e_reflete_o_que_foi_ligado()
    {
        foreach (var sub in new[] { RansomGuard.Agent.Posture.AuditSubcategory.DetailedFileShare, RansomGuard.Agent.Posture.AuditSubcategory.FileSystem, RansomGuard.Agent.Posture.AuditSubcategory.ProcessCreation })
        {
            var bits = WindowsAudit.Query(sub, out var error);
            output.WriteLine($"{sub.English}: bits={bits?.ToString() ?? "null"} erro={error}");
            Assert.NotNull(bits);
        }

        // Evidência, não asserção: o que o relatório em texto devolve neste Windows.
        try { output.WriteLine("auditpol /r:\n" + NativeTool.Run("auditpol.exe", $"/get /subcategory:{AuditScope.FileSystem.Guid} /r")); }
        catch (Exception ex) { output.WriteLine("auditpol /r falhou: " + ex.Message); }

        using var audit = AuditScope.Enable(AuditScope.FileSystem);
        Assert.True(WindowsAudit.IsSuccessEnabled(AuditScope.FileSystem));
    }
}

/// <summary>
/// D7 / A2 — o snapshot preventivo num Windows de verdade: cria uma cópia de sombra do volume do share, e o teto de
/// frequência recusa a segunda logo em seguida. A cópia criada pelo teste é removida ao final.
/// </summary>
[Collection("windows-real")]
[SupportedOSPlatform("windows")]
public sealed class PreemptiveSnapshotRealTests(ITestOutputHelper output)
{
    private static HashSet<string> ShadowIds() => PowerShellRunner.Run("Get-CimInstance Win32_ShadowCopy | ForEach-Object { $_.ID }")
        .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet(StringComparer.OrdinalIgnoreCase);

    [ElevatedFact]
    public async Task Snapshot_preventivo_cria_uma_copia_de_sombra_e_o_segundo_pedido_em_seguida_e_recusado()
    {
        using var share = TempShare.Create();
        var executor = new WindowsResponseExecutor(NullLogger<WindowsResponseExecutor>.Instance);
        var action = new ResponseAction(ResponseStep.PreemptiveSnapshot, "FS01", $@"\\{Environment.MachineName}\{share.Name}", "teste de integração");
        var before = ShadowIds();
        var created = new HashSet<string>();
        try
        {
            var first = await executor.ExecuteAsync(action);
            output.WriteLine($"{first.Status}: {first.Detail}");
            created = ShadowIds();
            created.ExceptWith(before);
            output.WriteLine($"cópias novas: {created.Count}");

            Assert.Equal(ResponseStatus.Executed, first.Status);
            Assert.Single(created);

            var second = await executor.ExecuteAsync(action);
            Assert.Equal(ResponseStatus.Skipped, second.Status);
            Assert.Contains("janela", second.Detail);
        }
        finally
        {
            foreach (var id in created)
                try { PowerShellRunner.Run($"Get-CimInstance Win32_ShadowCopy | Where-Object {{ $_.ID -eq '{id}' }} | Remove-CimInstance"); } catch (Exception) { }
        }
    }
}
