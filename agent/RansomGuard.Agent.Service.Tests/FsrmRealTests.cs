using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using RansomGuard.Agent.Service.Windows;
using RansomGuard.Core.Fsrm;
using Xunit.Abstractions;

namespace RansomGuard.Agent.Service.Tests;

/// <summary>
/// Teste que mexe no FSRM de verdade: cria e remove file group e file screens na máquina. Só roda quando pedido
/// explicitamente (<c>RG_FSRM_TESTS=1</c>, definido na CI depois de instalar o FSRM no runner) — nunca por acaso num
/// servidor que já usa o produto.
/// </summary>
public sealed class FsrmFactAttribute : FactAttribute
{
    public FsrmFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("RG_FSRM_TESTS") != "1")
            Skip = "Altera o FSRM da máquina; roda na CI com RG_FSRM_TESTS=1 (FSRM instalado no runner).";
    }
}

/// <summary>
/// E3/D3 — o file screen do produto num FSRM real: gera evento a cada violação (inclusive renomeação, com o nome de
/// destino), não altera file screen de outra origem e é removido por inteiro na reversão.
/// </summary>
[Collection("windows-real")]
[SupportedOSPlatform("windows")]
public sealed class FsrmRealTests(ITestOutputHelper output) : IDisposable
{
    private const string TestExtension = ".rglocked";
    private const string ForeignGroup = "rgit-grupo-do-cliente";

    private static readonly RansomwareCatalog Catalog = new() { Version = 1, Patterns = new[] { "*" + TestExtension } };
    private readonly List<TempShare> _shares = new();

    public void Dispose()
    {
        foreach (var share in _shares)
        {
            try { PowerShellRunner.Run($"Remove-FsrmFileScreen -Path '{share.LocalPath}' -Confirm:$false -ErrorAction SilentlyContinue"); } catch (Exception) { }
            share.Dispose();
        }
        try { PowerShellRunner.RunScriptFile(FsrmPlan.BuildRemovalPowerShell(), TimeSpan.FromMinutes(2), Path.GetTempPath()); } catch (Exception) { }
        try { PowerShellRunner.Run($"Remove-FsrmFileGroup -Name '{ForeignGroup}' -Confirm:$false -ErrorAction SilentlyContinue"); } catch (Exception) { }
    }

    private TempShare NewShare() { var s = TempShare.Create(); _shares.Add(s); return s; }

    private static ProtectionApplier Applier(string path) =>
        new(NullLogger<ProtectionApplier>.Instance, new[] { path }, fsrmBlocking: false,
            activeCatalog: () => Catalog, autoRepairVisibility: false);

    private static long NewestApplicationRecord()
    {
        using var reader = new EventLogReader(new EventLogQuery("Application", PathType.LogName) { ReverseDirection = true });
        using var rec = reader.ReadEvent();
        return rec?.RecordId ?? 0;
    }

    /// <summary>Eventos do FSRM (provedor SRMSVC) depois de um ponto do log de Aplicativo.</summary>
    private static List<(long Id, int EventId, string Xml)> FsrmEventsAfter(long recordId)
    {
        var list = new List<(long, int, string)>();
        var query = $"*[System[Provider[@Name='SRMSVC'] and (EventRecordID > {recordId})]]";
        using var reader = new EventLogReader(new EventLogQuery("Application", PathType.LogName, query));
        while (reader.ReadEvent() is { } rec)
            using (rec) list.Add((rec.RecordId ?? 0, rec.Id, rec.ToXml()));
        return list;
    }

    private static string Screen(string path) => PowerShellRunner.Run(
        $"Get-FsrmFileScreen -Path '{path}' -ErrorAction SilentlyContinue | Format-List Path,Active,IncludeGroup,Description | Out-String");

    [FsrmFact]
    public void File_screen_em_auditoria_registra_cada_violacao_com_usuario_e_nome_de_destino()
    {
        Assert.True(Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SrmSvc") is not null, "FSRM não está instalado");
        var share = NewShare();
        var applier = Applier(share.LocalPath);

        // O script de produção, direto: se o FSRM recusar algum parâmetro, o erro dele aparece aqui (o aplicador o engole
        // de propósito, para o agente degradar para canários em vez de parar).
        // Pelo mesmo caminho da produção: script em arquivo (L1).
        PowerShellRunner.RunScriptFile(FsrmPlan.BuildPowerShell(Catalog, new[] { share.LocalPath }, active: false), TimeSpan.FromMinutes(2), Path.GetTempPath());
        applier.Apply();
        var screen = Screen(share.LocalPath);
        output.WriteLine(screen);
        Assert.Contains(FsrmPlan.FileGroupName, screen);
        Assert.Contains(FsrmPlan.ScreenDescription, screen);
        Assert.Empty(applier.ForeignScreens);

        var baseline = NewestApplicationRecord();

        // Quatro violações, de quatro jeitos: criar local, criar pela rede, renomear local, renomear pela rede.
        File.WriteAllText(Path.Combine(share.LocalPath, "criado-local.xlsx" + TestExtension), "teste");
        Thread.Sleep(1500);
        File.WriteAllText(Path.Combine(share.Unc, "criado-rede.docx" + TestExtension), "teste");
        Thread.Sleep(1500);
        File.WriteAllText(Path.Combine(share.LocalPath, "renomeado-local.pdf"), "teste");
        File.Move(Path.Combine(share.LocalPath, "renomeado-local.pdf"), Path.Combine(share.LocalPath, "renomeado-local.pdf" + TestExtension));
        Thread.Sleep(1500);
        File.WriteAllText(Path.Combine(share.Unc, "renomeado-rede.dwg"), "teste");
        File.Move(Path.Combine(share.Unc, "renomeado-rede.dwg"), Path.Combine(share.Unc, "renomeado-rede.dwg" + TestExtension));

        // Em auditoria nada é bloqueado: os quatro arquivos existem.
        Assert.Equal(4, Directory.GetFiles(share.LocalPath, "*" + TestExtension).Length);

        var events = new List<(long Id, int EventId, string Xml)>();
        var deadline = DateTime.UtcNow.AddSeconds(45);
        while (DateTime.UtcNow < deadline)
        {
            events = FsrmEventsAfter(baseline);
            if (events.Count(e => e.Xml.Contains(FsrmPlan.EventMarker)) >= 4) break;
            Thread.Sleep(1000);
        }

        var ours = events.Where(e => e.Xml.Contains(FsrmPlan.EventMarker)).ToList();
        output.WriteLine($"eventos do FSRM depois da linha de base: {events.Count}; com a marca do produto: {ours.Count}");
        foreach (var e in events.Take(8)) output.WriteLine($"--- id={e.EventId} record={e.Id}\n{e.Xml}");

        var dir = Environment.GetEnvironmentVariable("RG_FIXTURE_DIR");
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
            var n = 0;
            foreach (var e in events.Take(12)) File.WriteAllText(Path.Combine(dir, $"fsrm-{++n:000}-{e.EventId}-{e.Id}.xml"), e.Xml);
        }

        Assert.NotEmpty(ours);                                                       // o file screen passou a avisar
        Assert.Contains(ours, e => e.Xml.Contains(TestExtension, StringComparison.OrdinalIgnoreCase));
        Assert.Contains(ours, e => e.Xml.Contains(Environment.UserName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// O cenário que o evento de share sozinho não enxerga: arquivos comuns renomeados, pela rede, para uma extensão
    /// do catálogo. Coletor de produção + FSRM real + motor de detecção → incidente de Alta com o usuário certo.
    /// </summary>
    [FsrmFact]
    public void Renomear_pela_rede_para_extensao_do_catalogo_vira_incidente_de_alta_confianca()
    {
        using var audit = AuditScope.Enable(AuditScope.DetailedFileShare);
        var share = NewShare();
        Applier(share.LocalPath).Apply();
        var canonical = $@"\\{Environment.MachineName}\{share.Name}";

        for (var i = 0; i < 6; i++)
            File.WriteAllText(Path.Combine(share.LocalPath, $"contrato{i}.docx"), "conteúdo original");   // antes da linha de base

        var cursor = new MemoryCursorStore(); var fsrmCursor = new MemoryCursorStore();
        var collector = new WindowsFileEventCollector(
            NullLogger<WindowsFileEventCollector>.Instance, new RansomGuard.Agent.Sensors.EventCursor(cursor),
            shares: new WindowsShareTable(Environment.MachineName, TimeSpan.Zero).Current,
            readSessions: () => Array.Empty<RansomGuard.Agent.Sensors.SmbSession>(),
            fsrmCursor: new RansomGuard.Agent.Sensors.EventCursor(fsrmCursor));
        Assert.Empty(collector.Drain());                                   // os dois logs partem de agora

        for (var i = 0; i < 6; i++)
            File.Move(Path.Combine(share.Unc, $"contrato{i}.docx"), Path.Combine(share.Unc, $"contrato{i}.docx" + TestExtension));

        var events = new List<RansomGuard.Core.Detection.FileEvent>();
        var deadline = DateTime.UtcNow.AddSeconds(45);
        while (DateTime.UtcNow < deadline)
        {
            events.AddRange(collector.Drain());
            Assert.Equal(0, collector.ConsecutiveFailures);
            if (events.Where(e => e.Path.EndsWith(TestExtension, StringComparison.OrdinalIgnoreCase)).Select(e => e.Path).Distinct().Count() >= 6) break;
            Thread.Sleep(1000);
        }
        var ours = events.Where(e => e.Share.Equals(canonical, StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var e in ours.OrderBy(e => e.At))
            output.WriteLine($"{e.Op,-6} path={e.Path} ext={e.NewExtension} user={e.User} ip={e.SourceIp} pid={e.ProcessId}");

        var renamed = ours.Where(e => e.Path.EndsWith(TestExtension, StringComparison.OrdinalIgnoreCase)).ToList();
        Assert.Equal(6, renamed.Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(renamed, e =>
        {
            Assert.Equal(TestExtension, e.NewExtension);
            Assert.EndsWith("\\" + Environment.UserName, e.User, StringComparison.OrdinalIgnoreCase);
            Assert.Null(e.ProcessId);                                      // veio pela rede: sem processo local
        });

        var options = new RansomGuard.Core.Detection.DetectionOptions
        {
            KnownExtensionsProvider = () => new HashSet<string>(StringComparer.OrdinalIgnoreCase) { TestExtension }
        };

        // Só com o que o evento de share entrega (nomes antigos), a extensão do catálogo não aparece...
        var semFileScreen = new RansomGuard.Core.Detection.DetectionEngine(options).Analyze(ours.Except(renamed).ToList());
        Assert.DoesNotContain(semFileScreen, d => d.Reasons.Contains(RansomGuard.Core.Detection.DetectionReason.KnownRansomExtension));

        // ...com o file screen, o mesmo ataque é incidente de Alta.
        var detection = Assert.Single(new RansomGuard.Core.Detection.DetectionEngine(options).Analyze(ours),
            d => d.Reasons.Contains(RansomGuard.Core.Detection.DetectionReason.KnownRansomExtension));
        Assert.Equal(RansomGuard.Core.Detection.Confidence.High, detection.Confidence);
        Assert.EndsWith("\\" + Environment.UserName, detection.User, StringComparison.OrdinalIgnoreCase);
    }

    [FsrmFact]
    public void File_screen_de_outra_origem_nao_e_alterado_e_a_reversao_remove_so_o_do_produto()
    {
        var nosso = NewShare();
        var doCliente = NewShare();
        PowerShellRunner.Run(
            $"New-FsrmFileGroup -Name '{ForeignGroup}' -IncludePattern @('*.mp3') | Out-Null; " +
            $"New-FsrmFileScreen -Path '{doCliente.LocalPath}' -IncludeGroup '{ForeignGroup}' -Active:$true -Description 'do cliente' | Out-Null");

        Applier(nosso.LocalPath).Apply();
        var sobreODoCliente = Applier(doCliente.LocalPath);
        sobreODoCliente.Apply();

        // O screen do cliente continua com o grupo e o modo dele; o produto só relata.
        var cliente = Screen(doCliente.LocalPath);
        output.WriteLine(cliente);
        Assert.Contains(ForeignGroup, cliente);
        Assert.DoesNotContain(FsrmPlan.FileGroupName, cliente);
        Assert.Contains("do cliente", cliente);
        Assert.Contains(sobreODoCliente.ForeignScreens, p => p.Equals(doCliente.LocalPath, StringComparison.OrdinalIgnoreCase));

        // Reversão: some o que é do produto (screen e grupo); o do cliente fica.
        Assert.True(Applier(nosso.LocalPath).RemoveFsrm());
        Assert.DoesNotContain(FsrmPlan.FileGroupName, Screen(nosso.LocalPath));
        Assert.Contains(ForeignGroup, Screen(doCliente.LocalPath));
        var grupo = PowerShellRunner.Run($"[bool](Get-FsrmFileGroup -Name '{FsrmPlan.FileGroupName}' -ErrorAction SilentlyContinue)").Trim();
        Assert.Equal("False", grupo);

        // E aplicar de novo recria tudo (idempotência depois de reverter).
        Applier(nosso.LocalPath).Apply();
        Assert.Contains(FsrmPlan.FileGroupName, Screen(nosso.LocalPath));
    }
}
