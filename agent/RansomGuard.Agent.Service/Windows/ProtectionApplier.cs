using RansomGuard.Agent.Posture;
using RansomGuard.Core.Detection;
using System.Runtime.Versioning;
using RansomGuard.Agent.Protection;
using RansomGuard.Core.Fsrm;

namespace RansomGuard.Agent.Service.Windows;

/// <summary>
/// Prepara o terreno no servidor: planta os canários e aplica o file screen do FSRM nas pastas
/// configuradas. É o que dá **mãos** ao agente — até F11 ele só observava.
///
/// Duas decisões que valem mais que o código:
///
/// <b>O FSRM começa passivo.</b> Bloquear extensão em share de produção sem o admin pedir
/// transformaria o produto no incidente. Auditar já entrega o sinal; bloquear é opt-in.
///
/// <b>Sem FSRM, o produto não finge.</b> Em Windows client ou servidor sem a role, o file screen
/// não existe. O agente reporta <c>CanaryOnly</c> e o painel diz exatamente o que está e o que não
/// está ativo — calmaria sem visibilidade não é segurança.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProtectionApplier
{
    private readonly ILogger<ProtectionApplier> _log;
    private readonly CanaryPlanter _planter;
    private readonly CanaryManifest? _canaries;
    private readonly string _visibilityFile;
    private readonly RansomGuard.Agent.Sensors.VisibilityState _visibility;
    private readonly IReadOnlyList<string> _paths;
    private readonly bool _fsrmBlocking;
    private readonly Func<RansomwareCatalog> _activeCatalog;
    private readonly RansomGuard.Agent.Sensors.HostSignalBuffer? _signals;
    private readonly bool _autoRepair;
    private readonly string _server;
    private bool _plantedOnce;
    private readonly Func<IReadOnlyCollection<string>> _learned;
    private int _learnedApplied = -1;
    /// <summary>G7: o file screen precisa ser reaplicado quando o agente aprendeu extensão nova.</summary>
    public bool NeedsReapplyForLearned => _learned().Count != _learnedApplied;

    /// <summary>Estado atual, para o diagnóstico e para o lote enviado ao painel.</summary>
    public ProtectionStatusResult Status { get; private set; } =
        ProtectionStatus.Evaluate(0, 0, false, false);

    /// <param name="fsrmBlocking">true = file screen ativo (bloqueia). Padrão: auditoria.</param>
    /// <param name="activeCatalog">
    /// F18: fornece o catálogo ativo (do <c>CatalogCoordinator</c>) no momento de aplicar. Antes o
    /// applier instanciava a semente direto; agora recebe o último catálogo assinado bom — ou a
    /// semente, quando ainda não há um. Default (sem coordenador) usa a semente, preservando testes.
    /// </param>
    public ProtectionApplier(ILogger<ProtectionApplier> log, IReadOnlyList<string> paths,
        bool fsrmBlocking = false, Func<RansomwareCatalog>? activeCatalog = null,
        RansomGuard.Agent.Sensors.HostSignalBuffer? signals = null, bool autoRepairVisibility = true, string? server = null,
        Func<IReadOnlyCollection<string>>? learnedExtensions = null, CanaryManifest? canaries = null, string? dataDirectory = null)
    {
        _learned = learnedExtensions ?? (() => Array.Empty<string>());
        _log = log;
        // B4: com o manifesto, os canários têm os nomes e o conteúdo desta instalação; sem ele (testes), os antigos.
        _canaries = canaries;
        _visibilityFile = Path.Combine(dataDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RansomGuard"), "visibility-baseline.json");
        _visibility = new RansomGuard.Agent.Sensors.VisibilityState(File.Exists(_visibilityFile));
        _planter = new CanaryPlanter(new WindowsCanaryFileSystem(), canaries?.Set);
        _paths = paths;
        _fsrmBlocking = fsrmBlocking;
        _activeCatalog = activeCatalog ?? (() => SeedCatalog.AsCatalog);
        _signals = signals;
        _autoRepair = autoRepairVisibility;
        _server = server ?? Environment.MachineName;
    }

    /// <summary>
    /// G2 — visibilidade auto-reparável. Lê a auditoria 'Detailed File Share' e o tamanho do Security log; com
    /// auto-reparo ligado, religa a auditoria e amplia o log para 1 GB. Auditoria desligada vira sinal de Alta
    /// (cegueira nunca é silêncio); reparo bem-sucedido vira sinal informativo (fica na trilha do painel).
    /// Nunca lança.
    /// </summary>
    /// <summary>L2b: a auditoria de compartilhamento já foi vista ligada aqui — dali em diante, desligada é adulteração.</summary>
    private void RememberAuditSeenOn()
    {
        if (File.Exists(_visibilityFile)) return;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_visibilityFile)!);
            File.WriteAllText(_visibilityFile, System.Text.Json.JsonSerializer.Serialize(new { shareAuditSeenOnUtc = DateTime.UtcNow }));
        }
        catch (Exception ex) { _log.LogWarning(ex, "Não foi possível registrar que a auditoria foi vista ligada."); }
    }

    public void RepairVisibility()
    {
        try
        {
            // A política de auditoria é lida e ligada pelo GUID da subcategoria, direto no auditpol.exe: não depende
            // do idioma do Windows nem custa um PowerShell por consulta.
            var auditOn = WindowsAudit.IsSuccessEnabled(AuditSubcategory.DetailedFileShare);
            var fileSystemAudit = WindowsAudit.IsSuccessEnabled(AuditSubcategory.FileSystem);
            long? logMax = null;
            try { logMax = SecurityLogReader.TryReadMaxBytes(NativeTool.Run("wevtutil.exe", "gl Security")); } catch (Exception) { }
            bool? procAudit = null;
            try
            {
                var subcategory = WindowsAudit.IsSuccessEnabled(AuditSubcategory.ProcessCreation);
                var commandLine = Microsoft.Win32.Registry.GetValue(
                    @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", "ProcessCreationIncludeCmdLine_Enabled", null);
                procAudit = subcategory is null ? null : subcategory == true && commandLine is int v && v == 1;
            }
            catch (Exception) { }

            // L2b/L13: alarme só se a auditoria já foi vista ligada nesta máquina, e uma vez por transição.
            var alert = auditOn is bool on && _visibility.ShouldAlert(on);
            if (_visibility.SeenOn) RememberAuditSeenOn();
            var plan = RansomGuard.Agent.Sensors.VisibilityGuard.Evaluate(auditOn, logMax, _autoRepair, _server, DateTime.UtcNow, procAudit, fileSystemAudit,
                shareAuditSeenOnBefore: alert);
            foreach (var sig in plan.Signals) { _log.LogError("{Detail}", sig.Detail); _signals?.Push(sig); }
            foreach (var repair in plan.Repairs)
            {
                try
                {
                    switch (repair)
                    {
                        case RansomGuard.Agent.Sensors.RepairAction.EnableDetailedFileShareAudit:
                            WindowsAudit.EnableSuccess(AuditSubcategory.DetailedFileShare); break;
                        case RansomGuard.Agent.Sensors.RepairAction.EnableFileSystemAudit:
                            WindowsAudit.EnableSuccess(AuditSubcategory.FileSystem); break;
                        case RansomGuard.Agent.Sensors.RepairAction.GrowSecurityLog:
                            NativeTool.Run("wevtutil.exe", "sl Security /ms:1073741824"); break;
                        case RansomGuard.Agent.Sensors.RepairAction.EnableProcessCreationAudit:
                            WindowsAudit.EnableSuccess(AuditSubcategory.ProcessCreation);
                            PowerShellRunner.RunStrict(ProcessAuditReader.EnableCommandLineScript); break;
                        default: throw new InvalidOperationException(repair.ToString());
                    }
                    var done = RansomGuard.Agent.Sensors.VisibilityGuard.Repaired(repair, _server, DateTime.UtcNow);
                    _log.LogWarning("{Detail}", done.Detail);
                    _signals?.Push(done);
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "Reparo de visibilidade {Repair} falhou — o painel mostra o achado na postura.", repair);
                }
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Verificação de visibilidade falhou.");
        }
    }

    /// <summary>
    /// Aplica a preparação. Idempotente: pode rodar a cada ciclo do agente. Nunca lança — falha
    /// vira log e estado degradado, porque parar o agente é pior que proteger menos.
    /// </summary>
    public ProtectionStatusResult Apply()
    {
        if (_paths.Count == 0)
        {
            Status = ProtectionStatus.Evaluate(0, 0, FsrmAvailable(), false);
            return Status;
        }

        var resultados = _planter.Plant(_paths);
        // B4: as pastas ficam no manifesto — é ele que sabe onde desfazer, mesmo se a configuração mudar depois.
        _canaries?.RememberRoots(_paths);
        if (resultados.Sum(r => r.Collisions) is > 0 and var colisoes)
            _log.LogWarning("{N} nome(s) de canário já eram usados por arquivos que não são do produto; esses arquivos não foram tocados e não contam como canário.", colisoes);
        foreach (var r in resultados.Where(r => !r.Ok))
            _log.LogWarning("Não foi possível preparar {Path}: {Erro}", r.Path, r.Error);
        foreach (var r in resultados.Where(r => r.Ok && r.Planted > 0))
            _log.LogInformation("{N} canário(s) plantado(s) em {Path}", r.Planted, r.Path);
        // D4: canário sem regra de auditoria continua valendo para acesso pela rede, mas um processo LOCAL que o toque
        // não gera evento. O admin precisa saber (em geral: o serviço não está rodando como SYSTEM).
        if (resultados.Sum(r => r.Unaudited) is > 0 and var semAuditoria)
            _log.LogWarning("{N} canário(s) ficaram sem regra de auditoria: ataque a partir do próprio servidor não será visto por eles.", semAuditoria);

        // G2: depois do primeiro plantio completo, "plantou de novo" significa que alguém apagou um canário —
        // ninguém legítimo faz isso. Vira sinal de Alta com a pasta.
        if (_plantedOnce && _signals is not null)
            foreach (var r in resultados.Where(r => r.Ok && r.Planted > 0 && r.AlreadyPresent > 0))
                _signals.Push(new HostSignal(DateTime.UtcNow, HostSignalKind.CanaryMissing, _server,
                    $"{r.Planted} canário(s) sumiram de {r.Path} e foram replantados."));
        if (resultados.Any(r => r.Ok)) _plantedOnce = true;

        RepairVisibility();

        var canarios = CanaryPlanter.CountPlanted(resultados);
        var fsrmDisponivel = FsrmAvailable();
        var fsrmAplicado = fsrmDisponivel && TryApplyFsrm();

        Status = ProtectionStatus.Evaluate(
            protectedPaths: resultados.Count(r => r.Ok),
            canariesPlanted: canarios,
            fsrmAvailable: fsrmDisponivel,
            fsrmActive: fsrmAplicado && _fsrmBlocking);

        _log.LogInformation("Modo de proteção: {Modo}. {Explicacao}", Status.Mode, Status.Explanation);
        return Status;
    }

    /// <summary>Pastas cujo file screen é de outra origem e por isso não foi alterado (para o diagnóstico e o painel).</summary>
    public IReadOnlyList<string> ForeignScreens { get; private set; } = Array.Empty<string>();

    /// <summary>
    /// Reverte o que o produto escreveu no servidor — pedido do admin ou desinstalação: remove os canários e, havendo
    /// FSRM, os file screens e o file group criados pelo produto. File screens de outra origem não são tocados.
    /// </summary>
    public IReadOnlyList<CanaryResult> Revert()
    {
        // Inclui as pastas que já foram protegidas e saíram da configuração: sem isso sobrariam canários órfãos, e
        // com nomes que não se identificam ninguém saberia quais são.
        var everywhere = _paths.Concat(_canaries?.Roots ?? Array.Empty<string>()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var removed = _planter.Remove(everywhere);
        RemoveFsrm();
        return removed;
    }

    /// <summary>Remove os file screens e o file group do produto. Devolve false se o FSRM existe e a remoção falhou.</summary>
    public bool RemoveFsrm()
    {
        if (!FsrmAvailable()) return true;
        try
        {
            PowerShellRunner.RunScriptFile(FsrmPlan.BuildRemovalPowerShell(), TimeSpan.FromMinutes(2));
            _log.LogInformation("File screens e file group do RansomGuard removidos do FSRM.");
            return true;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Não foi possível remover os file screens do RansomGuard do FSRM.");
            return false;
        }
    }

    /// <summary>
    /// O FSRM existe neste servidor? Em Windows client ou servidor sem a role de File Server, os
    /// cmdlets simplesmente não existem — e isso não é erro, é o ambiente.
    /// </summary>
    private bool FsrmAvailable()
    {
        try
        {
            var saida = PowerShellRunner.Run(
                "[bool](Get-Command Get-FsrmFileGroup -ErrorAction SilentlyContinue)").Trim();
            return saida.Equals("True", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Não foi possível verificar a disponibilidade do FSRM");
            return false;
        }
    }

    private bool TryApplyFsrm()
    {
        try
        {
            // F18: usa o catálogo ativo do coordenador (último assinado bom, ou semente enquanto
            // não há um). O elo de distribuição do AUD-1 passa a chegar de verdade até o FSRM.
            var catalogo = _activeCatalog();
            // G7: extensões aprendidas em incidentes de Alta entram no file group local, além do catálogo assinado.
            var learned = _learned();
            if (learned.Count > 0)
                catalogo = new RansomwareCatalog { Version = catalogo.Version, Patterns = catalogo.Patterns.Concat(learned.Select(e => "*" + e)).Distinct(StringComparer.OrdinalIgnoreCase).ToList(), NotePatterns = catalogo.NotePatterns, Tuning = catalogo.Tuning };
            _learnedApplied = learned.Count;
            var script = FsrmPlan.BuildPowerShell(catalogo, _paths, active: _fsrmBlocking);
            // L1: por arquivo, nunca pela linha de comando (o antivírus do Windows barra a lista de extensões em -Command).
            var output = PowerShellRunner.RunScriptFile(script, TimeSpan.FromMinutes(2));

            // Pasta que já tinha file screen de outra origem: não foi alterada. O admin precisa saber que ali o FSRM não
            // está com a lista do produto.
            ForeignScreens = FsrmPlan.ForeignScreens(output);
            foreach (var path in ForeignScreens)
                _log.LogWarning("A pasta {Path} já tem um file screen que não é do RansomGuard; ele não foi alterado.", path);

            _log.LogInformation("FSRM aplicado em modo {Modo} sobre {N} pasta(s)",
                _fsrmBlocking ? "BLOQUEIO" : "auditoria", _paths.Count);
            return true;
        }
        catch (Exception ex)
        {
            // Falhar aqui degrada para canário — nunca derruba o agente nem mente sobre o estado.
            _log.LogWarning(ex, "FSRM não pôde ser aplicado; seguindo apenas com canários");
            return false;
        }
    }
}
