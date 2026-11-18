using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;
using RansomGuard.Core.Simulation;

// FalsePositiveSimulator — o portão de regressão MAIS importante da Fatia 4. Prova o risco nº 1 do
// produto: em modo BLOQUEIO, o tráfego legítimo da rede (backup, robocopy, usuários) NÃO pode gerar
// nenhuma contenção — desabilitar a conta do backup às 2h mataria a confiança no produto. E, no
// MESMO fluxo, um ataque real DEVE ser contido. exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;

var failures = new List<string>();
void Check(string name, bool ok, string detail)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}");
    if (!ok) failures.Add(name);
}

// Configuração realista: modo BLOQUEIO ligado, com as contas de serviço na allowlist (como o
// produto recomenda). Motor de detecção e escada de resposta reais.
var detectionOpts = new DetectionOptions
{
    MassThreshold = 40,
    AllowlistedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"CORP\svc-backup", @"CORP\svc-migra" },
    AllowlistedIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "10.0.1.9", "10.0.1.15" }
};
var engine = new DetectionEngine(detectionOpts);
var ladder = new ResponseLadder();
var policy = new ResponsePolicy
{
    Mode = ResponseMode.Block,
    MaxStep = ResponseStep.DisableAdAccount,
    AllowlistedUsers = detectionOpts.AllowlistedUsers,
    AllowlistedIps = detectionOpts.AllowlistedIps
};

// G4a: contenção = degraus que agem contra alguém (IP, sessão, usuário, conta, share). O snapshot VSS
// preventivo não conta — protege o restore e não afeta ninguém (por isso também vale para Medium).
int Contentions(ScenarioData scenario)
{
    var count = 0;
    foreach (var d in engine.Analyze(scenario.Events, scenario.HostSignals))
        count += ladder.Decide(d, policy).Actions.Count(a => a.Step != ResponseStep.PreemptiveSnapshot);
    return count;
}
int Snapshots(ScenarioData scenario)
{
    var count = 0;
    foreach (var d in engine.Analyze(scenario.Events, scenario.HostSignals))
        count += ladder.Decide(d, policy).Actions.Count(a => a.Step == ResponseStep.PreemptiveSnapshot);
    return count;
}

Console.WriteLine("RansomGuard · FalsePositiveSimulator");
Console.WriteLine(new string('─', 60));

// 1. Tráfego 100% legítimo em modo BLOQUEIO → ZERO contenções.
Console.WriteLine("\nCenário 1 · Tráfego legítimo em modo BLOQUEIO");
var normal = NetworkScenario.NormalTraffic();
var normalContentions = Contentions(normal);
Console.WriteLine($"  {normal.Events.Count} eventos legítimos (backup+robocopy+usuários)");
Check("legitimo-zero-contencao", normalContentions == 0,
    $"{normalContentions} contenções (esperado 0 — backup não é derrubado)");

// 2. Backup em massa (5000 escritas) sozinho → ZERO contenções (allowlist + guard-rail).
Console.WriteLine("\nCenário 2 · Backup noturno pesado, isolado");
var backupOnly = new ScenarioData(
    Enumerable.Range(0, 5000).Select(i =>
        new FileEvent(new DateTime(2026, 7, 23, 2, 0, 0, DateTimeKind.Utc).AddMilliseconds(i),
            @"CORP\svc-backup", "10.0.1.9", @"\\FS01\Financeiro", FileOp.Write, $"bkp{i}.dat")).ToList(),
    Array.Empty<HostSignal>());
Check("backup-pesado-ileso", Contentions(backupOnly) == 0, "5000 escritas do backup → 0 contenções");

// 3. Ataque real (remoto via SMB + deleção de VSS, alta confiança) → É contido.
// Nota de design: só volume/extensão = Medium (só alerta, evita falso positivo); ataque que toca
// canário OU apaga VSS = High = contido. Ransomware apaga VSS quase sempre — este é o caso real.
Console.WriteLine("\nCenário 3 · Ataque real embutido no ambiente (remoto + VSS deletado)");
var baseAttack = NetworkScenario.RemoteSmbRansomware();
var t = new DateTime(2026, 7, 23, 2, 0, 0, DateTimeKind.Utc);
var attack = baseAttack with
{
    HostSignals = new[] { new HostSignal(t.AddSeconds(2), HostSignalKind.VssDeleted, "FS01") }
};
var attackContentions = Contentions(attack);
Check("ataque-contido", attackContentions > 0, $"{attackContentions} contenções (ataque remoto High detido)");

// 3b. Ataque só-volume (sem canário/VSS) → Medium → alerta, sem contenção automática (por design).
Console.WriteLine("\nCenário 3b · Ataque só-volume (Medium) → alerta, não contém");
var volumeOnly = NetworkScenario.RemoteSmbRansomware();
Check("volume-snapshot-preventivo", Snapshots(volumeOnly) > 0, "Medium em Block: snapshot VSS preventivo (não é contenção)");
Check("volume-so-alerta", Contentions(volumeOnly) == 0,
    "Medium não contém automaticamente (canário/VSS elevam para contenção)");

// 4. Ataque que toca canário mesmo vindo de IP allowlisted → contido (canário fura a allowlist).
Console.WriteLine("\nCenário 4 · Canário tocado por origem 'confiável'");
var canaryFromTrusted = new ScenarioData(
    new[] { new FileEvent(new DateTime(2026, 7, 23, 2, 0, 0, DateTimeKind.Utc),
        @"CORP\svc-backup", "10.0.1.9", @"\\FS01\Financeiro",
        FileOp.Rename, "_aaa_ransomguard_canary.docx", ".locked", IsCanary: true) },
    Array.Empty<HostSignal>());
Check("canario-fura-allowlist", Contentions(canaryFromTrusted) > 0,
    "canário tocado → contido mesmo de origem allowlisted");

Console.WriteLine("\n" + new string('─', 60));
if (failures.Count == 0) { Console.WriteLine("VERDE — guard-rails de falso positivo validados."); return 0; }
Console.WriteLine($"VERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return 1;
