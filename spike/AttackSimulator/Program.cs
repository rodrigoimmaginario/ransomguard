using RansomGuard.Core.Detection;
using RansomGuard.Core.Simulation;

// AttackSimulator — portão de regressão da Fatia 0 (pedido do owner).
// Reproduz o comportamento normal da rede e ataques de ransomware conhecidos, alimenta o
// DetectionEngine real e verifica que: (a) ataques são detectados e atribuídos ao ator certo;
// (b) o tráfego legítimo (backup/robocopy/usuários) NÃO dispara — semente do guard-rail de
// falso positivo. exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;

// Guard-rail: as contas de serviço de backup/migração entram na allowlist (como no produto real).
var options = new DetectionOptions
{
    MassThreshold = 40,
    AllowlistedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        @"CORP\svc-backup", @"CORP\svc-migra"
    },
    AllowlistedIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "10.0.1.9", "10.0.1.15" }
};
var engine = new DetectionEngine(options);

var failures = new List<string>();

void Check(string name, bool ok, string detail)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}");
    if (!ok) failures.Add(name);
}

Console.WriteLine("RansomGuard · AttackSimulator");
Console.WriteLine(new string('─', 60));

// 1. Tráfego normal não pode gerar detecção.
Console.WriteLine("\nCenário 1 · Tráfego normal da rede (backup + robocopy + usuários)");
var normal = NetworkScenario.NormalTraffic();
var normalDetections = engine.Analyze(normal.Events, normal.HostSignals);
Check("normal-nao-dispara", normalDetections.Count == 0,
    $"{normal.Events.Count} eventos legítimos → {normalDetections.Count} detecções (esperado 0)");

// 2. Ataque local + deleção de VSS → High, atribuído ao usuário local.
Console.WriteLine("\nCenário 2 · Ransomware local (conta comprometida no servidor)");
var local = NetworkScenario.LocalRansomware();
var localDet = engine.Analyze(local.Events, local.HostSignals);
var l = localDet.FirstOrDefault();
Check("local-detectado", l is not null, $"{localDet.Count} detecção(ões)");
Check("local-confianca-alta", l?.Confidence == Confidence.High,
    $"confiança {l?.Confidence} (VSS deletado no playbook)");
Check("local-atribuido", l?.User == @"CORP\joao" && l?.Server == "FS02",
    $"{l?.User} @ {l?.Server}");

// 3. Ataque remoto via SMB → detectado e atribuído ao IP de origem (o ponto cego do EDR).
Console.WriteLine("\nCenário 3 · Ransomware remoto via SMB (ponto cego do EDR)");
var remote = NetworkScenario.RemoteSmbRansomware();
var remoteDet = engine.Analyze(remote.Events, remote.HostSignals);
var r = remoteDet.FirstOrDefault();
Check("remoto-detectado", r is not null, $"{remoteDet.Count} detecção(ões)");
Check("remoto-atribuido-ao-ip", r?.SourceIp == "10.0.9.66",
    $"origem {r?.SourceIp} (máquina remota, não o servidor)");
Check("remoto-troca-extensao", r?.Reasons.Contains(DetectionReason.ExtensionFlip) == true,
    "troca de extensão em massa detectada");

// 4. Canário tocado → High imediato, mesmo antes do volume.
Console.WriteLine("\nCenário 4 · Canário tocado (detecção de altíssima confiança)");
var canary = NetworkScenario.CanaryTripped();
var canaryDet = engine.Analyze(canary.Events, canary.HostSignals);
var c = canaryDet.FirstOrDefault();
Check("canario-alta-confianca", c?.Confidence == Confidence.High, $"confiança {c?.Confidence}");
Check("canario-motivo", c?.Reasons.Contains(DetectionReason.CanaryTouched) == true, "canário como razão");


// ── G1 — seis perfis de ataque SEM canário, fluindo em lotes de 5 s como no agente real ────────────
// A pergunta que importa: o produto chega a Alta (contenção) ou pelo menos a Média (alerta + snapshot)
// quando o ransomware não toca canário, não apaga VSS e não mata o agente?
Console.WriteLine("\nCenário 5 · G1 — perfis de ataque sem canário (lotes de 5 s, memória entre ciclos)");
var t0 = new DateTime(2026, 10, 4, 10, 0, 0, DateTimeKind.Utc);
var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".lockbit", ".akira", ".locked" };
DetectionEngine Fresh() => new(new DetectionOptions
{
    MassThreshold = 40,
    KnownExtensionsProvider = () => known,
    DecoyShares = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"\\FS01\Backup$" },
    AllowlistedUsers = options.AllowlistedUsers, AllowlistedIps = options.AllowlistedIps
}, new ActorActivityTracker());

// Alimenta o motor em lotes de 5 s (como o Worker) e devolve a melhor detecção vista para o ator.
Detection? Run(DetectionEngine engine, IEnumerable<FileEvent> stream)
{
    Detection? best = null;
    foreach (var batch in stream.OrderBy(e => e.At).GroupBy(e => (long)((e.At - t0).TotalSeconds / 5)))
        foreach (var d in engine.Analyze(batch.ToList()))
            if (best is null || d.Confidence > best.Confidence) best = d;
    return best;
}
FileEvent Ev(double secs, string path, FileOp op = FileOp.Write, string? ext = null, string share = @"\\FS01\Fin") =>
    new(t0.AddSeconds(secs), @"CORP\vitima", "10.0.9.66", share, op, path, ext);

// 1. Rápido, extensão desconhecida: 100 arquivos/s renomeados para .zzz (não está no catálogo).
var rapido = Run(Fresh(), Enumerable.Range(0, 600).Select(i => Ev(i / 100.0, $"d{i / 50}\\f{i}.xlsx", FileOp.Rename, ".zzz")));
Check("g1-rapido-media", rapido is not null && rapido.Confidence >= Confidence.Medium, $"{rapido?.Confidence} ({string.Join("+", rapido?.Reasons ?? new HashSet<DetectionReason>())})");

// 2. Rápido, extensão CONHECIDA do catálogo: 5 arquivos bastam → Alta.
var conhecida = Run(Fresh(), Enumerable.Range(0, 8).Select(i => Ev(i * 0.3, $"f{i}.docx", FileOp.Rename, ".lockbit")));
Check("g1-extensao-conhecida-alta", conhecida?.Confidence == Confidence.High && conhecida.Reasons.Contains(DetectionReason.KnownRansomExtension), $"{conhecida?.Confidence}");

// 3. Low-and-slow: 1 arquivo a cada 4 s por 40 min (600 arquivos) — nunca 40 em 60 s.
var lento = Run(Fresh(), Enumerable.Range(0, 600).Select(i => Ev(i * 4.0, $"s{i}.pdf")));
Check("g1-lento-media", lento is not null && lento.Reasons.Contains(DetectionReason.SustainedRewrite), $"{lento?.Confidence} ({string.Join("+", lento?.Reasons ?? new HashSet<DetectionReason>())})");

// 4. Cifra em-lugar sem trocar extensão, intermitente (rajadas de 30 a cada 20 s): nunca 40 num lote de 5 s.
var intermitente = Run(Fresh(), Enumerable.Range(0, 20).SelectMany(burst => Enumerable.Range(0, 30).Select(i => Ev(burst * 20 + i * 0.1, $"b{burst}\\f{i}.xlsx"))));
Check("g1-intermitente-media", intermitente is not null && intermitente.Confidence >= Confidence.Medium, $"{intermitente?.Confidence} ({string.Join("+", intermitente?.Reasons ?? new HashSet<DetectionReason>())})");

// 5. Nota de resgate em 4 diretórios, poucos arquivos cifrados (o atacante foi cuidadoso com volume).
var nota = Run(Fresh(), new[] { "a", "b", "c", "d" }.Select((dir, i) => Ev(i, $"{dir}\\HOW_TO_RESTORE_FILES.txt")).Concat(Enumerable.Range(0, 10).Select(i => Ev(5 + i, $"a\\f{i}.xlsx"))));
Check("g1-nota-alta", nota?.Confidence == Confidence.High && nota.Reasons.Contains(DetectionReason.RansomNote), $"{nota?.Confidence}");

// 6. Share-isca: um único acesso de leitura ao share que ninguém usa.
var isca = Run(Fresh(), new[] { Ev(0, "backup-2024.bak", FileOp.Read, share: @"\\FS01\Backup$") });
Check("g1-isca-alta", isca?.Confidence == Confidence.High && isca.Reasons.Contains(DetectionReason.DecoyShareTouched), $"{isca?.Confidence}");

// Contraprova: o tráfego normal em lotes de 5 s com memória continua limpo (o ganho não vem de baixar o limiar).
var normalStream = normal.Events.OrderBy(e => e.At).ToList();
var normalEngine = Fresh();
var normalHits = 0;
var base0 = normalStream.First().At;
foreach (var batch in normalStream.GroupBy(e => (long)((e.At - base0).TotalSeconds / 5)))
    normalHits += normalEngine.Analyze(batch.ToList()).Count;
Check("g1-normal-continua-limpo", normalHits == 0, $"{normalHits} detecções no tráfego legítimo em lotes (esperado 0)");

var perfis = new[] { rapido, conhecida, lento, intermitente, nota, isca };
var alta = perfis.Count(d => d?.Confidence == Confidence.High);
var media = perfis.Count(d => d?.Confidence == Confidence.Medium);
Console.WriteLine($"  Perfis sem canário: {alta} em Alta (contenção), {media} em Média (alerta + snapshot), {6 - alta - media} invisíveis.");

Console.WriteLine("\n" + new string('─', 60));
if (failures.Count == 0)
{
    Console.WriteLine("VERDE — todos os cenários passaram.");
    return 0;
}

Console.WriteLine($"VERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return 1;
