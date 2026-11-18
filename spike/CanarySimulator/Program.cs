using RansomGuard.Core.Detection;
using RansomGuard.Core.Fsrm;

// CanarySimulator — valida o ciclo do arquivo-canário: plantar nomes que ancoram nos extremos do
// diretório, reconhecer um toque no canário e confirmar que ele vira detecção de alta confiança
// mesmo isolado (um único evento). exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;

var failures = new List<string>();
void Check(string name, bool ok, string detail)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}");
    if (!ok) failures.Add(name);
}

Console.WriteLine("RansomGuard · CanarySimulator");
Console.WriteLine(new string('─', 60));

const string share = @"\\FS01\Financeiro";
var canaries = CanaryPlan.NamesFor(share);
Console.WriteLine($"\nCanários plantados em {share}: {canaries.Count}");
foreach (var n in canaries) Console.WriteLine("  · " + n);

Check("ancora-inicio", canaries.Any(n => n.StartsWith("!0_")), "há canário no INÍCIO absoluto da listagem NTFS (G1: \"!\" vem antes de dígitos e letras)");
Check("ancora-meio-fim", canaries.Any(n => n.StartsWith("_aaa")), "há canário logo após as letras");
Check("ancora-fim", canaries.Any(n => n.StartsWith("~zz_")), "há canário no FIM absoluto da listagem (\"~\" é o último printável ASCII)");
Check("reconhece-canario",
    CanaryPlan.IsCanary($@"{share}\{canaries[0]}") && !CanaryPlan.IsCanary($@"{share}\folha.xlsx"),
    "distingue canário de arquivo real");

// Um único toque no canário deve bastar para uma detecção de alta confiança.
var engine = new DetectionEngine();
var evt = new FileEvent(
    new DateTime(2026, 7, 23, 2, 0, 0, DateTimeKind.Utc),
    @"CORP\atacante", "10.0.9.66", share,
    FileOp.Rename, $@"{share}\{canaries[0]}", ".locked", IsCanary: true);

var det = engine.Analyze(new[] { evt }).FirstOrDefault();
Check("toque-vira-deteccao", det is not null, "1 evento de canário → 1 detecção");
Check("alta-confianca", det?.Confidence == Confidence.High, $"confiança {det?.Confidence}");
Check("motivo-canario", det?.Reasons.Contains(DetectionReason.CanaryTouched) == true, "razão = canário");

Console.WriteLine("\n" + new string('─', 60));
if (failures.Count == 0) { Console.WriteLine("VERDE — ciclo do canário validado."); return 0; }
Console.WriteLine($"VERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return 1;
