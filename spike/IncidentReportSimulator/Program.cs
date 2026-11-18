using RansomGuard.Core.Audit;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;
using RansomGuard.Core.Signing;

// IncidentReportSimulator — portão de regressão do relatório de incidente assinado (Fatia 5).
// Gera um par de chaves de TESTE, monta o relatório de um incidente contido, assina, verifica OK;
// 1 byte alterado invalida. exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;
var failures = new List<string>();
void Check(string name, bool ok, string detail)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}");
    if (!ok) failures.Add(name);
}

var seed = Enumerable.Range(30, 32).Select(i => (byte)i).ToArray();
var keyId = new byte[] { 3, 1, 4, 1, 5, 9, 2, 6 };
var pub = MinisignPublicKey.FromRaw(keyId, Minisign.PublicKeyFromSeed(seed));

var t0 = new DateTime(2026, 7, 23, 2, 0, 0, DateTimeKind.Utc);
var incident = new Detection("FS01", @"CORP\vendas1", "10.0.9.66", @"\\FS01\Financeiro",
    Confidence.High, new HashSet<DetectionReason> { DetectionReason.CanaryTouched, DetectionReason.VssDeletion },
    120, t0, t0.AddSeconds(30));
var audit = new List<AuditEntry>
{
    new(t0.AddSeconds(31), "RansomGuard", "execute",
        new ResponseAction(ResponseStep.KillSmbSession, "FS01", "10.0.9.66", "auto"), "contenção automática"),
    new(t0.AddSeconds(31), "RansomGuard", "execute",
        new ResponseAction(ResponseStep.DisableAdAccount, "FS01", @"CORP\vendas1", "auto"), "contenção automática"),
    new(t0.AddHours(2), @"CORP\admin", "revert",
        new ResponseAction(ResponseStep.DisableAdAccount, "FS01", @"CORP\vendas1", "auto"), "revisado — conta reabilitada"),
};

Console.WriteLine("RansomGuard · IncidentReportSimulator");
Console.WriteLine(new string('─', 60));

var report = IncidentReport.From(incident, audit);
var (json, sig) = report.Sign(seed, keyId);
Console.WriteLine("\nRelatório canônico (trecho):");
Console.WriteLine("  " + (json.Length > 180 ? json[..180] + "…" : json));

Check("assina-e-verifica", IncidentReport.Verify(json, sig, pub) == MinisignVerificationResult.Valid, "assinatura válida");
Check("contem-incidente", json.Contains("FS01") && json.Contains("KillSmbSession"), "incidente + ações no documento");
Check("contem-remediacao", json.Contains("revert"), "trilha de remediação incluída");

var tampered = json.Replace("10.0.9.66", "10.0.0.1");
Check("adulteracao-invalida", IncidentReport.Verify(tampered, sig, pub) == MinisignVerificationResult.InvalidSignature,
    "1 byte alterado → assinatura inválida");

// Determinismo: mesmo incidente → mesmo JSON canônico (assinatura estável).
var (json2, _) = IncidentReport.From(incident, audit).Sign(seed, keyId);
Check("canonico-deterministico", json == json2, "serialização determinística");

Console.WriteLine("\n" + new string('─', 60));
if (failures.Count == 0) { Console.WriteLine("VERDE — relatório de incidente assinado validado."); return 0; }
Console.WriteLine($"VERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return 1;
