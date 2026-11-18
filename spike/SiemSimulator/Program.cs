using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;
using RansomGuard.Core.Siem;

// SiemSimulator — portão de regressão do export SIEM (Fatia 5). Prova que incidentes e ações viram
// linhas CEF válidas, de linha única, conteúdo-zero, com escaping correto. exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;
var failures = new List<string>();
void Check(string name, bool ok, string detail)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}");
    if (!ok) failures.Add(name);
}

var t0 = new DateTime(2026, 7, 23, 2, 0, 0, DateTimeKind.Utc);
var incident = new Detection("FS01", @"CORP\vendas1", "10.0.9.66", @"\\FS01\Financeiro",
    Confidence.High, new HashSet<DetectionReason> { DetectionReason.CanaryTouched, DetectionReason.VssDeletion },
    120, t0, t0.AddSeconds(30));

Console.WriteLine("RansomGuard · SiemSimulator");
Console.WriteLine(new string('─', 60));

var cefIncident = CefExporter.Incident(incident);
Console.WriteLine("\nIncidente → CEF:");
Console.WriteLine("  " + cefIncident);
Check("cabecalho-cef", cefIncident.StartsWith("CEF:0|RansomGuard|RansomGuard|1.0|100|"), "header CEF válido");
Check("linha-unica", !cefIncident.Contains('\n') && !cefIncident.Contains('\r'), "sem quebras de linha");
Check("atribuicao", cefIncident.Contains("src=10.0.9.66") && cefIncident.Contains("dvchost=FS01"), "IP e host presentes");
Check("severidade-alta", cefIncident.Contains("|9|"), "severidade 9 para High");

var action = new ResponseAction(ResponseStep.DisableAdAccount, "FS01", @"CORP\vendas1", "contenção");
var entry = new AuditEntry(t0, "RansomGuard", "execute", action, "automática");
var cefAction = CefExporter.ResponseAction(entry);
Console.WriteLine("\nAção de resposta → CEF:");
Console.WriteLine("  " + cefAction);
Check("acao-exporta", cefAction.Contains("act=DisableAdAccount"), "ação no CEF");
Check("escaping-backslash", cefAction.Contains(@"dst=CORP\\vendas1"), "'\\' escapado corretamente");

// Escaping de '=' em valor.
var weird = new Detection("FS01", "u", "1.2.3.4", @"\\FS01\od=d", Confidence.Medium,
    new HashSet<DetectionReason> { DetectionReason.MassRewrite }, 1, t0, t0);
Check("escaping-igual", CefExporter.Incident(weird).Contains(@"fname=\\\\FS01\\od\=d"), "'=' escapado na extensão");

Console.WriteLine("\n" + new string('─', 60));
if (failures.Count == 0) { Console.WriteLine("VERDE — export SIEM (CEF) validado."); return 0; }
Console.WriteLine($"VERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return 1;
