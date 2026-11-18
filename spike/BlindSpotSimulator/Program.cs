using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Score;

// BlindSpotSimulator — portão de regressão da G2 (visibilidade auto-reparável). O passo "cegar o agente" do
// playbook (desligar auditoria, limpar o log, apagar canários, log pequeno que roda) nunca pode virar silêncio:
// vira incidente de Alta e, quando dá, reparo automático. exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;
var failures = new List<string>();
void Check(string name, bool ok, string detail) { Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}"); if (!ok) failures.Add(name); }
Console.WriteLine("RansomGuard · BlindSpotSimulator (G2)");

var t0 = new DateTime(2026, 10, 4, 11, 0, 0, DateTimeKind.Utc);
string Xml(string id, params (string Name, string Value)[] data) =>
    $"<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>{id}</EventID><TimeCreated SystemTime=\"2026-10-04T11:00:00Z\"/><Computer>FS01.corp.local</Computer></System><EventData>{string.Join("", data.Select(d => $"<Data Name=\"{d.Name}\">{d.Value}</Data>"))}</EventData></Event>";

var engine = new DetectionEngine(new DetectionOptions(), new ActorActivityTracker());

// 1. Atacante desliga 'Detailed File Share' (4719) antes de cifrar.
var s4719 = VisibilityEventParser.Parse(Xml("4719", ("SubcategoryName", "Detailed File Share"), ("AuditPolicyChanges", "%%8448"), ("SubjectUserName", "adm-comprometido"), ("SubjectDomainName", "CORP")));
var d1 = engine.Analyze(Array.Empty<FileEvent>(), new[] { s4719! }).SingleOrDefault();
Check("4719 em file share vira incidente Alta", d1?.Confidence == Confidence.High && d1.Reasons.Contains(DetectionReason.VisibilityTamper) && d1.Server == "FS01", $"{d1?.Confidence} {s4719?.Detail}");

// 2. 4719 em subcategoria irrelevante (Logon) é ruído administrativo: nada.
Check("4719 fora das subcategorias de arquivo é ignorado", VisibilityEventParser.Parse(Xml("4719", ("SubcategoryName", "Logon"))) is null, "sem sinal");

// 3. Log limpo (1102).
var s1102 = VisibilityEventParser.Parse(Xml("1102", ("SubjectUserName", "adm-comprometido"), ("SubjectDomainName", "CORP")));
var d3 = engine.Analyze(Array.Empty<FileEvent>(), new[] { s1102! }).SingleOrDefault();
Check("1102 (log limpo) vira incidente Alta com autor", d3?.Confidence == Confidence.High && s1102!.Detail.Contains(@"CORP\adm-comprometido"), $"{s1102?.Detail}");

// 4. Canário apagado (replantio depois do primeiro plantio) — produzido pelo ProtectionApplier via buffer.
var buffer = new HostSignalBuffer();
buffer.Push(new HostSignal(t0, HostSignalKind.CanaryMissing, "FS01", "3 canário(s) sumiram de D:\\Shares\\Fin e foram replantados."));
var d4 = engine.Analyze(Array.Empty<FileEvent>(), buffer.Drain()).SingleOrDefault();
// D6: sozinho é Média (um espelhamento com purga apaga canários todo dia); com outro indício de adulteração, Alta.
Check("canário apagado sozinho vira incidente de Média", d4?.Confidence == Confidence.Medium, $"{d4?.Confidence}");
var d4b = engine.Analyze(Array.Empty<FileEvent>(), new[]
{
    new HostSignal(t0, HostSignalKind.CanaryMissing, "FS01", "3 canário(s) sumiram e foram replantados."),
    new HostSignal(t0.AddSeconds(20), HostSignalKind.VssReduced, "FS01", "2 cópia(s) de sombra removida(s)")
}).SingleOrDefault();
Check("canário apagado + cópias de sombra reduzidas vira Alta", d4b?.Confidence == Confidence.High, $"{d4b?.Confidence}");

// 5. Auditoria desligada + log de 20 MB: com auto-reparo, dois reparos e um sinal de Alta; o sinal de "reparado" NÃO é incidente.
var plan = VisibilityGuard.Evaluate(detailedFileShareAuditEnabled: false, securityLogMaxBytes: 20L * 1024 * 1024, autoRepair: true, "FS01", t0);
Check("auditoria desligada + log pequeno → 2 reparos planejados", plan.Repairs.SequenceEqual(new[] { RepairAction.EnableDetailedFileShareAudit, RepairAction.GrowSecurityLog }), string.Join("+", plan.Repairs));
var d5 = engine.Analyze(Array.Empty<FileEvent>(), plan.Signals).SingleOrDefault();
Check("auditoria desligada é incidente Alta (cegueira nunca é silêncio)", d5?.Confidence == Confidence.High, $"{d5?.Confidence}");
var repaired = plan.Repairs.Select(r => VisibilityGuard.Repaired(r, "FS01", t0)).ToList();
Check("reparo concluído é informativo, não incidente", engine.Analyze(Array.Empty<FileEvent>(), repaired).Count == 0, $"{repaired.Count} sinais informativos");

// 6. Auto-reparo desligado: só reporta.
var reportOnly = VisibilityGuard.Evaluate(false, 20L * 1024 * 1024, autoRepair: false, "FS01", t0);
Check("sem auto-reparo: reporta e não mexe", reportOnly.Repairs.Count == 0 && reportOnly.Signals.Count == 1, "1 sinal, 0 reparos");

// 7. Postura: log pequeno derruba a nota com a correção certa; log de 1 GB não.
var small = new PostureSnapshot { Server = "FS01", SecurityLogMaxBytes = 20L * 1024 * 1024 };
var big = small with { SecurityLogMaxBytes = 1024L * 1024 * 1024 };
var rs = new RiskScoreEngine().ScoreServer(small); var rb = new RiskScoreEngine().ScoreServer(big);
Check("regra seclog-size na postura", rs.Findings.Any(f => f.Rule.Id == "seclog-size") && rb.Findings.All(f => f.Rule.Id != "seclog-size") && rs.Score < rb.Score, $"{rs.Score} → {rb.Score}");

// 8. Leitor do wevtutil.
Check("wevtutil maxSize lido", RansomGuard.Agent.Posture.SecurityLogReader.TryReadMaxBytes("logging:\r\n  maxSize: 20971520\r\n") == 20971520L, "20 MB");

Console.WriteLine(failures.Count == 0
    ? "\nVERDE — cegar o agente vira incidente de Alta; auditoria e log são reparados; reparo não vira falso incidente."
    : $"\nVERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return failures.Count == 0 ? 0 : 1;
