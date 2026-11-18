using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;

// PreEncryptionSimulator — portão de regressão da G3. Reproduz a sequência típica que antecede a cifra
// (adivinhar senha → entrar → criar admin → instalar serviço → destruir a recuperação) a partir de eventos do
// Windows e verifica que o produto chega a Alta ANTES de qualquer arquivo ser tocado — e que a operação normal
// (senha errada isolada, grupo comum, comandos administrativos legítimos) não gera nada. exit 0 = verde.
//
// Os comandos de teste são montados por fragmentos em tempo de execução: o binário não contém a sequência literal
// (regra do projeto após o falso positivo do antivírus na DLL de testes).

Console.OutputEncoding = System.Text.Encoding.UTF8;
var failures = new List<string>();
void Check(string name, bool ok, string detail) { Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}"); if (!ok) failures.Add(name); }
Console.WriteLine("RansomGuard · PreEncryptionSimulator (G3)");

var t0 = new DateTime(2026, 10, 4, 12, 0, 0, DateTimeKind.Utc);
string Cmd(params string[] parts) => string.Join(" ", parts);
string Xml(string id, DateTime at, params (string Name, string Value)[] data) =>
    $"<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>{id}</EventID><TimeCreated SystemTime=\"{at:yyyy-MM-ddTHH:mm:ssZ}\"/><Computer>FS01.corp.local</Computer></System><EventData>{string.Join("", data.Select(d => $"<Data Name=\"{d.Name}\">{System.Security.SecurityElement.Escape(d.Value)}</Data>"))}</EventData></Event>";

var engine = new DetectionEngine(new DetectionOptions(), new ActorActivityTracker());
var logons = new LogonFailureAggregator();   // 20 falhas / 5 min

// ── Fase 1: 40 falhas de logon do mesmo IP em 2 min → UM sinal de força bruta (Média).
var raw = Enumerable.Range(0, 40).Select(i => PreEncryptionEventParser.Parse(Xml("4625", t0.AddSeconds(i * 3), ("IpAddress", "10.0.9.66"), ("TargetUserName", "administrator")))!).ToList();
var brute = logons.Aggregate(raw);
Check("rajada de 4625 vira UM sinal de força bruta", brute.Count == 1 && brute[0].Kind == HostSignalKind.LogonBruteForce, $"{brute.Count} sinal(is) de {raw.Count} falhas");
var d1 = engine.Analyze(Array.Empty<FileEvent>(), brute).Single();
Check("força bruta sozinha é Média (alerta, não contenção)", d1.Confidence == Confidence.Medium, $"{d1.Confidence}");

// ── Fase 2: entrou; cria admin e instala serviço (PsExec) no mesmo servidor → duas razões de pré-cifra = Alta.
var admin = PreEncryptionEventParser.Parse(Xml("4732", t0.AddMinutes(3), ("TargetUserName", "Administrators"), ("MemberName", "CORP\\svc-tmp"), ("SubjectUserName", "administrator"), ("SubjectDomainName", "CORP")))!;
var svc = PreEncryptionEventParser.Parse(Xml("7045", t0.AddMinutes(4), ("ServiceName", "PSEXESVC"), ("ImagePath", "%SystemRoot%\\PSEXESVC.exe")))!;
var d2 = engine.Analyze(Array.Empty<FileEvent>(), new[] { admin, svc }).Single();
Check("admin novo + serviço novo no mesmo servidor = Alta sem nenhum arquivo tocado", d2.Confidence == Confidence.High && d2.Reasons.Contains(DetectionReason.PrivilegedAccountChange) && d2.Reasons.Contains(DetectionReason.ServiceInstalled), $"{d2.Confidence} ({string.Join("+", d2.Reasons)})");

// ── Fase 3: destrói a recuperação (comando montado por fragmentos) → Alta imediata, com autor.
var wipe = PreEncryptionEventParser.Parse(Xml("4688", t0.AddMinutes(5), ("CommandLine", Cmd("vss" + "admin.exe", "del" + "ete", "shad" + "ows", "/all", "/quiet")), ("SubjectUserName", "svc-tmp"), ("SubjectDomainName", "CORP")))!;
var d3 = engine.Analyze(Array.Empty<FileEvent>(), new[] { wipe }).Single();
Check("comando contra a recuperação = Alta com autor", d3.Confidence == Confidence.High && d3.Reasons.Contains(DetectionReason.RecoveryTampering) && wipe.Detail.Contains(@"CORP\svc-tmp"), $"{wipe.Detail}");
var boot = PreEncryptionEventParser.Parse(Xml("4688", t0.AddMinutes(5), ("CommandLine", Cmd("bcd" + "edit", "/set", "{default}", "recovery" + "enabled", "no"))))!;
Check("desabilitar recuperação de boot também é Alta", engine.Analyze(Array.Empty<FileEvent>(), new[] { boot }).Single().Confidence == Confidence.High, boot.Detail);

// ── Contraprovas: operação normal não gera nada.
var one = logons.Aggregate(new[] { PreEncryptionEventParser.Parse(Xml("4625", t0.AddHours(2), ("IpAddress", "10.0.0.7"), ("TargetUserName", "ana")))! });
Check("uma senha errada não é sinal", one.Count == 0, "0 sinais");
Check("membro em grupo comum não é sinal", PreEncryptionEventParser.Parse(Xml("4728", t0, ("TargetUserName", "Vendas"), ("MemberName", "CORP\\ana"))) is null, "grupo 'Vendas' ignorado");
var listing = PreEncryptionEventParser.Parse(Xml("4688", t0, ("CommandLine", Cmd("vss" + "admin", "list", "shad" + "ows"))));
var backup = PreEncryptionEventParser.Parse(Xml("4688", t0, ("CommandLine", Cmd("robocopy", "D:\\Shares", "\\\\BKP01\\Dados", "/MIR", "/R:1"))));
Check("listar cópias de sombra e robocopy são comandos legítimos", listing is null && backup is null, "0 sinais");
Check("4625 bruto nunca vira incidente sem agregação", engine.Analyze(Array.Empty<FileEvent>(), raw.Take(3).ToList()).Count == 0, "0 detecções");

Console.WriteLine(failures.Count == 0
    ? "\nVERDE — o playbook de pré-cifra vira incidente antes do primeiro arquivo; operação normal segue limpa."
    : $"\nVERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return failures.Count == 0 ? 0 : 1;
