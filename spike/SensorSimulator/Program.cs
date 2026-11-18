using System.Text;
using RansomGuard.Agent.Posture;
using RansomGuard.Agent.Drill;
using RansomGuard.Agent.Protection;
using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Fsrm;
using RansomGuard.Core.Score;

// SensorSimulator — portão de regressão dos SENTIDOS do agente (F11).
//
// Até esta fatia o produto era cego: os coletores devolviam lista vazia e três campos da postura
// eram fixos no código. Este simulador exercita o caminho inteiro com eventos no formato real do
// Windows: XML do Security log → parser → correlação com sessão SMB → DetectionEngine → incidente.
//
// exit 0 = verde.

Console.OutputEncoding = Encoding.UTF8;

var falhas = new List<string>();
void Check(string nome, bool ok, string detalhe)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {nome} — {detalhe}");
    if (!ok) falhas.Add(nome);
}

var t0 = new DateTime(2026, 7, 26, 3, 14, 0, DateTimeKind.Utc);
const string Share = @"\\*\Financeiro";
const string LocalPath = @"D:\Shares\Financeiro";

string Xml5145(string user, string ip, string alvo, string acesso = "%%4417", long recordId = 1) => $"""
    <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System><EventID>5145</EventID>
        <TimeCreated SystemTime='{t0:yyyy-MM-ddTHH:mm:ss.fffffffZ}'/>
        <EventRecordID>{recordId}</EventRecordID></System>
      <EventData>
        <Data Name='SubjectUserName'>{user}</Data>
        <Data Name='SubjectDomainName'>CORP</Data>
        <Data Name='ObjectType'>File</Data>
        <Data Name='IpAddress'>{ip}</Data>
        <Data Name='ShareName'>{Share}</Data>
        <Data Name='ShareLocalPath'>\??\{LocalPath}</Data>
        <Data Name='RelativeTargetName'>{alvo}</Data>
        <Data Name='AccessList'>{acesso}</Data>
      </EventData>
    </Event>
    """;

string Xml4663(string user, string alvo, long recordId = 1) => $"""
    <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System><EventID>4663</EventID>
        <TimeCreated SystemTime='{t0:yyyy-MM-ddTHH:mm:ss.fffffffZ}'/>
        <EventRecordID>{recordId}</EventRecordID></System>
      <EventData>
        <Data Name='SubjectUserName'>{user}</Data>
        <Data Name='SubjectDomainName'>CORP</Data>
        <Data Name='ObjectType'>File</Data>
        <Data Name='ObjectName'>{LocalPath}\{alvo}</Data>
        <Data Name='AccessList'>%%4417</Data>
      </EventData>
    </Event>
    """;

Console.WriteLine("RansomGuard · SensorSimulator");
Console.WriteLine(new string('─', 66));

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 1 · Criptografia remota via SMB — o ponto cego do EDR");
{
    // 150 arquivos reescritos com extensão de ransomware, vindos de UMA máquina pela rede.
    var eventos = Enumerable.Range(1, 150)
        .Select(i => SecurityEventParser.Parse(
            Xml5145("vendas1", "10.0.9.66", $"doc{i}.docx.locked", recordId: i))!)
        .ToList();

    Check("eventos-traduzidos", eventos.Count == 150, $"{eventos.Count} eventos do XML real");
    Check("origem-atribuida", eventos.All(e => e.SourceIp == "10.0.9.66"), "IP de origem veio do 5145");
    Check("extensao-detectada", eventos.All(e => e.NewExtension == ".locked"), "extensão .locked extraída");

    var deteccoes = new DetectionEngine().Analyze(eventos, Array.Empty<HostSignal>());
    var d = deteccoes.FirstOrDefault();
    Check("incidente-gerado", d is not null, d is null ? "nenhum" : $"{deteccoes.Count} incidente(s)");
    Check("atribuicao-correta",
        d is not null && d.User == @"CORP\vendas1" && d.SourceIp == "10.0.9.66",
        d is null ? "-" : $"{d.User} de {d.SourceIp}");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 2 · Canário tocado — o sinal que dispara a contenção");
{
    var canario = CanaryPlan.NamesFor(LocalPath)[0];
    var evento = SecurityEventParser.Parse(Xml5145("vendas1", "10.0.9.66", canario))!;

    Check("canario-reconhecido", evento.IsCanary, $"'{canario}' marcado como canário");

    var d = new DetectionEngine().Analyze(new[] { evento }, Array.Empty<HostSignal>()).FirstOrDefault();
    Check("confianca-alta", d?.Confidence == Confidence.High,
        d is null ? "nenhum incidente" : $"confiança {d.Confidence}");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 3 · Evento 4663 sem IP → correlação com a sessão SMB");
{
    var bruto = SecurityEventParser.Parse(Xml4663("vendas1", "contrato.docx"))!;
    Check("4663-sem-ip", bruto.SourceIp == SecurityEventParser.LocalOrigin,
        "o 4663 não traz IP — precisa de correlação");

    const string sessoes = """
        SessionId    ClientComputerName ClientUserName NumOpens
        ---------    ------------------ -------------- --------
        412316860417 10.0.9.66          CORP\vendas1   3
        """;
    var atribuido = SessionCorrelator.Attribute(bruto, SessionCorrelator.ParseSessions(sessoes));
    Check("ip-recuperado", atribuido.SourceIp == "10.0.9.66",
        $"origem resolvida para {atribuido.SourceIp}");

    // Sem sessão correspondente, continua local — atribuir errado acusaria um inocente.
    var semSessao = SessionCorrelator.Attribute(bruto, Array.Empty<SmbSession>());
    Check("sem-sessao-nao-inventa", semSessao.SourceIp == SecurityEventParser.LocalOrigin,
        "sem sessão, o evento continua local");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 4 · Backup legítimo NÃO pode virar incidente");
{
    // Conta de backup lendo 5.000 arquivos: volume altíssimo, zero destruição.
    var eventos = Enumerable.Range(1, 5000)
        .Select(i => SecurityEventParser.Parse(
            Xml5145("backup", "10.0.0.5", $"arquivo{i}.docx", acesso: "%%4416", recordId: i))!)
        .ToList();

    Check("leitura-classificada", eventos.All(e => e.Op == FileOp.Read),
        "%%4416 (ReadData) vira leitura, não escrita");

    // G5 mudou a semântica: leitura em massa REMOTA por ator fora da allowlist é precursor de exfiltração (Média, só
    // alerta + snapshot). A conta de backup vai para a allowlist — é a configuração que o produto pede.
    var allow = new DetectionOptions { AllowlistedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { eventos[0].User } };
    var d = new DetectionEngine(allow).Analyze(eventos, Array.Empty<HostSignal>());
    Check("sem-falso-positivo", d.Count == 0, $"{d.Count} incidente(s) em 5.000 leituras da conta de backup (allowlist)");
    var exfil = new DetectionEngine().Analyze(eventos, Array.Empty<HostSignal>());
    Check("leitura-em-massa-sem-allowlist-e-media", exfil.Count == 1 && exfil[0].Confidence == Confidence.Medium && exfil[0].Reasons.Contains(DetectionReason.MassRead),
        "5.000 leituras remotas de conta desconhecida: alerta de exfiltração, sem contenção");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 5 · Cursor: reinício do serviço não duplica nem perde evento");
{
    var store = new MemoriaCursor();
    var cursor = new EventCursor(store);

    // Primeiro ciclo: processa 1..100.
    foreach (var i in Enumerable.Range(1, 100)) if (cursor.IsNew(i)) cursor.Advance(i);
    Check("primeiro-ciclo", cursor.LastRecordId == 100, $"cursor em {cursor.LastRecordId}");

    // Serviço reinicia: o cursor é relido do disco.
    var apos = new EventCursor(store);
    var reprocessados = Enumerable.Range(1, 100).Count(i => apos.IsNew(i));
    Check("nao-reprocessa", reprocessados == 0, $"{reprocessados} eventos reprocessados após reinício");

    var novos = Enumerable.Range(101, 50).Count(i => apos.IsNew(i));
    Check("nao-perde-novos", novos == 50, $"{novos} eventos novos reconhecidos");

    // Security log limpo (playbook de ransomware): os ids recomeçam do 1.
    apos.NoticeNewest(3);
    Check("log-limpo-reinicia", apos.LastRecordId == 0 && apos.IsNew(4),
        "cursor reiniciado após limpeza do log — o agente não cega");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 6 · Cópias de sombra apagadas");
{
    var w = new VssWatcher("FS01");
    Check("linha-de-base", w.Observe(12, t0) is null, "primeira leitura só estabelece a base");

    var sinal = w.Observe(0, t0.AddMinutes(1));
    Check("vss-apagado-detectado", sinal?.Kind == HostSignalKind.VssDeleted,
        sinal?.Detail ?? "nenhum sinal");

    // Leitura falha não pode virar alarme às 3h da manhã.
    var w2 = new VssWatcher("FS01");
    w2.Observe(12, t0);
    Check("falha-de-leitura-nao-alarma", w2.Observe(null, t0.AddMinutes(1)) is null,
        "WMI indisponível não vira 'apagaram seu VSS'");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 7 · Agente cego precisa APARECER, não silenciar");
{
    Check("falha-isolada-ignorada", SensorHealth.Evaluate(1, "FS01", t0) is null,
        "falha isolada é ruído");
    var s = SensorHealth.Evaluate(SensorHealth.FailureThreshold, "FS01", t0);
    Check("cegueira-vira-sinal", s?.Kind == HostSignalKind.AgentTamper, s?.Detail ?? "nenhum sinal");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 8 · Postura: o Score não pontua o que não mediu");
{
    // Auditoria não pôde ser lida (sem privilégio) — o caso real desta máquina.
    const string semPrivilegio = "Error 0x00000522 occurred:\r\nA required privilege is not held by the client.";
    Check("auditpol-sem-privilegio", AuditPolicyReader.TryRead(semPrivilegio, AuditSubcategory.DetailedFileShare) is null,
        "vira desconhecido, não 'auditoria desligada'");

    // Shares administrativos de qualquer Windows não podem virar achado crítico.
    const string administrativos = """
        Name   ScopeName AccountName            AccessControlType AccessRight
        ----   --------- -----------            ----------------- -----------
        C$     *         Everyone               Allow             Full
        ADMIN$ *         BUILTIN\Administrators Allow             Full
        """;
    Check("shares-administrativos-ignorados",
        SharePermissionReader.HasBroadWriteAccess(administrativos) == false,
        "C$/ADMIN$ não geram o achado crítico de share aberto");

    // Share de verdade aberto para Everyone: aí sim é achado.
    const string aberto = """
        Name       ScopeName AccountName AccessControlType AccessRight
        ----       --------- ----------- ----------------- -----------
        Financeiro *         Everyone    Allow             Full
        """;
    Check("share-aberto-detectado", SharePermissionReader.HasBroadWriteAccess(aberto),
        "Everyone com escrita é achado de verdade");

    // A nota sai sobre o que foi medido, e o não medido aparece.
    var postura = new PostureSnapshot
    {
        Server = "FS01",
        SmbSigningRequired = true, SmbAuthRateLimiter = true, VssEnabled = true,
        BackupServiceRunning = true, BackupsProtected = true, FsrmActive = true,
        ShareAuditingEnabled = true, CanariesPlanted = true,
        UnknownChecks = new HashSet<string> { "share-audit", "ntlm" }
    };
    var score = new RiskScoreEngine().ScoreServer(postura);
    Check("nota-sobre-o-medido", score.Score == 100 && score.Findings.Count == 0,
        $"nota {score.Score} sem achados inventados");
    Check("nao-medido-visivel", score.Unknown.Count == 2,
        $"{score.Unknown.Count} checagens marcadas como não verificadas");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 9 · Onde é seguro agir (F12) — o produto escreve no cliente");
{
    // Um erro de digitação numa GPO não pode virar incidente no parque inteiro.
    foreach (var perigoso in new[] { @"C:\", @"C:\Windows", @"C:\Program Files", @"\\OUTRO-FS\Share" })
    {
        var r = ProtectedPaths.Parse(perigoso);
        Check($"recusa {perigoso}", r.Accepted.Count == 0 && r.Rejected.Count == 1,
            r.Rejected.Count == 1 ? r.Rejected[0].Reason[..Math.Min(48, r.Rejected[0].Reason.Length)] + "…" : "ACEITOU");
    }

    var mix = ProtectedPaths.Parse(@"C:\Windows;D:\Shares\Financeiro;d:\shares\financeiro\");
    Check("caminho ruim nao derruba os bons", mix.Accepted.Count == 1 && mix.Rejected.Count == 1,
        $"{mix.Accepted.Count} aceito(s), {mix.Rejected.Count} recusado(s), duplicata removida");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 10 · Canários: plantar, repetir, remover — sem tocar no dado do cliente");
{
    var pasta = Path.Combine(Path.GetTempPath(), "rg-sim-" + Guid.NewGuid().ToString("N")[..8]);
    Directory.CreateDirectory(pasta);
    try
    {
        var doCliente = new[] { "contrato.docx", "_aaa_meu_arquivo.docx" };
        foreach (var n in doCliente) File.WriteAllText(Path.Combine(pasta, n), "dado do cliente");

        var planter = new CanaryPlanter(new DiscoReal());
        var esperados = CanaryPlan.NamesFor(pasta).Count;

        var p1 = planter.Plant(new[] { pasta }).Single();
        Check("plantio", p1.Ok && p1.Planted == esperados, $"{p1.Planted} canário(s) plantado(s)");

        var alvo = Path.Combine(pasta, CanaryPlan.NamesFor(pasta)[0]);
        var carimbo = File.GetLastWriteTimeUtc(alvo);
        var p2 = planter.Plant(new[] { pasta }).Single();
        Check("idempotente", p2.Planted == 0 && File.GetLastWriteTimeUtc(alvo) == carimbo,
            "rodar de novo não reescreve — o backup incremental do cliente agradece");

        planter.Remove(new[] { pasta });
        var restantes = Directory.EnumerateFiles(pasta).Select(Path.GetFileName).ToList();
        Check("remocao-preserva-o-cliente", restantes.Count == doCliente.Length,
            $"{restantes.Count} arquivo(s) do cliente intacto(s) após a remoção");
        Check("conteudo-do-cliente-intacto",
            doCliente.All(n => File.ReadAllText(Path.Combine(pasta, n)) == "dado do cliente"),
            "nenhum byte do cliente foi alterado");
    }
    finally
    {
        foreach (var f in Directory.EnumerateFiles(pasta)) File.SetAttributes(f, FileAttributes.Normal);
        Directory.Delete(pasta, true);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 11 · Modo de proteção: arredondar para baixo, nunca para cima");
{
    Check("sem-pasta-nao-e-protegido",
        ProtectionStatus.Evaluate(0, 0, true, true).Mode == ProtectionMode.None,
        "sem pasta configurada não há proteção, por mais FSRM que exista");

    Check("pasta-sem-canario-nao-conta",
        ProtectionStatus.Evaluate(2, 0, true, true).Mode == ProtectionMode.None,
        "pasta configurada sem canário é o 'achei que estava protegido'");

    var semFsrm = ProtectionStatus.Evaluate(2, 12, false, false);
    Check("sem-FSRM-diz-que-nao-tem", semFsrm.Mode == ProtectionMode.CanaryOnly &&
        semFsrm.Explanation.Contains("FSRM"), "degrada e explica em vez de fingir");

    Check("FSRM-padrao-e-auditoria",
        ProtectionStatus.Evaluate(2, 12, true, false).Mode == ProtectionMode.CanaryAndAudit,
        "bloquear em produção sem o admin pedir seria o produto virando o incidente");

    Check("bloqueio-e-opt-in",
        ProtectionStatus.Evaluate(2, 12, true, true).Mode == ProtectionMode.CanaryAndBlock,
        "com decisão explícita, aí sim bloqueia");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 12 · Catálogo semente não bloqueia arquivo legítimo");
{
    foreach (var legitimo in new[] { "*", "*.*", "*.docx", "*.pdf", "*.xlsx" })
        Check($"semente sem '{legitimo}'", !SeedCatalog.Patterns.Contains(legitimo),
            "curinga largo bloquearia share de produção");

    var script = FsrmPlan.BuildPowerShell(
        RansomwareCatalog.FromJson(SeedCatalog.Json), new[] { @"D:\Shares\Financeiro" }, active: false);
    Check("semente-gera-file-screen", script.Contains("*.lockbit") && script.Contains("PASSIVO"),
        "gera file screen em modo auditoria");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\nCenário 13 · Ensaio de ataque (F16) — a cadeia completa, com travas");
{
    var pasta = Path.Combine(Path.GetTempPath(), "rg-drill-" + Guid.NewGuid().ToString("N")[..8]);
    var fs = new DiscoReal();

    // Trava 1: pasta sem marcador é recusada.
    Directory.CreateDirectory(pasta);
    File.WriteAllText(Path.Combine(pasta, "dado_do_cliente.docx"), "importante");
    var drill = new AttackDrill(new DrillDisk());
    Check("recusa-sem-marcador", drill.CheckTarget(pasta) is not null,
        "pasta sem marcador não é tocada");
    Directory.Delete(pasta, true);

    // Prepara a pasta e planta canários (o produto), depois monta o ataque.
    drill.PrepareFolder(pasta, fileCount: 50);
    new CanaryPlanter(fs).Plant(new[] { pasta });

    // Trava 4: planejar não executa.
    var antes = Directory.EnumerateFiles(pasta).Count();
    var plano = drill.Plan(pasta, DrillScenario.Full);
    Check("plano-nao-executa", Directory.EnumerateFiles(pasta).Count() == antes,
        "mostrar o plano não altera nada");

    // O plano ataca os 50 docs, toca os canários (3 âncoras × 3 extensões) e deixa o bilhete.
    Check("plano-completo",
        plano.Count(a => a.Kind == "canário") == CanaryPlan.NamesFor(pasta).Count &&   // G1: 3 âncoras × 3 extensões = 9
        plano.Count(a => a.Kind == "reescrita") == 50 &&
        plano.Any(a => a.Kind == "bilhete de resgate"),
        $"{plano.Count} ações: {CanaryPlan.NamesFor(pasta).Count} canários + 50 reescritas + bilhete");

    // O relatório diz o que esperar, com o canário em primeiro.
    var expectativa = DrillExpectation.ForPlan(plano);
    Check("relatorio-poe-canario-primeiro", expectativa[0].Contains("ALTA confiança"),
        "o operador sabe o que conferir no painel");

    // Executa e confere o efeito real.
    drill.Execute(pasta, plano);
    var locked = Directory.EnumerateFiles(pasta, "*" + AttackDrill.EncryptedExtension).Count();
    Check("ataque-produz-extensao", locked == 50, $"{locked} arquivos .locked");

    var amostra = File.ReadAllText(Directory.EnumerateFiles(pasta, "*" + AttackDrill.EncryptedExtension).First());
    Check("nada-criptografado", amostra.Contains("ensaio") && !amostra.Any(char.IsControl),
        "conteúdo legível — nada é irrecuperável");

    // Trava 5: limpar remove tudo que o ensaio criou.
    drill.Clean(pasta);
    Check("limpar-reverte", !Directory.Exists(pasta), "pasta de ensaio removida por inteiro");
}

Console.WriteLine("\n" + new string('─', 66));
if (falhas.Count == 0)
{
    Console.WriteLine("VERDE — sentidos, mãos e ensaio de ataque provados ponta a ponta.");
    return 0;
}
Console.WriteLine($"VERMELHO — {falhas.Count} falha(s):");
foreach (var f in falhas) Console.WriteLine($"  ✗ {f}");
return 1;

/// <summary>Disco real para os cenários de canário — canário é arquivo comum, dá para provar aqui.</summary>
sealed class DiscoReal : ICanaryFileSystem
{
    public bool DirectoryExists(string path) => Directory.Exists(path);
    public IReadOnlyList<string> ListFiles(string path) =>
        Directory.EnumerateFiles(path).Select(Path.GetFileName).OfType<string>().ToList();
    public void WriteCanary(string fullPath, string content) => File.WriteAllText(fullPath, content);
    public void Delete(string fullPath) { File.SetAttributes(fullPath, FileAttributes.Normal); File.Delete(fullPath); }
}

/// <summary>Efetor de disco real do ensaio, para o simulador provar as travas em disco.</summary>
sealed class DrillDisk : IDrillFileSystem
{
    public bool DirectoryExists(string path) => Directory.Exists(path);
    public bool FileExists(string full) => File.Exists(full);
    public IReadOnlyList<string> ListFiles(string path) => Directory.EnumerateFiles(path).Select(Path.GetFileName).OfType<string>().ToList();
    public void CreateDirectory(string path) => Directory.CreateDirectory(path);
    public void WriteFile(string full, string c) => File.WriteAllText(full, c);
    public void Move(string from, string to) { if (File.Exists(from)) File.SetAttributes(from, FileAttributes.Normal); File.Move(from, to, true); }
    public void Touch(string full) { using var _ = File.Open(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite); }
    public void DeleteDirectory(string path) { foreach (var f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)) File.SetAttributes(f, FileAttributes.Normal); Directory.Delete(path, true); }
}

/// <summary>Cursor em memória, para o simulador não tocar em disco.</summary>
sealed class MemoriaCursor : ICursorStore
{
    private string? _c;
    public string? Read() => _c;
    public void Write(string content) => _c = content;
}
