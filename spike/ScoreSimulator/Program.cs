using RansomGuard.Core.Score;

// ScoreSimulator — portão de regressão da Fatia 1. Exercita o RiskScoreEngine real com perfis de
// servidor conhecidos: um servidor "ruim" tira nota baixa e lista correções; ao aplicar as
// correções na postura, a nota sobe e os achados somem; a rede consolida vários servidores e é
// penalizada por servidores sem agente. exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;

var engine = new RiskScoreEngine();
var failures = new List<string>();
void Check(string name, bool ok, string detail)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}");
    if (!ok) failures.Add(name);
}

Console.WriteLine("RansomGuard · ScoreSimulator");
Console.WriteLine(new string('─', 60));

// Servidor típico mal configurado (o "dia 1" de muitos clientes).
var bad = new PostureSnapshot
{
    Server = "FS01",
    SmbV1Enabled = true,
    SmbSigningRequired = false,
    NtlmUnrestricted = true,
    SmbAuthRateLimiter = false,
    Smb445ExposedBroadly = true,
    SharesWritableByEveryone = true,
    BroadNtfsPermissions = true,
    VssEnabled = false,
    BackupServiceRunning = false,
    BackupsProtected = false,
    FsrmActive = false,
    ShareAuditingEnabled = false,
    CanariesPlanted = false,
    AgentInstalled = true,
    OverprivilegedServiceAccounts = true,
    ExcessLocalAdmins = true,
    OsEndOfLifeOrUnpatched = true,
    RdpExposed = true
};

Console.WriteLine("\nCenário 1 · Servidor mal configurado (dia 1)");
var s1 = engine.ScoreServer(bad);
Console.WriteLine($"  Nota: {s1.Score}/100 ({ScoreReport.BandLabel(s1.Band)}), {s1.Findings.Count} achados");
Console.WriteLine($"  Correção prioritária: {s1.Findings.First().Rule.Title}");
Check("ruim-nota-baixa", s1.Score <= 40, $"{s1.Score} ≤ 40 (faixa crítica)");
Check("ruim-tem-correcoes", s1.Findings.Count >= 10, $"{s1.Findings.Count} correções listadas");
Check("ruim-prioriza-share", s1.Findings.First().Rule.Id == "share-everyone",
    "share Everyone-write no topo (maior prioridade)");

// O admin corrige o essencial ao longo da semana.
Console.WriteLine("\nCenário 2 · Depois de aplicar as correções");
var fixed_ = bad with
{
    SmbV1Enabled = false,
    SmbSigningRequired = true,
    NtlmUnrestricted = false,
    SmbAuthRateLimiter = true,
    Smb445ExposedBroadly = false,
    SharesWritableByEveryone = false,
    BroadNtfsPermissions = false,
    VssEnabled = true,
    BackupServiceRunning = true,
    BackupsProtected = true,
    FsrmActive = true,
    ShareAuditingEnabled = true,
    CanariesPlanted = true,
    OverprivilegedServiceAccounts = false,
    ExcessLocalAdmins = false,
    OsEndOfLifeOrUnpatched = false,
    RdpExposed = false
};
var s2 = engine.ScoreServer(fixed_);
Console.WriteLine($"  Nota: {s2.Score}/100 ({ScoreReport.BandLabel(s2.Band)}), {s2.Findings.Count} achados");
Check("corrigido-nota-alta", s2.Score >= 71, $"{s2.Score} ≥ 71 (faixa boa)");
Check("corrigido-sobe", s2.Score > s1.Score, $"{s1.Score} → {s2.Score}");
Check("corrigido-sem-achados", s2.Findings.Count == 0, "todos os achados resolvidos");

// Rede: mistura de servidores + gap de cobertura.
Console.WriteLine("\nCenário 3 · Consolidação da rede + gap de cobertura");
var net = engine.ScoreNetwork(new[] { bad, fixed_ }, discoveredWithoutAgent: 2);
Console.WriteLine($"  Nota da rede: {net.Score}/100 ({ScoreReport.BandLabel(net.Band)})");
Console.WriteLine($"  Servidores sem agente: {net.ServersWithoutAgent}");
Check("rede-pior-primeiro", net.Servers[0].Server == "FS01", "pior servidor listado primeiro");
Check("rede-penaliza-gap", net.ServersWithoutAgent == 2, "gap de cobertura contabilizado");

// Relatório executivo.
Console.WriteLine("\nCenário 4 · Relatório executivo");
var report = ScoreReport.BuildExecutive(net);
Check("relatorio-tem-nota", report.Contains("Nota consolidada"), "relatório traz a nota consolidada");
Check("relatorio-tem-prioridades", report.Contains("Prioridades"), "relatório lista prioridades");

Console.WriteLine("\n" + new string('─', 60));
Console.WriteLine("Prévia do relatório:");
Console.WriteLine(new string('·', 60));
foreach (var line in report.Split('\n').Take(12)) Console.WriteLine("  " + line.TrimEnd());

Console.WriteLine("\n" + new string('─', 60));
if (failures.Count == 0) { Console.WriteLine("VERDE — Score de Risco validado."); return 0; }
Console.WriteLine($"VERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return 1;
