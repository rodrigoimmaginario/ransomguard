using RansomGuard.Core.Fsrm;

// FsrmOrchestrationSimulator — porta do script original do owner (MetadadosExtensoesRansonware.ps1)
// para orquestração dirigida por catálogo. Verifica que, a partir do catálogo, geramos um script
// FSRM idempotente e completo. Não executa FSRM (isso é do serviço/lab); valida a geração. exit 0.

Console.OutputEncoding = System.Text.Encoding.UTF8;

var seedPath = Path.Combine(AppContext.BaseDirectory, "catalog.seed.json");
if (!File.Exists(seedPath))
{
    // Cai para o caminho do repositório em execução via `dotnet run`.
    seedPath = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", "..", "list", "catalog.seed.json"));
}

var failures = new List<string>();
void Check(string name, bool ok, string detail)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}");
    if (!ok) failures.Add(name);
}

Console.WriteLine("RansomGuard · FsrmOrchestrationSimulator");
Console.WriteLine(new string('─', 60));

var catalog = RansomwareCatalog.FromJson(File.ReadAllText(seedPath));
Console.WriteLine($"\nCatálogo carregado: v{catalog.Version}, {catalog.Patterns.Count} padrões");

var paths = new[] { @"D:\Shares\Financeiro", @"E:\Shares\Projetos" };
var active = FsrmPlan.BuildPowerShell(catalog, paths, active: true);
var passive = FsrmPlan.BuildPowerShell(catalog, paths, active: false);

Check("gera-file-group", active.Contains(FsrmPlan.FileGroupName), FsrmPlan.FileGroupName);
Check("inclui-todos-padroes",
    catalog.Patterns.All(p => active.Contains($"'{p}'")),
    $"{catalog.Patterns.Count} padrões presentes no script");
Check("aplica-a-todas-pastas", paths.All(active.Contains), $"{paths.Length} pastas");
Check("idempotente",
    active.Contains("Get-FsrmFileGroup") && active.Contains("Set-FsrmFileGroup")
        && active.Contains("New-FsrmFileGroup"),
    "cria-ou-atualiza file group e file screen");
Check("modo-ativo-bloqueia", active.Contains("-Active:$true"), "screen ativo no modo de bloqueio");
Check("modo-passivo-audita",
    passive.Contains("-Active:$false") && !passive.Contains("-Active:$true"),
    "screen passivo no modo de auditoria");

Console.WriteLine("\nPrévia do script gerado (modo ativo):");
Console.WriteLine(new string('·', 60));
foreach (var line in active.Split('\n').Take(10))
    Console.WriteLine("  " + line.TrimEnd());
Console.WriteLine("  ...");

Console.WriteLine("\n" + new string('─', 60));
if (failures.Count == 0) { Console.WriteLine("VERDE — orquestração FSRM validada."); return 0; }
Console.WriteLine($"VERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return 1;
