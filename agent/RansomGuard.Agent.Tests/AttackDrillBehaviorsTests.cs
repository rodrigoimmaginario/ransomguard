using RansomGuard.Agent.Drill;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// M3 — o provocador reproduz os comportamentos de ataque da matriz de casos de uso (A2–A9, A14), para o laboratório
/// simular mais do que "regrava e renomeia". As cinco travas continuam: só em pasta marcada, nunca cifra, só com
/// confirmação (na CLI), reversível.
/// </summary>
public class AttackDrillBehaviorsTests
{
    private sealed class Disk : IDrillFileSystem
    {
        public Dictionary<string, string> Files { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Dirs { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Hidden { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Reads { get; } = new();
        /// <summary>A partir desta quantidade de operações de escrita, o "servidor" passa a negar (contenção em curso).</summary>
        public int DenyAfter { get; set; } = int.MaxValue;
        private int _writes;

        private void Gate() { if (++_writes > DenyAfter) throw new UnauthorizedAccessException("Acesso negado."); }
        public bool DirectoryExists(string path) => Dirs.Contains(path);
        public bool FileExists(string path) => Files.ContainsKey(path);
        public IReadOnlyList<string> ListFiles(string path) =>
            Files.Keys.Where(f => string.Equals(Path.GetDirectoryName(f), path, StringComparison.OrdinalIgnoreCase)).Select(f => Path.GetFileName(f)).ToList();
        public IReadOnlyList<string> ListDirectories(string path) =>
            Dirs.Where(d => string.Equals(Path.GetDirectoryName(d), path, StringComparison.OrdinalIgnoreCase)).ToList();
        public void CreateDirectory(string path) => Dirs.Add(path);
        public void WriteFile(string fullPath, string content) { Gate(); Files[fullPath] = content; }
        public void Move(string from, string to) { Gate(); Files[to] = Files[from]; Files.Remove(from); }
        public void Touch(string fullPath) => Gate();
        public void DeleteDirectory(string path) { }
        public void DeleteFile(string fullPath) { Gate(); Files.Remove(fullPath); }
        public void ReadFile(string fullPath) => Reads.Add(fullPath);
        public bool IsHiddenOrSystem(string fullPath) => Hidden.Contains(fullPath);
    }

    private const string Folder = @"D:\ensaio";

    private static (AttackDrill Drill, Disk Disk) Prepared(int files = 20, int subfolders = 0)
    {
        var disk = new Disk();
        var drill = new AttackDrill(disk);
        Assert.Null(drill.PrepareFolder(Folder, files, subfolders));
        return (drill, disk);
    }

    private static string[] DataFiles(Disk disk) =>
        disk.Files.Keys.Where(f => !f.EndsWith(AttackDrill.MarkerFile, StringComparison.OrdinalIgnoreCase)).OrderBy(f => f).ToArray();

    [Fact]
    public void Copia_cifrada_ao_lado_e_apaga_o_original()
    {
        var (drill, disk) = Prepared(5);

        var result = drill.Run(Folder, drill.Plan(Folder, DrillScenario.CopyEncryptDelete, new DrillOptions(Extension: ".zzlab")));

        Assert.Equal(10, result.Done);                                        // 5 gravações + 5 exclusões
        Assert.All(DataFiles(disk), f => Assert.EndsWith(".docx.zzlab", f));
        Assert.All(DataFiles(disk), f => Assert.Contains("ensaio", disk.Files[f]));   // conteúdo inerte, nunca cifra
    }

    [Fact]
    public void Regrava_no_lugar_sem_mudar_nome_nem_extensao()
    {
        var (drill, disk) = Prepared(5);
        var before = DataFiles(disk);

        drill.Run(Folder, drill.Plan(Folder, DrillScenario.InPlace, new DrillOptions()));

        Assert.Equal(before, DataFiles(disk));
        Assert.All(before, f => Assert.Contains("substituido", disk.Files[f]));
    }

    [Fact]
    public void Apagador_remove_os_arquivos_de_ensaio_e_preserva_o_marcador()
    {
        var (drill, disk) = Prepared(8);

        var result = drill.Run(Folder, drill.Plan(Folder, DrillScenario.Wiper, new DrillOptions(Count: 6)));

        Assert.Equal(6, result.Done);
        Assert.Equal(2, DataFiles(disk).Length);
        Assert.True(disk.FileExists(Path.Combine(Folder, AttackDrill.MarkerFile)));
    }

    [Fact]
    public void Leitura_em_massa_so_le()
    {
        var (drill, disk) = Prepared(7);
        var before = disk.Files.ToDictionary(kv => kv.Key, kv => kv.Value);

        var result = drill.Run(Folder, drill.Plan(Folder, DrillScenario.MassRead, new DrillOptions()));

        Assert.Equal(7, result.Done);
        Assert.Equal(7, disk.Reads.Count);
        Assert.Equal(before, disk.Files);
    }

    [Fact]
    public void Renomeacao_aceita_extensao_fora_do_catalogo_e_recusa_extensao_malformada()
    {
        var (drill, disk) = Prepared(3);

        drill.Run(Folder, drill.Plan(Folder, DrillScenario.MassRename, new DrillOptions(Extension: ".q7x")));

        Assert.All(DataFiles(disk), f => Assert.EndsWith(".q7x", f));
        Assert.True(AttackDrill.IsSafeExtension(".q7x"));
        Assert.False(AttackDrill.IsSafeExtension("q7x"));
        Assert.False(AttackDrill.IsSafeExtension(".a b"));
        Assert.False(AttackDrill.IsSafeExtension(@".a\..\b"));
        Assert.False(AttackDrill.IsSafeExtension(".exe"));                     // o ensaio nunca produz executável
        Assert.Throws<ArgumentException>(() => drill.Plan(Folder, DrillScenario.MassRename, new DrillOptions(Extension: ".exe")));
    }

    [Fact]
    public void Pular_ocultos_deixa_de_fora_os_arquivos_ocultos_e_de_sistema()
    {
        var (drill, disk) = Prepared(4);
        var hidden = Path.Combine(Folder, "!Indice 2021.xlsx");
        disk.Files[hidden] = "canário plantado pelo agente";
        disk.Hidden.Add(hidden);

        var skipping = drill.Plan(Folder, DrillScenario.InPlace, new DrillOptions(SkipHidden: true));
        var blind = drill.Plan(Folder, DrillScenario.InPlace, new DrillOptions());

        Assert.DoesNotContain(skipping, a => a.Target == "!Indice 2021.xlsx");
        Assert.Equal("!Indice 2021.xlsx", blind[0].Target);                   // sem pular, a varredura alfabética o pega primeiro
    }

    [Fact]
    public void Com_subpastas_o_ataque_alcanca_os_arquivos_delas_e_a_nota_vai_para_todas()
    {
        var (drill, disk) = Prepared(files: 3, subfolders: 4);

        Assert.Equal(15, DataFiles(disk).Length);                             // 3 na raiz + 3 em cada uma das 4
        Assert.Equal(15, drill.Plan(Folder, DrillScenario.InPlace, new DrillOptions()).Count);

        var note = drill.Plan(Folder, DrillScenario.RansomNote, new DrillOptions());
        Assert.Equal(5, note.Count);                                          // raiz + 4 subpastas: a MESMA nota espalhada
        drill.Run(Folder, note);
        Assert.Equal(5, disk.Files.Keys.Count(f => Path.GetFileName(f) == AttackDrill.RansomNoteName));
    }

    /// <summary>
    /// A contenção chega no meio do ataque: o provocador não pode morrer com exceção — é o registro dele que diz
    /// quantos arquivos foram tocados antes de o servidor fechar a porta.
    /// </summary>
    [Fact]
    public void Quando_o_servidor_passa_a_negar_o_ataque_para_e_registra_quantos_arquivos_tocou()
    {
        var (drill, disk) = Prepared(100);
        disk.DenyAfter = 100 + 1 + 37;                                        // preparação (100 arquivos + marcador) e depois 37 gravações
        var ticks = 0;
        var t0 = new DateTime(2026, 11, 16, 12, 0, 0, DateTimeKind.Utc);

        var result = drill.Run(Folder, drill.Plan(Folder, DrillScenario.InPlace, new DrillOptions(Count: 100)), clock: () => t0.AddSeconds(ticks++));

        Assert.Equal(37, result.Done);
        Assert.True(result.StoppedEarly);
        Assert.Equal(37, result.FirstFailureIndex);
        Assert.Equal(AttackDrill.MaxConsecutiveFailures, result.Failed);
        Assert.Contains("negado", result.Error);
        Assert.True(result.FirstFailureAtUtc > result.StartedUtc);
        Assert.True(result.EndedUtc >= result.FirstFailureAtUtc);
    }

    [Fact]
    public void Ritmo_lento_e_em_rajadas()
    {
        var slow = new DrillPacing(IntervalMs: 500);
        Assert.Equal(500, slow.DelayAfter(0));
        Assert.Equal(500, slow.DelayAfter(41));

        var bursts = new DrillPacing(Burst: 30, PauseMs: 20_000);
        Assert.Equal(0, bursts.DelayAfter(0));
        Assert.Equal(0, bursts.DelayAfter(28));
        Assert.Equal(20_000, bursts.DelayAfter(29));                          // depois do 30º arquivo, pausa
        Assert.Equal(20_000, bursts.DelayAfter(59));

        Assert.Equal(0, DrillPacing.None.DelayAfter(123));

        var delays = new List<int>();
        var (drill, _) = Prepared(6);
        drill.Run(Folder, drill.Plan(Folder, DrillScenario.InPlace, new DrillOptions()), new DrillPacing(Burst: 2, PauseMs: 7), delays.Add);
        Assert.Equal(new[] { 7, 7 }, delays);                                  // depois do 2º e do 4º; depois do último não há o que esperar
    }

    [Fact]
    public void As_travas_valem_para_os_comportamentos_novos()
    {
        var disk = new Disk();
        var drill = new AttackDrill(disk);
        disk.Dirs.Add(@"D:\Dados");
        disk.Files[@"D:\Dados\contrato.docx"] = "do cliente";

        Assert.NotNull(drill.CheckTarget(@"D:\Dados"));                        // sem marcador: recusado
        Assert.NotNull(drill.PrepareFolder(@"D:\Dados", 5, 2));                // pasta com conteúdo que não é de ensaio: recusado
        Assert.Equal("do cliente", disk.Files[@"D:\Dados\contrato.docx"]);
    }
}
