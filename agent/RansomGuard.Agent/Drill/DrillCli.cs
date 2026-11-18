using System.Text;

namespace RansomGuard.Agent.Drill;

/// <summary>
/// Linha de comando do ensaio de ataque. É a fina camada que garante as duas coisas que o
/// <see cref="AttackDrill"/> deixa para o chamador: **mostrar o plano antes** e **só agir com
/// confirmação explícita**.
///
/// Uso:
///   --ensaio-preparar &lt;pasta&gt;              cria a pasta de ensaio (marcador + arquivos)
///   --ensaio &lt;pasta&gt; [--cenario X]          mostra o plano; NÃO executa
///   --ensaio &lt;pasta&gt; [--cenario X] --confirmar   executa o ataque controlado
///   --ensaio-limpar &lt;pasta&gt;                 apaga a pasta de ensaio
///
/// Cenários: completo (padrão), reescrita, renomeacao, canario, bilhete, e os da matriz do laboratório (M3):
/// copia-apaga, no-lugar, apagador, leitura.
///
/// Opções (M3):
///   --arquivos N --subpastas N        (em --ensaio-preparar) tamanho da pasta de ensaio
///   --quantidade N                    quantos arquivos o ataque alcança (padrão 150)
///   --extensao .abc                   extensão dos "cifrados" (padrão .locked, do catálogo)
///   --pular-ocultos                   ignora arquivos ocultos e de sistema
///   --intervalo-ms N                  pausa entre arquivos (ataque lento)
///   --rajada N --pausa-ms M           pausa longa a cada N arquivos (ataque em rajadas)
///   --relatorio arquivo.json          grava o registro da execução (contagens e instantes, em UTC)
/// </summary>
public static class DrillCli
{
    public static int Run(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        var drill = new AttackDrill(new WindowsDrillFileSystem());

        if (TryGet(args, "--ensaio-preparar", out var prep))
            return Preparar(drill, prep, Number(args, "--arquivos", 200, 1, 20_000), Number(args, "--subpastas", 0, 0, 50));

        if (TryGet(args, "--ensaio-limpar", out var limpar))
            return Limpar(drill, limpar);

        if (TryGet(args, "--ensaio", out var pasta))
            return Ensaio(drill, pasta, args);

        Console.WriteLine("Uso: --ensaio-preparar <pasta> | --ensaio <pasta> [--cenario X] [--confirmar] | --ensaio-limpar <pasta>");
        return 2;
    }

    private static int Preparar(AttackDrill drill, string pasta, int arquivos = 200, int subpastas = 0)
    {
        Cabecalho();
        var r = drill.PrepareFolder(pasta, arquivos, subpastas);
        if (r is not null)
        {
            Console.WriteLine($"  Recusado: {r.Reason}");
            return 1;
        }
        Console.WriteLine($"  Pasta de ensaio pronta: {pasta}");
        Console.WriteLine($"  Marcador {AttackDrill.MarkerFile} gravado; arquivos descartáveis criados.");
        Console.WriteLine("\n  Próximo passo: deixe o agente plantar os canários nesta pasta");
        Console.WriteLine($"    RansomGuard.Agent.Service.exe --preparar   (com Agent:ProtectedPaths={pasta})");
        Console.WriteLine("  Depois rode o ataque:");
        Console.WriteLine($"    RansomGuard.Agent.Service.exe --ensaio \"{pasta}\" --confirmar");
        return 0;
    }

    private static int Ensaio(AttackDrill drill, string pasta, string[] args)
    {
        Cabecalho();

        var recusa = drill.CheckTarget(pasta);
        if (recusa is not null)
        {
            Console.WriteLine($"  Recusado: {recusa.Reason}");
            return 1;
        }

        var cenario = ParseCenario(args);
        var opcoes = new DrillOptions(
            Count: Number(args, "--quantidade", 150, 1, 100_000),
            Extension: TryGet(args, "--extensao", out var ext) ? ext : AttackDrill.EncryptedExtension,
            SkipHidden: args.Contains("--pular-ocultos"));
        if (!AttackDrill.IsSafeExtension(opcoes.Extension))
        {
            Console.WriteLine($"  Recusado: extensão não aceita pelo ensaio ({opcoes.Extension}).");
            return 1;
        }
        var ritmo = new DrillPacing(Number(args, "--intervalo-ms", 0, 0, 600_000), Number(args, "--rajada", 0, 0, 100_000), Number(args, "--pausa-ms", 0, 0, 600_000));
        // Os comportamentos originais sem opção nenhuma seguem pelo plano de sempre (não alcançam os canários).
        var usaOpcoes = cenario is DrillScenario.CopyEncryptDelete or DrillScenario.InPlace or DrillScenario.Wiper or DrillScenario.MassRead
                        || args.Any(a => a is "--quantidade" or "--extensao" or "--pular-ocultos" or "--subpastas-alvo");
        var plano = usaOpcoes || cenario == DrillScenario.RansomNote ? drill.Plan(pasta, cenario, opcoes) : drill.Plan(pasta, cenario);

        Console.WriteLine($"  Cenário: {cenario}   Pasta: {pasta}");
        Console.WriteLine($"  Ações planejadas: {plano.Count}\n");
        foreach (var g in plano.GroupBy(a => a.Kind))
            Console.WriteLine($"    • {g.Count()}× {g.Key}");

        Console.WriteLine("\n  O que o produto DEVERIA detectar:");
        foreach (var l in DrillExpectation.ForPlan(plano))
            Console.WriteLine($"    → {l}");

        if (!args.Contains("--confirmar"))
        {
            Console.WriteLine("\n  Isto foi só o PLANO. Nada foi alterado.");
            Console.WriteLine("  Para executar de verdade, repita o comando com --confirmar.");
            return 0;
        }

        var resultado = drill.Run(pasta, plano, ritmo);
        var feitas = resultado.Done;
        if (TryGet(args, "--relatorio", out var relatorio))
            File.WriteAllText(relatorio, System.Text.Json.JsonSerializer.Serialize(new
            {
                scenario = cenario.ToString(), folder = pasta, extension = opcoes.Extension, skipHidden = opcoes.SkipHidden,
                intervalMs = ritmo.IntervalMs, burst = ritmo.Burst, pauseMs = ritmo.PauseMs,
                resultado.Planned, resultado.Done, resultado.Failed, resultado.FirstFailureIndex,
                startedUtc = resultado.StartedUtc.ToString("o"), firstFailureAtUtc = resultado.FirstFailureAtUtc?.ToString("o"),
                endedUtc = resultado.EndedUtc.ToString("o"), resultado.StoppedEarly, resultado.Error
            }, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        if (resultado.StoppedEarly)
            Console.WriteLine($"\n  ■ Ensaio INTERROMPIDO pelo servidor depois de {feitas} ação(ões): {resultado.Error}");
        else if (resultado.Failed > 0)
            Console.WriteLine($"\n  ! {resultado.Failed} ação(ões) recusada(s) pelo servidor: {resultado.Error}");
        Console.WriteLine($"\n  ✔ Ensaio executado: {feitas} ação(ões).");
        Console.WriteLine("  Confira o painel e o canal de alerta. Ao terminar, limpe com:");
        Console.WriteLine($"    RansomGuard.Agent.Service.exe --ensaio-limpar \"{pasta}\"");
        return 0;
    }

    private static int Limpar(AttackDrill drill, string pasta)
    {
        Cabecalho();
        var r = drill.Clean(pasta);
        if (r is not null)
        {
            Console.WriteLine($"  Recusado: {r.Reason}");
            return 1;
        }
        Console.WriteLine($"  Pasta de ensaio removida: {pasta}");
        return 0;
    }

    private static DrillScenario ParseCenario(string[] args)
    {
        if (!TryGet(args, "--cenario", out var v)) return DrillScenario.Full;
        return v.ToLowerInvariant() switch
        {
            "reescrita" => DrillScenario.MassRewrite,
            "renomeacao" or "renomeação" => DrillScenario.MassRename,
            "canario" or "canário" => DrillScenario.Canary,
            "bilhete" => DrillScenario.RansomNote,
            "copia-apaga" => DrillScenario.CopyEncryptDelete,
            "no-lugar" => DrillScenario.InPlace,
            "apagador" => DrillScenario.Wiper,
            "leitura" => DrillScenario.MassRead,
            _ => DrillScenario.Full
        };
    }

    private static void Cabecalho()
    {
        Console.WriteLine("RansomGuard · ensaio de ataque controlado");
        Console.WriteLine("⚠️  Só opera em pasta de ensaio (marcador obrigatório). Nada é criptografado.");
        Console.WriteLine(new string('─', 66));
    }

    /// <summary>Lê um número depois de uma flag, dentro de um intervalo; fora dele (ou ausente) vale o padrão.</summary>
    private static int Number(string[] args, string flag, int fallback, int min, int max) =>
        TryGet(args, flag, out var text) && int.TryParse(text, out var n) && n >= min && n <= max ? n : fallback;

    /// <summary>Lê o valor após uma flag (ex.: `--ensaio C:\pasta`).</summary>
    private static bool TryGet(string[] args, string flag, out string value)
    {
        var i = Array.IndexOf(args, flag);
        if (i >= 0 && i + 1 < args.Length && !args[i + 1].StartsWith("--"))
        {
            value = args[i + 1];
            return true;
        }
        value = "";
        return false;
    }
}
