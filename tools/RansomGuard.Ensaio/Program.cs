using System.Text;
using RansomGuard.Agent.Drill;

// Provocador de ensaio do RansomGuard — versão para rodar NA MÁQUINA CLIENTE.
//
// É a mesma AttackDrill (F16) do agente, com as MESMAS cinco travas: só opera em pasta com o
// marcador, recusa caminhos perigosos e UNC, nunca cifra, exige --confirmar, é reversível. A única
// diferença é onde roda — numa estação, mirando o share de teste por um drive mapeado — para o file
// server registrar o ataque com o IP REMOTO real do cliente.
//
// Toda a inteligência mora na lib RansomGuard.Agent; aqui só há o banner e a delegação para DrillCli.

Console.OutputEncoding = Encoding.UTF8;

Console.WriteLine("╔══════════════════════════════════════════════════════════════════╗");
Console.WriteLine("║   RansomGuard · PROVOCADOR DE ENSAIO (cliente → share de teste)    ║");
Console.WriteLine("║                                                                    ║");
Console.WriteLine("║   ISTO É UM ENSAIO. Não criptografa nada e é 100% reversível.      ║");
Console.WriteLine("║   Só age em pasta de ensaio (marcador obrigatório). Mire o share   ║");
Console.WriteLine("║   por um DRIVE MAPEADO (ex.: net use X: \\\\FS01\\teste  →  X:\\ensaio). ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════════════╝");
Console.WriteLine();

if (args.Length == 0)
{
    Console.WriteLine("Como usar (rode nesta ordem):");
    Console.WriteLine();
    Console.WriteLine("  1) Mapeie o share de teste para uma letra:");
    Console.WriteLine("       net use X: \\\\FS01\\teste");
    Console.WriteLine();
    Console.WriteLine("  2) Prepare a pasta de ensaio (cria o marcador + arquivos descartáveis):");
    Console.WriteLine("       RansomGuard-Ensaio.exe --ensaio-preparar X:\\ensaio");
    Console.WriteLine();
    Console.WriteLine("  3) Veja o PLANO (não altera nada):");
    Console.WriteLine("       RansomGuard-Ensaio.exe --ensaio X:\\ensaio");
    Console.WriteLine();
    Console.WriteLine("  4) Execute o ataque de mentira:");
    Console.WriteLine("       RansomGuard-Ensaio.exe --ensaio X:\\ensaio --confirmar");
    Console.WriteLine();
    Console.WriteLine("  5) Confira o incidente no painel (usuário + IP de ORIGEM do cliente) e limpe:");
    Console.WriteLine("       RansomGuard-Ensaio.exe --ensaio-limpar X:\\ensaio");
    Console.WriteLine();
    Console.WriteLine("Cenários (opcional): --cenario completo|reescrita|renomeacao|canario|bilhete");
    return 0;
}

return DrillCli.Run(args);
