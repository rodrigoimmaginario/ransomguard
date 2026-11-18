using RansomGuard.Core.Detection;

namespace RansomGuard.Core.Simulation;

/// <summary>
/// Gera fluxos de eventos que reproduzem casos de uso conhecidos — comportamento normal da rede e
/// ataques de ransomware — para exercitar o motor de detecção de forma autônoma (sem lab Windows).
/// Determinístico: cenários fixos, sem aleatoriedade, para servir de portão de regressão.
///
/// Os eventos aqui têm a mesma forma dos que o agente coletaria dos recursos nativos do Windows
/// (4663/5145, USN, canário via SACL), de modo que validar contra este gerador valida a lógica
/// real de detecção. A fidelidade dos *coletores* é confirmada nos spikes do lab do tester.
/// </summary>
public static class NetworkScenario
{
    private static readonly DateTime Base = new(2026, 7, 23, 2, 0, 0, DateTimeKind.Utc);

    /// <summary>Um dia normal: backup noturno, robocopy de migração e usuários editando arquivos.</summary>
    public static ScenarioData NormalTraffic()
    {
        var e = new List<FileEvent>();

        // Backup noturno: milhares de leituras/escritas legítimas por uma conta de serviço.
        for (var i = 0; i < 3000; i++)
            e.Add(new FileEvent(Base.AddMilliseconds(i * 5), @"CORP\svc-backup", "10.0.1.9",
                @"\\FS01\Financeiro", i % 2 == 0 ? FileOp.Read : FileOp.Write, $"arquivo{i}.dat"));

        // Robocopy de migração: renomeações/escritas em massa, também conta de serviço.
        for (var i = 0; i < 800; i++)
            e.Add(new FileEvent(Base.AddSeconds(60).AddMilliseconds(i * 10), @"CORP\svc-migra", "10.0.1.15",
                @"\\FS02\Projetos", FileOp.Write, $"migrado{i}.bin"));

        // Usuários comuns: poucas edições espalhadas.
        foreach (var u in new[] { ("CORP\\maria", "10.0.4.77"), ("CORP\\bob", "10.0.5.20") })
            for (var i = 0; i < 8; i++)
                e.Add(new FileEvent(Base.AddSeconds(120 + i * 3), u.Item1, u.Item2,
                    @"\\FS01\Financeiro", FileOp.Write, $"planilha{i}.xlsx"));

        return new ScenarioData(e, new List<HostSignal>());
    }

    /// <summary>Ataque local: conta comprometida criptografa um share a partir do próprio servidor.</summary>
    public static ScenarioData LocalRansomware()
    {
        var e = new List<FileEvent>();
        for (var i = 0; i < 300; i++)
            e.Add(new FileEvent(Base.AddSeconds(i / 3.0), @"CORP\joao", "10.0.6.31",
                @"\\FS02\Projetos", FileOp.Write, $"contrato{i}.docx", NewExtension: ".crypted"));

        var signals = new List<HostSignal>
        {
            new(Base.AddSeconds(20), HostSignalKind.VssDeleted, "FS02", "remoção das cópias de sombra /all /quiet")
        };
        return new ScenarioData(e, signals);
    }

    /// <summary>
    /// Ataque remoto via SMB (o modo dominante): uma máquina comprometida criptografa o share do
    /// servidor pela rede. O processo malicioso nunca roda no servidor — a atribuição vem do IP.
    /// Usa criptografia intermitente (rename + write) para simular evasão de entropia.
    /// </summary>
    public static ScenarioData RemoteSmbRansomware()
    {
        var e = new List<FileEvent>();
        const string attackerIp = "10.0.9.66";
        for (var i = 0; i < 500; i++)
        {
            var t = Base.AddSeconds(i / 4.0);
            e.Add(new FileEvent(t, @"CORP\vendas1", attackerIp, @"\\FS01\Financeiro",
                FileOp.Rename, $"relatorio{i}.xlsx", NewExtension: ".locked"));
        }
        return new ScenarioData(e, new List<HostSignal>());
    }

    /// <summary>Ataque que começa tocando os canários plantados — detecção de altíssima confiança.</summary>
    public static ScenarioData CanaryTripped()
    {
        var e = new List<FileEvent>();
        // Ransomware varre a pasta em ordem alfabética e atinge o canário logo no início.
        e.Add(new FileEvent(Base, @"CORP\atacante", "10.0.9.66", @"\\FS01\Financeiro",
            FileOp.Rename, "_aaa_canary_000.docx", ".locked", IsCanary: true));
        for (var i = 0; i < 120; i++)
            e.Add(new FileEvent(Base.AddSeconds(1 + i / 5.0), @"CORP\atacante", "10.0.9.66",
                @"\\FS01\Financeiro", FileOp.Write, $"doc{i}.docx", NewExtension: ".locked"));
        return new ScenarioData(e, new List<HostSignal>());
    }
}

/// <summary>Dados de um cenário: eventos de arquivo e sinais de host correlatos.</summary>
public sealed record ScenarioData(
    IReadOnlyList<FileEvent> Events,
    IReadOnlyList<HostSignal> HostSignals);
