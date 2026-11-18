using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Sensors;

/// <summary>
/// Vigia as cópias de sombra. Apagar o VSS é passo praticamente universal do playbook de
/// ransomware — acontece **antes** de pedir resgate, para tirar a saída fácil da vítima. Por isso
/// o <c>DetectionEngine</c> trata este sinal como alta confiança.
///
/// A detecção é por **queda na contagem** entre ciclos, e não por evento: `vssadmin delete
/// shadows` e a API `IVssBackupComponents` produzem eventos diferentes (ou nenhum), enquanto o
/// sumiço das cópias é observável de qualquer jeito.
///
/// Lógica pura — o serviço só informa a contagem lida do WMI.
/// </summary>
public sealed class VssWatcher
{
    private readonly string _server;
    private int? _anterior;

    public VssWatcher(string server) => _server = server;

    /// <summary>Última contagem conhecida (para diagnóstico no painel).</summary>
    public int? LastCount => _anterior;

    /// <summary>
    /// Informa a contagem atual de shadow copies e devolve o sinal, se houver queda.
    /// </summary>
    /// <param name="atual">
    /// Contagem atual, ou <c>null</c> quando a leitura falhou. Leitura falha **não** vira sinal:
    /// alarme falso de "apagaram seu VSS" no meio da madrugada custa a confiança do admin.
    /// </param>
    /// <param name="now">Instante (injetado para teste).</param>
    public HostSignal? Observe(int? atual, DateTime now)
    {
        if (atual is null) return null;              // não sabemos: não inventamos sinal

        var anterior = _anterior;
        _anterior = atual;

        if (anterior is null) return null;           // primeira leitura: só estabelece a linha de base
        if (atual >= anterior) return null;          // igual ou aumentou: nada de errado

        var removidas = anterior.Value - atual.Value;
        // D6: "apagaram as cópias de sombra" é todas sumirem de uma vez. Um backup que cria e remove o próprio
        // snapshot, ou a rotação por espaço, tiram uma de várias — indício fraco, não o passo do playbook.
        var zeradas = atual.Value == 0 && anterior.Value >= 2;
        return new HostSignal(now, zeradas ? HostSignalKind.VssDeleted : HostSignalKind.VssReduced, _server,
            $"{removidas} cópia(s) de sombra removida(s) — de {anterior} para {atual}");
    }

    /// <summary>
    /// Reinicia a linha de base sem gerar sinal. Usado quando o próprio produto sabe que a queda é
    /// legítima (ex.: rotação agendada informada pelo admin).
    /// </summary>
    public void Rebaseline(int atual) => _anterior = atual;
}

/// <summary>
/// Converte falha repetida de leitura em sinal visível. Um coletor que falha em silêncio é pior
/// que um coletor ausente: o painel mostra "tudo calmo" enquanto o agente está cego — e cegar o
/// sensor é exatamente o que um EDR killer faria antes de agir.
/// </summary>
public static class SensorHealth
{
    /// <summary>Falhas seguidas antes de admitir que há um problema (evita ruído por falha isolada).</summary>
    public const int FailureThreshold = 3;

    /// <param name="consecutiveFailures">Falhas seguidas do coletor de eventos.</param>
    public static HostSignal? Evaluate(int consecutiveFailures, string server, DateTime now) =>
        consecutiveFailures >= FailureThreshold
            ? new HostSignal(now, HostSignalKind.AgentTamper, server,
                $"O coletor de eventos falhou {consecutiveFailures} vezes seguidas — o agente pode estar cego")
            : null;
}
