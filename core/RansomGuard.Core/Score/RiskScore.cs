namespace RansomGuard.Core.Score;

/// <summary>Faixa de risco derivada da nota — dirige a cor/urgência no painel e no relatório.</summary>
public enum RiskBand
{
    Critical, // 0–40
    Attention, // 41–70
    Good       // 71–100
}

/// <summary>Resultado do score de um servidor.</summary>
/// <param name="Server">Servidor avaliado.</param>
/// <param name="Score">Nota 0–100, calculada **sobre o que foi medido** (100 = sem achados).</param>
/// <param name="Band">Faixa de risco.</param>
/// <param name="Findings">Achados, já ordenados por prioridade decrescente.</param>
/// <param name="Unknown">
/// Regras que o agente não conseguiu verificar. Não contam como achado nem como aprovação — o
/// painel as mostra separadamente, para o admin verificar à mão. Ficar em silêncio sobre elas
/// seria pior: a nota pareceria completa sem ser.
/// </param>
public sealed record ServerScore(
    string Server,
    int Score,
    RiskBand Band,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<ScoreRule> Unknown);

/// <summary>Resultado consolidado da rede.</summary>
/// <param name="Score">Nota consolidada 0–100 (média dos servidores, penalizada por gap de cobertura).</param>
/// <param name="Band">Faixa consolidada.</param>
/// <param name="Servers">Score por servidor, do pior para o melhor.</param>
/// <param name="ServersWithoutAgent">Quantos servidores descobertos estão sem agente.</param>
public sealed record NetworkScore(
    int Score,
    RiskBand Band,
    IReadOnlyList<ServerScore> Servers,
    int ServersWithoutAgent);

public static class RiskBands
{
    public static RiskBand Of(int score) => score switch
    {
        <= 40 => RiskBand.Critical,
        <= 70 => RiskBand.Attention,
        _ => RiskBand.Good
    };
}
