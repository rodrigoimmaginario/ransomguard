namespace RansomGuard.Core.Score;

/// <summary>
/// Calcula o Score de Risco de Ransomware a partir de retratos de postura. Lógica pura e
/// determinística: aplica o catálogo de regras, produz nota 0–100 por servidor e consolida a rede,
/// com achados priorizados. O gap de cobertura (servidores sem agente) penaliza a nota da rede —
/// empurrando a adoção do agente (sinergia comercial documentada no roadmap).
/// </summary>
public sealed class RiskScoreEngine
{
    private readonly IReadOnlyList<ScoreRule> _rules;
    private readonly int _maxScore;

    public RiskScoreEngine(IReadOnlyList<ScoreRule>? rules = null)
    {
        _rules = rules ?? ScoreRules.Default;
        _maxScore = ScoreRules.MaxScore(_rules);
        if (_maxScore <= 0)
            throw new ArgumentException("Catálogo de regras sem peso.", nameof(rules));
    }

    /// <summary>
    /// Score de um único servidor. Regras listadas em <see cref="PostureSnapshot.UnknownChecks"/>
    /// não são avaliadas: saem do numerador e do denominador, e voltam em
    /// <see cref="ServerScore.Unknown"/>. A nota passa a significar "de tudo que consegui medir,
    /// isto está certo" — em vez de punir o servidor por uma leitura que falhou.
    /// </summary>
    public ServerScore ScoreServer(PostureSnapshot posture)
    {
        var unknown = _rules.Where(r => posture.UnknownChecks.Contains(r.Id)).ToList();
        var avaliadas = _rules.Where(r => !posture.UnknownChecks.Contains(r.Id)).ToList();

        var findings = avaliadas
            .Where(r => r.IsViolated(posture))
            .Select(r => new Finding(posture.Server, r))
            .OrderByDescending(f => f.Priority)
            .ThenBy(f => f.Rule.Id, StringComparer.Ordinal)
            .ToList();

        // Denominador = peso do que foi efetivamente medido. Sem nada medido não existe nota
        // honesta: 0 de cobertura vira 0 de confiança, não 100 por omissão.
        var medido = ScoreRules.MaxScore(avaliadas);
        var lost = findings.Sum(f => f.Rule.Weight);
        var score = medido > 0
            ? (int)Math.Round(100.0 * (medido - lost) / medido, MidpointRounding.AwayFromZero)
            : 0;
        score = Math.Clamp(score, 0, 100);

        return new ServerScore(posture.Server, score, RiskBands.Of(score), findings, unknown);
    }

    /// <summary>
    /// Consolida a rede. <paramref name="discoveredWithoutAgent"/> são servidores encontrados na
    /// varredura mas sem agente: cada um puxa a nota consolidada para baixo (penalidade por
    /// visibilidade cega), pois o que não se mede não se protege.
    /// </summary>
    public NetworkScore ScoreNetwork(
        IEnumerable<PostureSnapshot> postures,
        int discoveredWithoutAgent = 0)
    {
        var servers = postures
            .Select(ScoreServer)
            .OrderBy(s => s.Score)
            .ThenBy(s => s.Server, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (servers.Count == 0 && discoveredWithoutAgent == 0)
            return new NetworkScore(0, RiskBand.Critical, servers, 0);

        var avg = servers.Count > 0 ? servers.Average(s => s.Score) : 0.0;

        // Penalidade por cobertura: fração de servidores sem agente sobre o total conhecido.
        var total = servers.Count + discoveredWithoutAgent;
        var coverage = total > 0 ? (double)servers.Count / total : 0.0;
        var consolidated = (int)Math.Round(avg * coverage, MidpointRounding.AwayFromZero);
        consolidated = Math.Clamp(consolidated, 0, 100);

        return new NetworkScore(
            consolidated, RiskBands.Of(consolidated), servers, discoveredWithoutAgent);
    }
}
