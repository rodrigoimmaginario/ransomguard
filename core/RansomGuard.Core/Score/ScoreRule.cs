namespace RansomGuard.Core.Score;

/// <summary>Categorias de risco (espelham a análise de mercado/tecnologia).</summary>
public enum ScoreCategory
{
    SmbSurface,
    ShareExposure,
    Resilience,
    Detection,
    Identity,
    OsHygiene
}

/// <summary>Severidade de um achado — combinada com o peso na priorização.</summary>
public enum Severity
{
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// <summary>
/// Uma checagem de postura. Se <see cref="IsViolated"/> retorna true para o snapshot, o servidor
/// perde <see cref="Weight"/> pontos e o achado entra na lista de correções. Cada regra carrega a
/// premissa de ataque que endereça e a correção acionável — é o que vira a linha do relatório.
///
/// Regras vivem em código na fatia 1; migram para o catálogo assinado na fatia 3 (pesos ajustáveis
/// sem recompilar).
/// </summary>
public sealed record ScoreRule(
    string Id,
    ScoreCategory Category,
    Severity Severity,
    int Weight,
    string Title,
    string AttackPremise,
    string Fix,
    Func<PostureSnapshot, bool> IsViolated);

/// <summary>Um achado: a regra violada por um servidor específico.</summary>
public sealed record Finding(string Server, ScoreRule Rule)
{
    /// <summary>Prioridade = peso × severidade. Ordena a lista de correções.</summary>
    public int Priority => Rule.Weight * (int)Rule.Severity;
}
