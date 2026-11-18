namespace RansomGuard.Core.Fsrm;

/// <param name="Ok">O catálogo é seguro de aplicar?</param>
/// <param name="Reason">Motivo da recusa (vazio quando Ok).</param>
public sealed record CatalogPolicyResult(bool Ok, string Reason = "")
{
    public static CatalogPolicyResult Pass() => new(true);
    public static CatalogPolicyResult Reject(string reason) => new(false, reason);
}

/// <summary>
/// F18a — validação **semântica** do catálogo, depois da assinatura. A verificação criptográfica
/// (<see cref="Catalog.CatalogVerifier"/>) garante que a lista veio do owner e não regrediu; a
/// policy garante que a lista é **segura de aplicar** num file server.
///
/// Por que existir: a assinatura não impede o próprio owner de assinar, por engano, um catálogo
/// vazio (que cegaria o produto) ou com curinga universal `*` (que faria o FSRM bloquear arquivo
/// de trabalho legítimo — o falso positivo mais caro). A policy é a rede que pega esse erro antes
/// de a lista virar file screen. Lógica pura e determinística.
/// </summary>
public static class CatalogPolicy
{
    /// <summary>Teto de padrões — um catálogo absurdamente grande é sinal de erro/abuso, não de defesa.</summary>
    public const int MaxPatterns = 2_000;

    /// <summary>Curingas largos demais: pegariam arquivo legítimo no file screen.</summary>
    private static readonly string[] UniversalWildcards = { "*", "*.*", "*.", "*.???", "?.*" };

    public static CatalogPolicyResult Check(RansomwareCatalog catalog)
    {
        // Versão >= 1: a 0 é reservada à semente compilada, que nunca é "publicada".
        if (catalog.Version < 1)
            return CatalogPolicyResult.Reject($"Versão inválida ({catalog.Version}); catálogo publicado começa em 1.");

        var patterns = catalog.Patterns ?? Array.Empty<string>();
        if (patterns.Count == 0)
            return CatalogPolicyResult.Reject("Catálogo sem padrões — aplicá-lo cegaria a proteção.");

        if (patterns.Count > MaxPatterns)
            return CatalogPolicyResult.Reject($"Catálogo com {patterns.Count} padrões excede o teto de {MaxPatterns}.");

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in patterns)
        {
            var p = (raw ?? "").Trim();
            if (p.Length == 0)
                return CatalogPolicyResult.Reject("Padrão vazio no catálogo.");

            if (UniversalWildcards.Contains(p, StringComparer.OrdinalIgnoreCase))
                return CatalogPolicyResult.Reject(
                    $"Padrão largo demais ('{p}'): bloquearia arquivo legítimo no FSRM.");

            if (!seen.Add(p))
                return CatalogPolicyResult.Reject($"Padrão duplicado ('{p}').");
        }

        // G7: notas de resgate — só nome de arquivo com curinga; nada que pareça caminho/comando.
        foreach (var raw in catalog.NotePatterns ?? Array.Empty<string>())
        {
            var n = (raw ?? "").Trim();
            if (n.Length < 4 || n.Length > 80 || n.Contains('\\') || n.Contains('/') || n.Contains(';') || n.Contains('|') || n.Contains('$'))
                return CatalogPolicyResult.Reject($"Padrão de nota inválido ('{n}').");
            if (n.Trim('*') .Length < 3)
                return CatalogPolicyResult.Reject($"Padrão de nota largo demais ('{n}'): casaria arquivo legítimo.");
        }

        // G7: afinação — faixas que não cegam nem ensurdecem o produto.
        if (catalog.Tuning is { } t)
        {
            if (t.MassThreshold is < 10 or > 10_000) return CatalogPolicyResult.Reject("tuning.massThreshold fora da faixa 10–10000.");
            if (t.RollingWindowThreshold is < 20 or > 50_000) return CatalogPolicyResult.Reject("tuning.rollingWindowThreshold fora da faixa 20–50000.");
            if (t.SlowThreshold is < 50 or > 100_000) return CatalogPolicyResult.Reject("tuning.slowThreshold fora da faixa 50–100000.");
            if (t.ReadThreshold is < 100 or > 1_000_000) return CatalogPolicyResult.Reject("tuning.readThreshold fora da faixa 100–1000000.");
            if (t.KnownExtensionThreshold is < 1 or > 1_000) return CatalogPolicyResult.Reject("tuning.knownExtensionThreshold fora da faixa 1–1000.");
            if (t.MinNoteDirectories is < 1 or > 100) return CatalogPolicyResult.Reject("tuning.minNoteDirectories fora da faixa 1–100.");
        }

        return CatalogPolicyResult.Pass();
    }
}
