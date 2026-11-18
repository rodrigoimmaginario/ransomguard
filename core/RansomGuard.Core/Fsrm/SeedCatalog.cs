namespace RansomGuard.Core.Fsrm;

/// <summary>
/// Catálogo **semente**, compilado no binário. É a lista mínima que o agente usa quando ainda não
/// recebeu um catálogo assinado.
///
/// ⚠️ Isto é um degrau, não o destino. A arquitetura do produto manda a inteligência de detecção
/// morar numa **lista assinada** (minisign/Ed25519, com anti-rollback), verificada pelo
/// <see cref="Catalog.CatalogVerifier"/> — que já existe e está provado. O que falta é o elo de
/// distribuição: publicar o <c>catalog.json</c> assinado e o agente buscá-lo (achado <b>AUD-1</b>
/// da auditoria de 2026-07-26).
///
/// Enquanto esse elo não existe, usar a semente é honesto — o produto protege com o que tem — mas
/// **não deve ser confundido com "catálogo atualizado"**. É por isso que a semente é pequena e
/// conservadora: só extensões e nomes de ransom note amplamente conhecidos, sem curinga arriscado
/// que pudesse bloquear arquivo legítimo do cliente.
/// </summary>
public static class SeedCatalog
{
    /// <summary>
    /// Versão 0: menor que qualquer catálogo assinado real, para o anti-rollback do
    /// <see cref="Catalog.CatalogVerifier"/> sempre aceitar a lista de verdade por cima desta.
    /// </summary>
    public const int Version = 0;

    public static readonly IReadOnlyList<string> Patterns = new[]
    {
        // Extensões deixadas por famílias amplamente documentadas.
        "*.locked", "*.crypted", "*.crypt", "*.encrypted", "*.enc",
        "*.locky", "*.zepto", "*.cerber", "*.crypto",
        "*.wcry", "*.wncry", "*.wannacry",
        "*.crab", "*.gdcb", "*.krab", "*.ryk",
        "*.conti", "*.lockbit", "*.blackcat", "*.akira", "*.play", "*.qilin",
        // Bilhetes de resgate: aparecem cedo, às vezes antes de a criptografia terminar.
        "HOW_TO_DECRYPT*", "HOW_TO_BACK_FILES*", "*_readme.txt",
        "*RECOVER*FILES*", "*DECRYPT*INSTRUCTION*", "*RESTORE*FILES*"
    };

    /// <summary>A semente no mesmo formato do catálogo assinado, para reusar o mesmo caminho de código.</summary>
    public static string Json =>
        "{\"version\":" + Version + ",\"patterns\":[" +
        string.Join(",", Patterns.Select(p => "\"" + p + "\"")) + "]}";

    /// <summary>A semente como <see cref="RansomwareCatalog"/> — o catálogo ativo padrão do agente.</summary>
    public static RansomwareCatalog AsCatalog => new() { Version = Version, Patterns = Patterns };
}
