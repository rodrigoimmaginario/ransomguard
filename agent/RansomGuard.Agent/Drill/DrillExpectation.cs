namespace RansomGuard.Agent.Drill;

/// <summary>
/// Traduz um plano de ensaio no que o produto **deveria** detectar. Sem essa tradução, o operador
/// vê arquivos mudando e não sabe o que esperar no painel — e "não sei o que era para acontecer" é
/// indistinguível de "o produto falhou". Lógica pura, para o texto ser testável.
/// </summary>
public static class DrillExpectation
{
    /// <summary>Frases do que conferir no painel, na ordem de importância para a validação.</summary>
    public static IReadOnlyList<string> ForPlan(IReadOnlyList<DrillAction> plan)
    {
        var linhas = new List<string>();

        var canarios = plan.Count(a => a.Kind == "canário");
        var reescritas = plan.Count(a => a.Kind == "reescrita");
        var renomeacoes = plan.Count(a => a.Kind == "renomeação");
        var bilhete = plan.Any(a => a.Kind == "bilhete de resgate");

        // O canário é o sinal de maior confiança — se houver, é o primeiro a conferir.
        if (canarios > 0)
            linhas.Add($"Incidente de ALTA confiança: {canarios} canário(s) tocado(s). " +
                       "Este é o sinal que dispara a contenção quando o modo é Block.");

        if (reescritas > 0)
            linhas.Add($"{reescritas} arquivo(s) reescrito(s) com extensão {AttackDrill.EncryptedExtension} — " +
                       "sinal de volume + troca de extensão conhecida.");

        if (renomeacoes > 0)
            linhas.Add($"{renomeacoes} renomeação(ões) em massa — o padrão mais comum de ransomware.");

        if (plan.Any(a => a.Kind == "cópia cifrada"))
            linhas.Add("Arquivos gravados com extensão nova e originais apagados — troca de extensão observada nas duas pontas.");
        if (plan.Any(a => a.Kind == "regravação"))
            linhas.Add($"{plan.Count(a => a.Kind == "regravação")} arquivo(s) regravado(s) no lugar, sem mudar o nome — só volume e ritmo denunciam.");
        if (plan.Count(a => a.Kind == "exclusão") is > 0 and var apagados && !plan.Any(a => a.Kind == "cópia cifrada"))
            linhas.Add($"{apagados} arquivo(s) apagado(s) — exclusão em massa.");
        if (plan.Any(a => a.Kind == "leitura"))
            linhas.Add($"{plan.Count(a => a.Kind == "leitura")} arquivo(s) lido(s) — leitura em massa por sessão remota.");

        if (bilhete)
            linhas.Add($"Bilhete de resgate '{AttackDrill.RansomNoteName}' criado — " +
                       "casa com o catálogo e (num file server) é bloqueado pelo FSRM.");

        if (linhas.Count == 0)
            linhas.Add("Nada a detectar: o plano está vazio (a pasta pode não ter arquivos ou canários).");
        else
            linhas.Add("Origem esperada: LOCAL (::1) — este ensaio roda na própria máquina. " +
                       "A atribuição por IP remoto só aparece num ataque vindo de outra máquina.");

        return linhas;
    }
}
