namespace RansomGuard.Core.Fsrm;

/// <summary>
/// R7 — lê a saída do <c>Get-FsrmFileScreen</c> e decide se o file screen do RansomGuard está
/// aplicado. Antes o Score checava só se a *role* do FSRM estava instalada — um servidor com FSRM
/// mas sem o screen do produto passava por protegido, inflando a nota que é a porta de entrada
/// do produto. Aqui a pergunta certa: existe um screen cujo grupo é o nosso?
///
/// Tri-estado: <c>null</c> quando não deu para ler (comando ausente, sem permissão) — o Score trata
/// como "não verificado", nunca chuta. Lógica pura (texto → resposta), testável sem file server.
/// </summary>
public static class FsrmScreenReader
{
    /// <summary>Marca de erro do PowerShell: distingue "sem screen" de "não consegui perguntar".</summary>
    private static readonly string[] ErrorMarkers =
    {
        "não é reconhecido", "nao e reconhecido", "is not recognized",
        "CommandNotFoundException", "Access is denied", "Acesso negado"
    };

    /// <returns>
    /// <c>true</c> se há file screen aplicado com o grupo do RansomGuard; <c>false</c> se a saída é
    /// legível mas não tem o screen; <c>null</c> se não deu para ler.
    /// </returns>
    public static bool? TryRead(string? getFsrmFileScreenOutput)
    {
        if (getFsrmFileScreenOutput is null) return null;

        if (ErrorMarkers.Any(m => getFsrmFileScreenOutput.Contains(m, StringComparison.OrdinalIgnoreCase)))
            return null;

        var output = getFsrmFileScreenOutput.Trim();
        if (output.Length == 0) return false;   // legível e vazio = nenhum screen aplicado

        // O file group do produto é a assinatura: um screen de outro grupo não é o nosso.
        return output.Contains(FsrmPlan.FileGroupName, StringComparison.OrdinalIgnoreCase);
    }
}
