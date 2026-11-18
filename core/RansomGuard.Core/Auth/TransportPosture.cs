namespace RansomGuard.Core.Auth;

/// <param name="Secure">Transporte endurecido (HTTPS + segredo de ingestão)?</param>
/// <param name="Warnings">Avisos acionáveis quando não está — para log/painel.</param>
public sealed record TransportPostureResult(bool Secure, IReadOnlyList<string> Warnings);

/// <summary>
/// R9 — avalia a postura do canal agente→painel e diz, em português, o que endurecer. O produto
/// **avisa**, não bloqueia: o piloto interno roda em `http` de LAN sem quebrar, mas o operador vê o
/// risco. Para o RC com parceiros, a recomendação (HTTPS + segredo obrigatório) vira empacotamento.
///
/// Lógica pura e sem estado: entra a URL do backend e se há segredo de ingestão; sai a postura.
/// </summary>
public static class TransportPosture
{
    public static TransportPostureResult Evaluate(string? backendUrl, bool enrolled)
    {
        var warnings = new List<string>();
        var isHttps = false;
        var isLoopback = false;

        if (Uri.TryCreate(backendUrl, UriKind.Absolute, out var uri))
        {
            isHttps = uri.Scheme == Uri.UriSchemeHttps;
            isLoopback = uri.IsLoopback;
        }
        else
        {
            warnings.Add("URL do painel inválida — não foi possível confirmar HTTPS.");
        }

        // http em rede real: lote de detecção trafega em claro (espionável/forjável). Loopback não.
        if (!isHttps && !isLoopback && warnings.Count == 0)
            warnings.Add(
                "Canal com o painel em CLARO (http). Numa rede real, os lotes podem ser espionados " +
                "ou forjados — use https:// no painel para o piloto com parceiros.");

        if (!enrolled)
            warnings.Add(
                "Agente ainda NÃO enrolado no painel: os lotes serão recusados até o enrolamento. " +
                "Gere um token na tela Agentes do painel e informe-o na instalação (ENROLLTOKEN).");

        var secure = isHttps && enrolled;
        return new TransportPostureResult(secure, warnings);
    }
}
