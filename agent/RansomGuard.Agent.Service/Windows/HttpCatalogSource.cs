using RansomGuard.Agent.Catalog;

namespace RansomGuard.Agent.Service.Windows;

/// <summary>
/// Busca o catálogo assinado no PAINEL (relay), não na internet — preserva a promessa de que o
/// agente só fala com o painel self-hosted. O painel é quem vai à origem pública, verifica e faz
/// cache; o agente pega os bytes exatos e verifica de novo por conta própria (defesa em
/// profundidade, no <c>CatalogCoordinator</c>).
///
/// Limite de tamanho e timeout: um relay comprometido ou defeituoso não pode fazer o agente baixar
/// um corpo gigante. Falha de rede vira <c>null</c> (o coordenador mantém o último bom), nunca
/// exceção que suba ao ciclo.
/// </summary>
public sealed class HttpCatalogSource : ICatalogSource
{
    private const int MaxBytes = 512 * 1024;   // catálogo é lista de padrões; 512 KB é folga enorme
    private readonly HttpClient _http;
    private readonly ILogger<HttpCatalogSource> _log;

    public HttpCatalogSource(HttpClient http, ILogger<HttpCatalogSource> log)
    {
        _http = http;
        _log = log;
    }

    public async Task<CatalogArtifact?> FetchAsync(CancellationToken ct = default)
    {
        try
        {
            var json = await GetLimitedAsync("/api/catalog/catalog.json", ct);
            var sig = await GetLimitedAsync("/api/catalog/catalog.json.minisig", ct);
            if (json is null || sig is null) return null;
            return new CatalogArtifact(json, sig);
        }
        catch (Exception ex)
        {
            // Aviso, não depuração: um agente que nunca recebe o catálogo assinado precisa aparecer no log.
            _log.LogWarning(ex, "Não foi possível buscar o catálogo no painel (mantém o atual).");
            return null;
        }
    }

    private async Task<string?> GetLimitedAsync(string path, CancellationToken ct)
    {
        using var resp = await _http.GetAsync(path, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!resp.IsSuccessStatusCode) return null;
        if (resp.Content.Headers.ContentLength is > MaxBytes) return null;

        var bytes = await resp.Content.ReadAsByteArrayAsync(ct);
        return bytes.Length > MaxBytes ? null : System.Text.Encoding.UTF8.GetString(bytes);
    }
}
