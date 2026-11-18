namespace RansomGuard.Server.Catalog;

/// <summary>
/// Busca o catálogo assinado na ORIGEM pública — arquivos versionados na branch `main` do
/// repositório público do projeto (pasta `list/`), não em `releases/latest` (que serve os MSIs e
/// quebraria). É o único ponto do produto que fala com a internet; o agente só fala com
/// o painel.
///
/// Limite de tamanho e timeout: uma origem defeituosa não pode fazer o painel baixar um corpo
/// gigante. Falha vira <c>null</c> (o sync mantém o cache), nunca exceção que suba ao host.
/// </summary>
public sealed class HttpCatalogOrigin : ICatalogOrigin
{
    /// <summary>Origem padrão (sobreposta por <c>Catalog:OriginUrl</c>).</summary>
    public const string DefaultOriginUrl = "https://raw.githubusercontent.com/rodrigoimmaginario/ransomguard/main/list";

    private const int MaxBytes = 512 * 1024;
    private readonly HttpClient _http;
    private readonly string _jsonUrl;
    private readonly string _sigUrl;

    public HttpCatalogOrigin(HttpClient http, string baseUrl)
    {
        _http = http;
        var root = baseUrl.TrimEnd('/');
        _jsonUrl = $"{root}/catalog.json";
        _sigUrl = $"{root}/catalog.json.minisig";
    }

    public async Task<CatalogBytes?> FetchAsync(CancellationToken ct = default)
    {
        var json = await GetLimitedAsync(_jsonUrl, ct);
        var sig = await GetLimitedAsync(_sigUrl, ct);
        if (json is null || sig is null) return null;
        return new CatalogBytes(json, sig);
    }

    private async Task<string?> GetLimitedAsync(string url, CancellationToken ct)
    {
        using var resp = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!resp.IsSuccessStatusCode) return null;
        if (resp.Content.Headers.ContentLength is > MaxBytes) return null;
        var bytes = await resp.Content.ReadAsByteArrayAsync(ct);
        return bytes.Length > MaxBytes ? null : System.Text.Encoding.UTF8.GetString(bytes);
    }
}
