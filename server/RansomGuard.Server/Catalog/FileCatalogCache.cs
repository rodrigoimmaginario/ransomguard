namespace RansomGuard.Server.Catalog;

/// <summary>
/// O cache do relay: os bytes que o painel serve ao agente em `/api/catalog/...`. Vive em
/// <c>catalog-cache/</c> na raiz de conteúdo do painel — o mesmo diretório que o endpoint lê.
///
/// Escrita atômica (grava .tmp e renomeia por cima): uma queda no meio da gravação não deixa o
/// agente baixar um arquivo pela metade. Leitura ilegível é "sem cache" (o relay responde 404 e o
/// agente segue na semente), nunca erro fatal.
/// </summary>
public sealed class FileCatalogCache : ICatalogCache
{
    private readonly string _dir;
    private string PathJson => Path.Combine(_dir, "catalog.json");
    private string PathSig => Path.Combine(_dir, "catalog.json.minisig");
    private string PathVersion => Path.Combine(_dir, "catalog.version");

    public FileCatalogCache(string dir) => _dir = dir;

    public CatalogBytes? Load()
    {
        try
        {
            if (!File.Exists(PathJson) || !File.Exists(PathSig)) return null;
            return new CatalogBytes(File.ReadAllText(PathJson), File.ReadAllText(PathSig));
        }
        catch
        {
            return null;
        }
    }

    public int LoadVersion()
    {
        try
        {
            return File.Exists(PathVersion) && int.TryParse(File.ReadAllText(PathVersion), out var v) ? v : 0;
        }
        catch
        {
            return 0;
        }
    }

    public void Save(CatalogBytes bytes, int version)
    {
        Directory.CreateDirectory(_dir);
        AtomicWrite(PathJson, bytes.Json);
        AtomicWrite(PathSig, bytes.Signature);
        AtomicWrite(PathVersion, version.ToString());
    }

    private static void AtomicWrite(string path, string content)
    {
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, content);
        File.Move(tmp, path, overwrite: true);
    }
}
