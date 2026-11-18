using System.Text.Json;
using RansomGuard.Agent.Catalog;

namespace RansomGuard.Agent.Service.Windows;

/// <summary>
/// Persiste o último catálogo assinado bom e a maior versão aceita em <c>%ProgramData%</c>, para o
/// anti-rollback sobreviver a reinício do serviço e à atualização do MSI.
///
/// Escrita atômica: grava num arquivo temporário e renomeia por cima. Uma queda de energia no meio
/// da gravação não pode deixar um estado parcial que o coordenador leia como catálogo válido — daí
/// o rename, que é atômico no NTFS. Leitura ilegível é tratada como "sem catálogo" (o coordenador
/// cai na semente), nunca como erro fatal.
/// </summary>
public sealed class FileCatalogStore : ICatalogStore
{
    private readonly string _dir;
    private string PathJson => System.IO.Path.Combine(_dir, "catalog.json");
    private string PathSig => System.IO.Path.Combine(_dir, "catalog.json.minisig");
    private string PathVersion => System.IO.Path.Combine(_dir, "catalog.version");

    public FileCatalogStore(string? dir = null)
    {
        _dir = dir ?? System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "RansomGuard", "catalog");
    }

    public CatalogArtifact? Load()
    {
        try
        {
            if (!File.Exists(PathJson) || !File.Exists(PathSig)) return null;
            return new CatalogArtifact(File.ReadAllText(PathJson), File.ReadAllText(PathSig));
        }
        catch
        {
            return null;   // ilegível = sem catálogo; o coordenador usa a semente
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

    public void Save(CatalogArtifact artifact, int version)
    {
        Directory.CreateDirectory(_dir);
        AtomicWrite(PathJson, artifact.Json);
        AtomicWrite(PathSig, artifact.Signature);
        AtomicWrite(PathVersion, version.ToString());
    }

    /// <summary>Grava em .tmp e renomeia por cima — o leitor nunca vê um arquivo pela metade.</summary>
    private static void AtomicWrite(string path, string content)
    {
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, content);
        File.Move(tmp, path, overwrite: true);
    }
}
