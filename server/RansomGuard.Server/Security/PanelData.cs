
namespace RansomGuard.Server.Security;

/// <summary>
/// A4 — onde o painel guarda o que é dele: banco, chave da instalação, segredos, cache do catálogo.
///
/// Instalado, tudo fica em <c>%ProgramData%\RansomGuard\Painel</c>: a pasta do executável (Program Files) é só de
/// leitura para a conta do serviço, e segredo não mora ao lado de binário. Em desenvolvimento continua na pasta do
/// projeto. <c>Panel:DataDir</c> escolhe outra pasta; os caminhos individuais (<c>Database:Path</c>,
/// <c>InstallKey:Path</c>, <c>InstallSecrets:Path</c>) continuam valendo por cima.
/// </summary>
/// <param name="Managed">A pasta é do painel (e não a do projeto): ele a restringe na partida.</param>
public sealed record PanelPaths(
    string DataDirectory, string Database, string InstallKey, string InstallSecrets, string CatalogCache, string SetupToken, bool Managed)
{
    public const string SetupTokenFileName = "token-de-setup.txt";

    public static PanelPaths Resolve(IConfiguration config, string contentRoot, bool development, string? programData = null)
    {
        var configured = config["Panel:DataDir"];
        var managed = !string.IsNullOrWhiteSpace(configured) || !development;
        var dir = !string.IsNullOrWhiteSpace(configured) ? configured
            : development ? contentRoot
            : Path.Combine(programData ?? Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RansomGuard", "Painel");

        var secrets = config["InstallSecrets:Path"] ?? Path.Combine(dir, "install-secrets.json");
        return new PanelPaths(
            DataDirectory: dir,
            Database: config["Database:Path"] ?? Path.Combine(dir, "ransomguard.db"),
            InstallKey: config["InstallKey:Path"] ?? Path.Combine(dir, "install-key.json"),
            InstallSecrets: secrets,
            CatalogCache: Path.Combine(dir, "catalog-cache"),
            SetupToken: Path.Combine(Path.GetDirectoryName(secrets) ?? dir, SetupTokenFileName),
            Managed: managed);
    }
}

/// <summary>
/// B2 — arquivos de segredo do painel (chave da instalação, segredos), protegidos com DPAPI de máquina. A mecânica
/// está em <see cref="RansomGuard.Core.Security.ProtectedFile"/>; aqui fica só o propósito do painel.
/// </summary>
public static class ProtectedFile
{
    private const string Purpose = "RansomGuard.Panel.v1";

    public static bool IsProtected(string path) => RansomGuard.Core.Security.ProtectedFile.IsProtected(path);
    public static string? Read(string path) => RansomGuard.Core.Security.ProtectedFile.Read(path, Purpose);
    public static string? ReadAndSeal(string path) => RansomGuard.Core.Security.ProtectedFile.ReadAndSeal(path, Purpose);
    public static void Write(string path, string content) => RansomGuard.Core.Security.ProtectedFile.Write(path, content, Purpose);
}

/// <summary>
/// Token de primeira execução em arquivo, na pasta de dados (restrita a administradores). Existe só enquanto não há
/// conta de dono. Como serviço, o painel não tem console, e o log de Aplicativo do Windows é legível por qualquer
/// usuário do servidor — por isso o token não vai para o log.
/// </summary>
public static class SetupTokenFile
{
    public static void Sync(string path, string token, bool accountExists)
    {
        if (accountExists)
        {
            if (File.Exists(path)) File.Delete(path);
            return;
        }
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        File.WriteAllText(path,
            "RansomGuard - token de primeira execucao" + Environment.NewLine +
            "Informe na tela /setup para criar a conta de administrador. Este arquivo e apagado quando a conta e criada." + Environment.NewLine +
            Environment.NewLine + token + Environment.NewLine);
    }
}
