using System.Security.Cryptography;
using System.Text;

namespace RansomGuard.Core.Security;

/// <summary>
/// B2 — arquivo de segredo protegido com DPAPI de máquina (painel: chave da instalação e segredos; agente: a chave
/// da própria identidade).
///
/// O que isso dá e o que não dá: o arquivo copiado para fora do servidor (backup da pasta, imagem de disco, zip
/// montado por engano) não abre em outra máquina. Dentro do servidor, quem impede a leitura é a permissão da pasta —
/// DPAPI de máquina abre para qualquer processo local que alcance o arquivo. As duas barreiras andam juntas.
///
/// Arquivo em texto (versão anterior, ou backup restaurado) é aceito e pode ser regravado protegido. Arquivo
/// protegido que não abre é ERRO (<see cref="InvalidDataException"/>): quem chama decide o que fazer, mas nunca deve
/// confundir isso com "não existe".
/// </summary>
/// <remarks><paramref name="purpose"/> separa os usos: um arquivo do agente não abre como arquivo do painel.</remarks>
public static class ProtectedFile
{
    public const string Prefix = "RGP1:";

    public static bool IsProtected(string path) =>
        File.Exists(path) && File.ReadAllText(path).StartsWith(Prefix, StringComparison.Ordinal);

    /// <summary>Conteúdo em claro; <c>null</c> se o arquivo não existe. Lança <see cref="InvalidDataException"/> se não abre.</summary>
    public static string? Read(string path, string purpose)
    {
        if (!File.Exists(path)) return null;
        var raw = File.ReadAllText(path);
        if (!raw.StartsWith(Prefix, StringComparison.Ordinal)) return raw;   // texto de versão anterior
        try
        {
            var blob = Convert.FromBase64String(raw[Prefix.Length..].Trim());
            return Encoding.UTF8.GetString(Unprotect(blob, purpose));
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new InvalidDataException(
                $"{Path.GetFileName(path)} está protegido e não abre nesta máquina (arquivo de outro servidor, ou alterado). " +
                "O arquivo não foi modificado.", ex);
        }
    }

    /// <summary>Como <see cref="Read"/>; se o arquivo estava em texto, regrava protegido (sem falhar se a pasta for só de leitura).</summary>
    public static string? ReadAndSeal(string path, string purpose)
    {
        var content = Read(path, purpose);
        if (content is not null && !IsProtected(path))
        {
            try { Write(path, content, purpose); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* segue em texto */ }
        }
        return content;
    }

    /// <summary>
    /// Grava protegido, por arquivo temporário + troca: não deixa arquivo pela metade, e o arquivo novo nasce com a
    /// permissão da pasta (um arquivo regravado no lugar manteria a permissão antiga).
    /// </summary>
    public static void Write(string path, string content, string purpose)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Directory.CreateDirectory(dir);
        var temp = Path.Combine(dir, Path.GetFileName(path) + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp");
        try
        {
            File.WriteAllText(temp, Prefix + Convert.ToBase64String(Protect(Encoding.UTF8.GetBytes(content), purpose)));
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    // O produto é Windows; fora dele (desenvolvimento em outro sistema) não há DPAPI e o conteúdo fica em texto.
    private static byte[] Protect(byte[] data, string purpose) =>
        OperatingSystem.IsWindows() ? ProtectedData.Protect(data, Encoding.UTF8.GetBytes(purpose), DataProtectionScope.LocalMachine) : data;

    private static byte[] Unprotect(byte[] blob, string purpose) =>
        OperatingSystem.IsWindows() ? ProtectedData.Unprotect(blob, Encoding.UTF8.GetBytes(purpose), DataProtectionScope.LocalMachine) : blob;
}
