namespace RansomGuard.Agent.Drill;

/// <summary>
/// Efetor de disco real do ensaio de ataque. Fino de propósito: toda a segurança (marcador,
/// caminhos recusados, confirmação) vive no <see cref="AttackDrill"/>, que é testável. Aqui só há
/// I/O — e este arquivo nunca decide sozinho tocar em nada.
/// </summary>
public sealed class WindowsDrillFileSystem : IDrillFileSystem
{
    public bool DirectoryExists(string path) => Directory.Exists(path);
    public bool FileExists(string fullPath) => File.Exists(fullPath);

    public IReadOnlyList<string> ListFiles(string path) =>
        Directory.EnumerateFiles(path).Select(Path.GetFileName).OfType<string>().ToList();

    public void CreateDirectory(string path) => Directory.CreateDirectory(path);

    public void WriteFile(string fullPath, string content)
    {
        if (!File.Exists(fullPath)) { File.WriteAllText(fullPath, content); return; }
        // Arquivo que já existe é aberto e truncado, como faz quem cifra no lugar — funciona também em arquivo
        // oculto ou de sistema (um canário), que a criação por cima recusaria.
        using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Write, FileShare.Read);
        stream.SetLength(0);
        var bytes = System.Text.Encoding.UTF8.GetBytes(content);
        stream.Write(bytes, 0, bytes.Length);
    }

    public void Move(string from, string to)
    {
        // Canário nasce Hidden+System (F12): sem limpar o atributo, o Move falharia.
        if (File.Exists(from)) File.SetAttributes(from, FileAttributes.Normal);
        File.Move(from, to, overwrite: true);
    }

    public void Touch(string fullPath)
    {
        // Detecção é por ACESSO, não por alteração — abrir para leitura gera o evento 4663/5145
        // sem modificar o conteúdo do canário.
        using var _ = File.Open(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
    }

    public IReadOnlyList<string> ListDirectories(string path) =>
        new DirectoryInfo(path).EnumerateDirectories()
            .Where(d => !d.Attributes.HasFlag(FileAttributes.ReparsePoint))   // nunca segue junção para fora da pasta de ensaio
            .Select(d => d.FullName).ToList();

    public void DeleteFile(string fullPath)
    {
        if (File.Exists(fullPath)) File.SetAttributes(fullPath, FileAttributes.Normal);
        File.Delete(fullPath);
    }

    public void ReadFile(string fullPath)
    {
        using var stream = File.Open(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var buffer = new byte[64 * 1024];
        while (stream.Read(buffer, 0, buffer.Length) > 0) { }
    }

    public bool IsHiddenOrSystem(string fullPath)
    {
        var attributes = File.GetAttributes(fullPath);
        return attributes.HasFlag(FileAttributes.Hidden) || attributes.HasFlag(FileAttributes.System);
    }

    public void DeleteDirectory(string path)
    {
        // Limpa atributos dos ocultos (canários, marcador) antes de apagar a pasta inteira.
        foreach (var f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            File.SetAttributes(f, FileAttributes.Normal);
        Directory.Delete(path, recursive: true);
    }
}
