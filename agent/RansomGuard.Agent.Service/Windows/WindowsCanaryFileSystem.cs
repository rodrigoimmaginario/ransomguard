using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using RansomGuard.Agent.Protection;

namespace RansomGuard.Agent.Service.Windows;

/// <summary>
/// Efetor real de disco do plantio. Fino de propósito: toda a decisão (o que plantar, o que não
/// tocar, o que é idempotente) vive no <see cref="CanaryPlanter"/>, que é testável.
///
/// Os canários nascem <b>Hidden + System</b>: o usuário final não os vê no Explorer, o que evita
/// tanto a pergunta "que arquivo é esse?" quanto a chance de alguém apagá-los por engano. Quem
/// varre a pasta programaticamente — que é o caso do ransomware — continua enxergando.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsCanaryFileSystem : ICanaryFileSystem
{
    public bool DirectoryExists(string path) => Directory.Exists(path);

    public IReadOnlyList<string> ListFiles(string path) =>
        Directory.EnumerateFiles(path).Select(Path.GetFileName).OfType<string>().ToList();

    // G1: subpastas para canários densos. Pontos de reanálise/sistema e links são pulados — nunca seguimos reparse points
    // (um junction para fora do share levaria canário para onde o admin não pediu).
    public IReadOnlyList<string> ListDirectories(string path) =>
        new DirectoryInfo(path).EnumerateDirectories()
            .Where(d => !d.Attributes.HasFlag(FileAttributes.ReparsePoint) && !d.Attributes.HasFlag(FileAttributes.System))
            .Select(d => d.FullName).ToList();

    public void WriteCanary(string fullPath, string content)
    {
        File.WriteAllText(fullPath, content);
        File.SetAttributes(fullPath, FileAttributes.Hidden | FileAttributes.System);
    }

    public void WriteCanary(string fullPath, byte[] content)
    {
        File.WriteAllBytes(fullPath, content);
        File.SetAttributes(fullPath, FileAttributes.Hidden | FileAttributes.System);
    }

    /// <summary>
    /// B4: tamanho exato + os primeiros 4 KB. O tamanho já descarta quase todo arquivo de cliente sem ler nada, e 4 KB
    /// de bytes que só a semente da instalação reproduz não coincidem por acaso — sem reler o canário inteiro a cada
    /// reaplicação em centenas de pastas.
    /// </summary>
    public bool ContentEquals(string fullPath, byte[] expected)
    {
        try
        {
            var info = new FileInfo(fullPath);
            if (!info.Exists || info.Length != expected.Length) return false;
            var head = new byte[Math.Min(4096, expected.Length)];
            using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            stream.ReadExactly(head);
            return head.AsSpan().SequenceEqual(expected.AsSpan(0, head.Length));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>O que se audita no canário: gravar, acrescentar e apagar/renomear — por qualquer conta, quando dá certo.</summary>
    private const FileSystemRights Audited = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete;

    /// <summary>
    /// D4: regra de auditoria (SACL) no próprio arquivo. Exige o privilégio de segurança, que o serviço tem como SYSTEM;
    /// sem ele a chamada lança e o plantio registra o canário como "sem auditoria".
    /// </summary>
    public void EnsureAudited(string fullPath)
    {
        var file = new FileInfo(fullPath);
        var security = file.GetAccessControl(AccessControlSections.Audit);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

        foreach (FileSystemAuditRule rule in security.GetAuditRules(true, true, typeof(SecurityIdentifier)))
            if (rule.IdentityReference.Equals(everyone) && rule.AuditFlags.HasFlag(AuditFlags.Success)
                && (rule.FileSystemRights & Audited) == Audited)
                return;   // já auditado: não regrava nada

        security.AddAuditRule(new FileSystemAuditRule(everyone, Audited, AuditFlags.Success));
        file.SetAccessControl(security);
    }

    public void Delete(string fullPath)
    {
        // Hidden/System impede o File.Delete direto em alguns caminhos; limpa os atributos antes.
        if (File.Exists(fullPath)) File.SetAttributes(fullPath, FileAttributes.Normal);
        File.Delete(fullPath);
    }
}
