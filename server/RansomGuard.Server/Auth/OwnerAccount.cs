namespace RansomGuard.Server.Auth;

/// <summary>
/// A conta única de administração do painel. Linha única (Id = 1). Guarda só o **hash** da senha —
/// nunca a senha. O painel é self-hosted e de um único adm; não há cadastro multiusuário aqui.
/// </summary>
public sealed class OwnerAccount
{
    public int Id { get; set; } = 1;

    /// <summary>Nome de login (livre; o padrão sugerido é "admin").</summary>
    public string Username { get; set; } = "admin";

    /// <summary>Senha em PBKDF2 (base64(salt).base64(hash)). Nunca a senha em claro.</summary>
    public string PasswordHash { get; set; } = "";

    public DateTime CreatedAt { get; set; }
    /// <summary>G8: "admin" (altera) ou "viewer" (só lê). A primeira conta é sempre admin.</summary>
    public string Role { get; set; } = Roles.Admin;
}
