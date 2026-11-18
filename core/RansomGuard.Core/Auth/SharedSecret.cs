using System.Security.Cryptography;
using System.Text;

namespace RansomGuard.Core.Auth;

/// <summary>
/// Verificação de um **segredo compartilhado** — o que protege a ingestão do agente
/// (<c>/api/ingest</c>), que é máquina-para-máquina e não usa cookie de navegador.
///
/// Decisões:
/// <list type="bullet">
///   <item><b>Opt-in.</b> Painel sem segredo configurado → aceita qualquer um (não quebra o pacote
///   0.2.0 já no ar). Configurado → exige o cabeçalho, senão recusa.</item>
///   <item><b>Tempo constante.</b> A comparação não vaza, pelo tempo de resposta, quantos bytes
///   bateram — senão um atacante adivinha o segredo byte a byte.</item>
/// </list>
///
/// Lógica pura e sem estado; o "de onde vem o cabeçalho" é do painel.
/// </summary>
public static class SharedSecret
{
    /// <summary>
    /// A requisição está autorizada?
    /// </summary>
    /// <param name="configured">Segredo esperado (do painel). Vazio/null = proteção desligada.</param>
    /// <param name="presented">Segredo apresentado no cabeçalho pela requisição.</param>
    public static bool IsAuthorized(string? configured, string? presented)
    {
        // Proteção desligada: aceita tudo (compatibilidade com quem não configurou).
        if (string.IsNullOrEmpty(configured)) return true;

        // Proteção ligada, mas nada apresentado: recusa.
        if (string.IsNullOrEmpty(presented)) return false;

        // Comparação em tempo constante sobre os bytes UTF-8.
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(configured),
            Encoding.UTF8.GetBytes(presented));
    }

    /// <summary>true se o painel exige token (há segredo configurado). Só para a UI/log avisarem.</summary>
    public static bool IsProtectionEnabled(string? configured) => !string.IsNullOrEmpty(configured);
}
