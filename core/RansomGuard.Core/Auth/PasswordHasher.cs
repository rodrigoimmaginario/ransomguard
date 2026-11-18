using System.Globalization;
using System.Security.Cryptography;

namespace RansomGuard.Core.Auth;

/// <summary>
/// Hash de senha com PBKDF2-HMAC-SHA256 e salt por conta. Formato armazenado:
/// <c>iterações.base64(salt).base64(hash)</c>. O formato anterior, <c>base64(salt).base64(hash)</c> com 100 mil
/// iterações, continua sendo verificado; <see cref="NeedsRehash"/> diz quando regravar (no primeiro login certo).
/// Verificação em **tempo constante** — o tempo de resposta não vaza quantos bytes bateram.
///
/// Lógica pura e sem estado; o "onde guardar" é do painel.
/// </summary>
public static class PasswordHasher
{
    /// <summary>Custo atual (D10): 600 mil iterações, a referência da OWASP para PBKDF2-HMAC-SHA256.</summary>
    public const int CurrentIterations = 600_000;

    private const int LegacyIterations = 100_000, SaltSize = 16, HashSize = 32;
    /// <summary>Teto do que se aceita ler de um valor armazenado: um número absurdo não vira negação de serviço.</summary>
    private const int MaxIterations = 5_000_000;

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, CurrentIterations, HashAlgorithmName.SHA256, HashSize);
        return $"{CurrentIterations.ToString(CultureInfo.InvariantCulture)}.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string password, string stored)
    {
        if (!TryParse(stored, out var iterations, out var salt, out var expected)) return false;
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>O valor armazenado foi gerado com custo menor que o atual (ou é ilegível)?</summary>
    public static bool NeedsRehash(string stored) =>
        !TryParse(stored, out var iterations, out _, out _) || iterations < CurrentIterations;

    private static bool TryParse(string? stored, out int iterations, out byte[] salt, out byte[] hash)
    {
        iterations = 0; salt = hash = Array.Empty<byte>();
        var parts = (stored ?? "").Split('.');
        try
        {
            if (parts.Length == 2)
            {
                iterations = LegacyIterations;
                salt = Convert.FromBase64String(parts[0]);
                hash = Convert.FromBase64String(parts[1]);
            }
            else if (parts.Length == 3
                     && int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out iterations)
                     && iterations is > 0 and <= MaxIterations)
            {
                salt = Convert.FromBase64String(parts[1]);
                hash = Convert.FromBase64String(parts[2]);
            }
            else return false;
        }
        catch (FormatException) { return false; }
        return salt.Length > 0 && hash.Length > 0;
    }
}

/// <summary>
/// Freia tentativas de login por conta/origem. Não trava o admin legítimo (a janela é curta), mas
/// torna o brute force inviável. Uma instância é compartilhada por todas as requisições do painel: o acesso é
/// sincronizado e o que já expirou é descartado, para um atacante que varia o nome de usuário não fazer a memória
/// crescer sem limite.
/// </summary>
public sealed class LoginThrottle
{
    /// <summary>Acima disto, entradas expiradas são descartadas; se ainda sobrar, as que expiram antes saem.</summary>
    public const int MaxTrackedKeys = 10_000;

    private readonly Dictionary<string, (int Fails, DateTime Until)> _state = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private readonly int _maxFails;
    private readonly TimeSpan _lockout;

    public LoginThrottle(int maxFails = 5, TimeSpan? lockout = null)
    {
        _maxFails = maxFails;
        _lockout = lockout ?? TimeSpan.FromMinutes(5);
    }

    public int TrackedKeys { get { lock (_gate) return _state.Count; } }

    /// <summary>Está bloqueado agora?</summary>
    public bool IsLocked(string key, DateTime now)
    {
        lock (_gate) return _state.TryGetValue(key, out var s) && s.Fails >= _maxFails && now < s.Until;
    }

    /// <summary>Registra uma falha; ao atingir o teto, arma o bloqueio.</summary>
    public void RegisterFailure(string key, DateTime now)
    {
        lock (_gate)
        {
            var fails = _state.TryGetValue(key, out var current) ? current.Fails + 1 : 1;
            _state[key] = (fails, now + _lockout);
            if (_state.Count > MaxTrackedKeys) Prune(now);
        }
    }

    /// <summary>Sucesso limpa o histórico daquela chave.</summary>
    public void RegisterSuccess(string key)
    {
        lock (_gate) _state.Remove(key);
    }

    private void Prune(DateTime now)
    {
        foreach (var expired in _state.Where(kv => kv.Value.Until <= now).Select(kv => kv.Key).ToList())
            _state.Remove(expired);
        if (_state.Count <= MaxTrackedKeys) return;
        // Ataque em curso com milhares de chaves ainda válidas: sai primeiro o que expira antes.
        foreach (var oldest in _state.OrderBy(kv => kv.Value.Until).Take(_state.Count - MaxTrackedKeys + MaxTrackedKeys / 10).Select(kv => kv.Key).ToList())
            _state.Remove(oldest);
    }
}
