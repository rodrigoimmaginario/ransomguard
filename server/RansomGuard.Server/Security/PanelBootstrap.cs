using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace RansomGuard.Server.Security;

/// <summary>
/// F39/F40 — segredos da instalação do painel, criados uma vez no primeiro boot e guardados fora do banco:
/// token de primeira execução (obrigatório no /setup até existir conta)
/// e o certificado TLS autoassinado (PFX + senha). O arquivo fica na pasta de dados do painel, protegido (B2).
/// </summary>
public sealed record InstallSecrets
{
    /// <summary>Não é mais usado (B1: cada agente tem a própria chave). Fica só para ler arquivos de versões anteriores.</summary>
    public string IngestSecret { get; init; } = "";
    public string SetupToken { get; init; } = "";
    public string CertificatePfxBase64 { get; init; } = "";
    public string CertificatePassword { get; init; } = "";
    public string CertificateThumbprint { get; init; } = "";
    public DateTime CreatedAt { get; init; }
}

public sealed class InstallSecretsStore(string path)
{
    private InstallSecrets? _cached;

    public InstallSecrets GetOrCreate(string hostName, DateTime now)
    {
        if (_cached is not null) return _cached;
        // Arquivo que existe e não abre lança aqui: nunca vira "primeira execução" com segredos novos.
        if (ProtectedFile.ReadAndSeal(path) is { } existing)
        {
            _cached = JsonSerializer.Deserialize<InstallSecrets>(existing) ?? throw new InvalidDataException("install-secrets inválido");
            return _cached;
        }
        var (pfx, password, thumb) = SelfSignedCertificate.Create(hostName, now);
        _cached = new InstallSecrets
        {
            SetupToken = Token(16),
            CertificatePfxBase64 = Convert.ToBase64String(pfx),
            CertificatePassword = password,
            CertificateThumbprint = thumb,
            CreatedAt = now
        };
        ProtectedFile.Write(path, JsonSerializer.Serialize(_cached, new JsonSerializerOptions { WriteIndented = true }));
        return _cached;
    }

    public X509Certificate2 LoadCertificate(InstallSecrets s) =>
        X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(s.CertificatePfxBase64), s.CertificatePassword, X509KeyStorageFlags.Exportable);

    /// <summary>Token URL-safe (base64url) com n bytes de entropia.</summary>
    public static string Token(int bytes) =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>Certificado TLS autoassinado do painel (RSA 2048, 5 anos, SAN = host + localhost).</summary>
public static class SelfSignedCertificate
{
    public static (byte[] Pfx, string Password, string ThumbprintSha256) Create(string hostName, DateTime now)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={hostName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(hostName); san.AddDnsName("localhost"); san.AddIpAddress(System.Net.IPAddress.Loopback);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));   // serverAuth
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        using var cert = req.CreateSelfSigned(now.AddMinutes(-5), now.AddYears(5));
        var password = InstallSecretsStore.Token(24);
        return (cert.Export(X509ContentType.Pfx, password), password, Thumbprint(cert));
    }

    /// <summary>SHA-256 do certificado em hexa maiúsculo — o que o agente fixa (TOFU ou configuração).</summary>
    public static string Thumbprint(X509Certificate2 cert) => Convert.ToHexString(SHA256.HashData(cert.RawData));
}

/// <summary>F40 — cabeçalhos de segurança do painel e política de cookie.</summary>
public static class SecurityHeaders
{
    public static IApplicationBuilder UseRansomGuardSecurityHeaders(this IApplicationBuilder app) =>
        app.Use(async (ctx, next) =>
        {
            var h = ctx.Response.Headers;
            h["X-Content-Type-Options"] = "nosniff";
            h["X-Frame-Options"] = "DENY";
            h["Referrer-Policy"] = "no-referrer";
            h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
            // Blazor Server precisa de scripts e estilos próprios (inline em alguns pontos); o que fecha é frame/base/object.
            h["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'";
            if (ctx.Request.IsHttps) h["Strict-Transport-Security"] = "max-age=31536000";
            await next();
        });
}

/// <summary>F40 — limites da ingestão: lote grande demais é recusado antes de tocar o banco.</summary>
public static class IngestLimits
{
    public const int MaxEventsPerBatch = 5_000;
    public const int MaxIncidentsPerBatch = 200;
    public const long MaxBodyBytes = 8L * 1024 * 1024;

    public static string? Validate(int events, int incidents) =>
        events > MaxEventsPerBatch ? $"lote com {events} eventos excede o máximo de {MaxEventsPerBatch}"
        : incidents > MaxIncidentsPerBatch ? $"lote com {incidents} incidentes excede o máximo de {MaxIncidentsPerBatch}"
        : null;
}
