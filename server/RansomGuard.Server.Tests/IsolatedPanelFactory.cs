using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace RansomGuard.Server.Tests;

/// <summary>
/// Painel inteiro em processo, com banco e chave da instalação em diretório temporário próprio — duas
/// classes de teste podem subir o painel em paralelo sem disputar o mesmo arquivo SQLite.
/// </summary>
public sealed class IsolatedPanelFactory : WebApplicationFactory<Program>
{
    private readonly Dictionary<string, RansomGuard.Core.Auth.AgentKey> _agentKeys = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Cliente HTTP de um AGENTE enrolado (B1): enrola o servidor na primeira vez e assina cada lote enviado a
    /// <c>/api/ingest</c> com a chave dele, como o agente real faz.
    /// </summary>
    public HttpClient CreateAgentClient(string server)
    {
        RansomGuard.Core.Auth.AgentKey key;
        lock (_agentKeys)
        {
            if (!_agentKeys.TryGetValue(server, out key!))
            {
                key = RansomGuard.Core.Auth.AgentKey.Generate();
                using var scope = Services.CreateScope();
                var agents = scope.ServiceProvider.GetRequiredService<RansomGuard.Server.Agents.AgentEnrollmentService>();
                var token = agents.CreateTokenAsync(1, TimeSpan.FromHours(1), "teste", DateTime.UtcNow).GetAwaiter().GetResult();
                var outcome = agents.EnrollAsync(token, server, key.PublicKeyBase64, "teste", DateTime.UtcNow).GetAwaiter().GetResult();
                if (outcome != RansomGuard.Server.Agents.EnrollOutcome.Enrolled) throw new InvalidOperationException($"enrolamento de {server}: {outcome}");
                _agentKeys[server] = key;
            }
        }
        return CreateDefaultClient(new SigningHandler(server, key));
    }

    private sealed class SigningHandler(string server, RansomGuard.Core.Auth.AgentKey key) : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.Content is not null && request.RequestUri?.AbsolutePath == "/api/ingest")
            {
                var body = await request.Content.ReadAsByteArrayAsync(ct);
                var content = new ByteArrayContent(body);
                content.Headers.ContentType = new("application/json");
                request.Content = content;
                var timestamp = RansomGuard.Core.Auth.BatchSignature.Timestamp(DateTime.UtcNow);
                request.Headers.Add(RansomGuard.Core.Auth.BatchSignature.AgentHeader, server);
                request.Headers.Add(RansomGuard.Core.Auth.BatchSignature.TimestampHeader, timestamp);
                request.Headers.Add(RansomGuard.Core.Auth.BatchSignature.SignatureHeader, RansomGuard.Core.Auth.BatchSignature.Sign(key, server, timestamp, body));
            }
            return await base.SendAsync(request, ct);
        }
    }
    public string SecretsPath => Path.Combine(_dir, "install-secrets.json");
    /// <summary>Pasta de dados desta instância (banco, chave, segredos, cache do catálogo, token de setup).</summary>
    public string DataDir => _dir;
    /// <summary>Token de primeira execução — os segredos em disco são protegidos (B2), então vem do próprio painel.</summary>
    public string SetupToken => Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions
        .GetRequiredService<RansomGuard.Server.Security.InstallSecrets>(Services).SetupToken;
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rg-panel-" + Guid.NewGuid().ToString("N"));

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        Directory.CreateDirectory(_dir);
        builder.UseSetting("Panel:DataDir", _dir);
        builder.UseSetting("Database:Path", Path.Combine(_dir, "ransomguard.db"));
        builder.UseSetting("InstallKey:Path", Path.Combine(_dir, "install-key.json"));
        builder.UseSetting("InstallSecrets:Path", Path.Combine(_dir, "install-secrets.json"));
        builder.UseSetting("Panel:Https", "false");
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }
}
