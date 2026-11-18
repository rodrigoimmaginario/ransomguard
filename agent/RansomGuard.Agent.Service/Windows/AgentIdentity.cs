using System.Net;
using System.Net.Http.Json;
using System.Net.NetworkInformation;
using System.Text.Json;
using RansomGuard.Core.Auth;
using RansomGuard.Core.Security;

namespace RansomGuard.Agent.Service.Windows;

/// <summary>
/// B1 — a identidade deste agente: uma chave Ed25519 gerada aqui, guardada protegida na pasta de dados (restrita),
/// e a marca de que o painel já a conhece para este nome de servidor.
/// </summary>
public sealed class AgentIdentity
{
    public const string KeyFileName = "agent-identity.json";
    public const string EnrolledFileName = "agent-enrolled.json";
    private const string Purpose = "RansomGuard.Agent.Identity.v1";

    private sealed record StoredKey(string Seed, DateTime CreatedAt);
    private sealed record StoredEnrollment(string Server, string Fingerprint, DateTime At);

    private readonly string _enrolledPath;
    private readonly ILogger _log;

    public AgentIdentity(string dataDirectory, string server, ILogger log)
    {
        Server = server;
        _log = log;
        _enrolledPath = Path.Combine(dataDirectory, EnrolledFileName);
        Key = LoadOrCreate(Path.Combine(dataDirectory, KeyFileName));
    }

    public string Server { get; }
    public AgentKey Key { get; }

    /// <summary>O painel já recebeu ESTA chave para ESTE nome? (Chave nova ou nome novo = outra identidade.)</summary>
    public bool IsEnrolled
    {
        get
        {
            try
            {
                if (!File.Exists(_enrolledPath)) return false;
                var stored = JsonSerializer.Deserialize<StoredEnrollment>(File.ReadAllText(_enrolledPath));
                return stored is not null && stored.Fingerprint == Key.Fingerprint
                       && string.Equals(stored.Server, Server, StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception) { return false; }
        }
    }

    public void MarkEnrolled()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_enrolledPath)!);
        File.WriteAllText(_enrolledPath, JsonSerializer.Serialize(new StoredEnrollment(Server, Key.Fingerprint, DateTime.UtcNow)));
    }

    public void ClearEnrollment()
    {
        try { if (File.Exists(_enrolledPath)) File.Delete(_enrolledPath); }
        catch (Exception ex) { _log.LogWarning(ex, "Não foi possível apagar a marca de enrolamento."); }
    }

    private AgentKey LoadOrCreate(string path)
    {
        try
        {
            if (ProtectedFile.ReadAndSeal(path, Purpose) is { } existing
                && JsonSerializer.Deserialize<StoredKey>(existing) is { } stored)
                return AgentKey.FromSeed(Convert.FromBase64String(stored.Seed));
        }
        catch (Exception ex) when (ex is InvalidDataException or JsonException or FormatException or ArgumentException)
        {
            // O agente não deixa de proteger o servidor por causa de um arquivo: guarda o ilegível para análise, gera
            // outra chave e fica sem enrolamento — o painel recusa os lotes até o administrador enrolar de novo.
            var aside = path + ".ilegivel-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            try { File.Move(path, aside, overwrite: true); } catch (Exception) { /* segue: será sobrescrito */ }
            _log.LogError(ex, "A chave de identidade do agente não abre ({Path}); uma nova foi gerada e o agente precisa ser enrolado de novo no painel.", aside);
        }

        var key = AgentKey.Generate();
        ProtectedFile.Write(path, JsonSerializer.Serialize(new StoredKey(Convert.ToBase64String(key.Seed), DateTime.UtcNow)), Purpose);
        return key;
    }
}

/// <summary>
/// Apresenta a chave do agente ao painel, uma vez, com o token de enrolamento que o administrador gerou. Depois de
/// aceito, o token é descartado (ele já não vale nada) e os lotes passam a ser autenticados pela assinatura.
/// </summary>
public sealed class AgentEnroller(HttpClient http, AgentIdentity identity, Func<string?> token, Action discardToken, ILogger<AgentEnroller> log)
{
    private DateTime _lastWarning = DateTime.MinValue;

    public async Task<bool> EnsureEnrolledAsync(CancellationToken ct)
    {
        var current = token();
        if (identity.IsEnrolled)
        {
            // Token sobrando (reinstalacao ou atualizacao com ENROLLTOKEN informado de novo): o agente ja tem identidade
            // no painel e nao precisa dele - sai do registro em vez de ficar la, valido, esperando alguem ler.
            if (!string.IsNullOrWhiteSpace(current)) { try { discardToken(); } catch (Exception ex) { log.LogWarning(ex, "Nao foi possivel apagar o token de enrolamento do registro."); } }
            return true;
        }

        if (string.IsNullOrWhiteSpace(current))
        {
            Warn("Agente sem enrolamento no painel e sem token: gere um token na tela Agentes do painel e reinstale com ENROLLTOKEN (ou grave o valor EnrollToken no registro do agente). A detecção local continua; o painel não recebe nada.");
            return false;
        }

        try
        {
            using var response = await http.PostAsJsonAsync("/api/enroll",
                new { token = current, server = identity.Server, publicKey = identity.Key.PublicKeyBase64 }, ct);
            if (response.IsSuccessStatusCode)
            {
                identity.MarkEnrolled();
                try { discardToken(); } catch (Exception ex) { log.LogWarning(ex, "Enrolado, mas não foi possível apagar o token do registro."); }
                log.LogInformation("Agente enrolado no painel como {Server}, chave {Fingerprint}.", identity.Server, identity.Key.Fingerprint);
                return true;
            }
            var detail = await ErrorOf(response, ct);
            Warn(response.StatusCode == HttpStatusCode.Conflict
                ? $"Enrolamento recusado: {detail}"
                : $"Enrolamento recusado pelo painel ({(int)response.StatusCode}): {detail}");
            return false;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            log.LogWarning(ex, "Não foi possível falar com o painel para o enrolamento; tentará no próximo ciclo.");
            return false;
        }
    }

    internal static async Task<string> ErrorOf(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            return doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() ?? "" : "";
        }
        catch (Exception) { return ""; }
    }

    /// <summary>O mesmo aviso, no máximo a cada 10 minutos — o ciclo roda a cada 5 segundos.</summary>
    private void Warn(string message)
    {
        if (DateTime.UtcNow - _lastWarning < TimeSpan.FromMinutes(10)) return;
        _lastWarning = DateTime.UtcNow;
        log.LogError("{Message}", message);
    }
}

/// <summary>
/// Endereços de que este servidor depende — o agente nunca os bloqueia, venha a ordem de onde vier
/// (<see cref="RansomGuard.Core.Response.InfrastructureGuardExecutor"/>): os próprios, os gateways, os servidores de
/// nomes (num domínio, os controladores) e o painel.
/// </summary>
public static class InfrastructureAddresses
{
    private static IReadOnlySet<string> _cached = new HashSet<string>();
    private static DateTime _at = DateTime.MinValue;
    private static readonly object Gate = new();

    public static IReadOnlySet<string> Current(string backendUrl, bool refresh = false)
    {
        lock (Gate)
        {
            if (!refresh && DateTime.UtcNow - _at < TimeSpan.FromMinutes(5)) return _cached;
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "127.0.0.1", "::1" };
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    var ip = nic.GetIPProperties();
                    foreach (var a in ip.UnicastAddresses) set.Add(a.Address.ToString());
                    foreach (var g in ip.GatewayAddresses) set.Add(g.Address.ToString());
                    foreach (var d in ip.DnsAddresses) set.Add(d.ToString());
                }
            }
            catch (Exception) { /* sem acesso às interfaces: seguem os demais */ }
            try
            {
                if (Uri.TryCreate(backendUrl, UriKind.Absolute, out var panel))
                {
                    if (IPAddress.TryParse(panel.Host, out var literal)) set.Add(literal.ToString());
                    else foreach (var a in Dns.GetHostAddresses(panel.Host)) set.Add(a.ToString());
                }
            }
            catch (Exception) { /* painel sem resolução agora: tenta na próxima renovação */ }
            set.Remove("0.0.0.0");
            _cached = set; _at = DateTime.UtcNow;
            return _cached;
        }
    }
}
