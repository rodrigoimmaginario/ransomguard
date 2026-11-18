using System.Net.Http.Json;
using RansomGuard.Agent.Auth;

namespace RansomGuard.Agent.Service.Windows;

/// <summary>F38 — chave pública fixada do painel, em ProgramData (sobrevive a reinício e atualização do MSI).</summary>
public sealed class FilePanelKeyStore(string path) : IPanelKeyStore
{
    public string? Load()
    {
        try { return File.Exists(path) ? File.ReadAllText(path) : null; }
        catch (Exception) { return null; }
    }

    public void Save(string publicKeyFileContent)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, publicKeyFileContent);
    }
}

/// <summary>
/// Fixa a chave do painel no primeiro contato (TOFU) consultando <c>/api/identity</c>. Só age quando o
/// agente ainda não tem chave; com chave fixada, uma chave diferente é registrada como suspeita e ignorada.
/// </summary>
public sealed class PanelIdentityPinner(HttpClient http, PanelTrust trust, ILogger<PanelIdentityPinner> log)
{
    private sealed record Identity(string InstallId, string KeyId, string PublicKey);

    public async Task EnsurePinnedAsync(CancellationToken ct)
    {
        if (trust.HasKey) return;
        try
        {
            var id = await http.GetFromJsonAsync<Identity>("/api/identity", ct);
            if (id is null || string.IsNullOrWhiteSpace(id.PublicKey)) { log.LogWarning("Painel sem identidade publicada; contenção fica no último estado."); return; }
            if (trust.TryPin(id.PublicKey))
                log.LogInformation("Chave do painel fixada (TOFU): instalação {Install}, keyId {KeyId}.", id.InstallId, id.KeyId);
            else
                log.LogWarning("Painel apresentou chave diferente da fixada ({KeyId}); ignorada. Se o painel foi reinstalado, remova a chave fixada manualmente.", id.KeyId);
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "Não foi possível obter a identidade do painel; tentará no próximo ciclo.");
        }
    }
}

/// <summary>F33 — última política assinada aceita, em ProgramData (reaplicada ao subir, verificada de novo).</summary>
public sealed class FilePolicyStore(string path) : RansomGuard.Agent.IPolicyStore
{
    public RansomGuard.Core.Auth.SignedAssertion? Load()
    {
        try
        {
            return File.Exists(path)
                ? System.Text.Json.JsonSerializer.Deserialize<RansomGuard.Core.Auth.SignedAssertion>(File.ReadAllText(path))
                : null;
        }
        catch (Exception) { return null; }
    }

    public void Save(RansomGuard.Core.Auth.SignedAssertion policy)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, System.Text.Json.JsonSerializer.Serialize(policy));
    }
}

/// <summary>
/// F39 — handler HTTP do agente: aceita o certificado do painel conforme <see cref="RansomGuard.Agent.Auth.CertificatePinning"/>
/// (configurado > fixado por TOFU > cadeia válida). O pin fica em ProgramData (<c>panel-cert.sha256</c>).
/// </summary>
public static class PinnedHttpHandler
{
    public static HttpClientHandler Create(string pinPath, string? configuredThumbprint, ILogger log)
    {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
        {
            if (cert is null) return false;
            var presented = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(cert.RawData));
            string? pinned = null;
            try { pinned = File.Exists(pinPath) ? File.ReadAllText(pinPath).Trim() : null; } catch (Exception) { }
            var chainValid = errors == System.Net.Security.SslPolicyErrors.None;
            switch (RansomGuard.Agent.Auth.CertificatePinning.Decide(presented, pinned, configuredThumbprint, chainValid))
            {
                case RansomGuard.Agent.Auth.PinDecision.Accept: return true;
                case RansomGuard.Agent.Auth.PinDecision.PinAndAccept:
                    try { Directory.CreateDirectory(Path.GetDirectoryName(pinPath)!); File.WriteAllText(pinPath, presented); log.LogInformation("Certificado do painel fixado (TOFU): {Thumb}", presented); }
                    catch (Exception ex) { log.LogWarning(ex, "Não foi possível gravar o pin do certificado."); }
                    return true;
                default:
                    log.LogError("Certificado do painel RECUSADO: apresentado {Presented}; fixado {Pinned}; configurado {Configured}. Se o painel foi reinstalado, apague {Path}.",
                        presented, pinned ?? "-", configuredThumbprint ?? "-", pinPath);
                    return false;
            }
        };
        return handler;
    }
}

/// <summary>
/// D8 — todo cliente HTTP que fala com o painel usa o mesmo pin de certificado. O painel nasce com certificado
/// autoassinado; um cliente comum o recusa — foi assim que o catálogo assinado nunca chegava ao agente em HTTPS.
/// </summary>
public static class AgentHttp
{
    public static HttpClient CreatePinned(string backendUrl, string pinPath, string? configuredThumbprint, ILogger log, TimeSpan? timeout = null) =>
        new(PinnedHttpHandler.Create(pinPath, configuredThumbprint, log))
        {
            BaseAddress = new Uri(backendUrl),
            Timeout = timeout ?? TimeSpan.FromSeconds(30)
        };
}

/// <summary>B5 — IPs da blocklist de rede que este agente bloqueou no firewall, em ProgramData (sobrevive ao reinício).</summary>
public sealed class FileAppliedBlocklistStore(string path) : RansomGuard.Agent.IAppliedBlocklistStore
{
    public IReadOnlyCollection<string> Load()
    {
        try
        {
            return File.Exists(path)
                ? System.Text.Json.JsonSerializer.Deserialize<List<string>>(File.ReadAllText(path)) ?? new List<string>()
                : new List<string>();
        }
        catch (Exception) { return new List<string>(); }
    }

    public void Save(IReadOnlyCollection<string> ips)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, System.Text.Json.JsonSerializer.Serialize(ips));
    }
}

/// <summary>F34 — fila durável em ProgramData\RansomGuard\queue: um arquivo JSON por lote, nome ordenável por tempo.</summary>
public sealed class FileBatchQueue(string directory, ILogger log) : RansomGuard.Agent.Queue.IBatchQueue
{
    private static readonly System.Text.Json.JsonSerializerOptions Json = new() { WriteIndented = false };

    private IEnumerable<string> Files() =>
        Directory.Exists(directory) ? Directory.EnumerateFiles(directory, "*.json").OrderBy(f => f, StringComparer.Ordinal) : Enumerable.Empty<string>();

    public int Count => Files().Count();

    public void Enqueue(RansomGuard.Agent.AgentBatch batch)
    {
        try
        {
            Directory.CreateDirectory(directory);
            var name = $"{batch.At:yyyyMMdd'T'HHmmss'.'fff}-{Guid.NewGuid():N}.json";
            File.WriteAllText(Path.Combine(directory, name), System.Text.Json.JsonSerializer.Serialize(batch, Json));
        }
        catch (Exception ex) { log.LogError(ex, "Não foi possível guardar o lote na fila — este lote será perdido."); }
    }

    public IReadOnlyList<RansomGuard.Agent.AgentBatch> Peek(int max)
    {
        var list = new List<RansomGuard.Agent.AgentBatch>();
        foreach (var f in Files().Take(max))
        {
            try
            {
                var b = System.Text.Json.JsonSerializer.Deserialize<RansomGuard.Agent.AgentBatch>(File.ReadAllText(f), Json);
                if (b is not null) list.Add(b); else File.Delete(f);
            }
            catch (Exception ex) { log.LogWarning(ex, "Lote corrompido na fila descartado: {File}", f); try { File.Delete(f); } catch (Exception) { } }
        }
        return list;
    }

    public void DequeueOldest()
    {
        var f = Files().FirstOrDefault();
        if (f is not null) try { File.Delete(f); } catch (Exception ex) { log.LogWarning(ex, "Não foi possível remover {File}", f); }
    }

    public int Prune(DateTime now, int maxCount, TimeSpan maxAge)
    {
        var files = Files().ToList();
        var drop = new List<string>();
        foreach (var f in files)
        {
            var stamp = Path.GetFileName(f)[..18];
            if (DateTime.TryParseExact(stamp, "yyyyMMdd'T'HHmmss'.'fff", null, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var at)
                && now - at > maxAge) drop.Add(f);
        }
        var remaining = files.Count - drop.Count;
        if (remaining > maxCount) drop.AddRange(files.Where(f => !drop.Contains(f)).Take(remaining - maxCount));
        foreach (var f in drop) try { File.Delete(f); } catch (Exception) { }
        if (drop.Count > 0) log.LogWarning("Fila: {N} lote(s) descartado(s) por teto de idade/quantidade.", drop.Count);
        return drop.Count;
    }
}
